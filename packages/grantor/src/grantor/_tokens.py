"""Verifying tokens by signature, and never any other way.

Every token this issuer mints is a signed JWT, including the access token.
Verify it against the JWKS; never decode-and-trust. That is the first thing
the guide asks of a relying party and it is the one that cannot be walked
back later.

The seam here is deliberate: :func:`decode_and_verify` and
:func:`check_nonce` are pure and public, so every attack this module defends
against — a tampered signature, a wrong issuer, a wrong audience, an expired
token, a replayed nonce — has a test that mints a key locally and never
opens a socket. Mocking a socket to test a pure function is a sign the seam
is in the wrong place.
"""

from __future__ import annotations

import secrets
import threading
import time
from collections.abc import Iterable, Mapping
from typing import Any

import httpx
import jwt
from jwt import PyJWKSet

from ._discovery import HTTP_TIMEOUT_SECONDS, DiscoveryDocument
from ._errors import DiscoveryError, TokenError

__all__ = [
    "JwksCache",
    "DEFAULT_JWKS_TTL_SECONDS",
    "fetch_jwks",
    "async_fetch_jwks",
    "decode_and_verify",
    "check_nonce",
    "verify_id_token",
    "async_verify_id_token",
    "verify_access_token",
    "async_verify_access_token",
    "clear_jwks_cache",
    "LEEWAY_SECONDS",
    "ID_TOKEN_REQUIRED_CLAIMS",
    "ACCESS_TOKEN_REQUIRED_CLAIMS",
]

# The issuer and the relying party are different hosts with different clocks.
# Thirty seconds absorbs ordinary drift without meaningfully extending the
# life of an expired token.
LEEWAY_SECONDS = 30

# How long a fetched key set is reused. Matches the discovery document's
# default, and is what `GRANTOR_JWKS_CACHE_SECONDS` sets on the Django side
# — the name always said JWKS; for a while it only bounded discovery.
DEFAULT_JWKS_TTL_SECONDS = 3600.0
#: How often an unknown ``kid`` may send a fresh key set back to the issuer.
UNKNOWN_KID_REFETCH_SECONDS = 30.0

ID_TOKEN_REQUIRED_CLAIMS = ("exp", "iat", "iss", "aud", "sub")
ACCESS_TOKEN_REQUIRED_CLAIMS = ("exp", "iat", "iss", "aud", "sub")


def _key_id(raw: str) -> str | None:
    try:
        return jwt.get_unverified_header(raw).get("kid")
    except jwt.PyJWTError:
        return None


class JwksCache:
    """The issuer's signing keys, cached with a TTL, with one retry on an
    unknown ``kid``.

    Three failure modes, pulling in three directions, and a key cache has to
    miss all of them.

    *Never refetching* makes a rotation an outage: every token signed with
    the new key is rejected until the process restarts. A miss therefore
    refetches **once**, and a key still unknown after that is a rejection.

    *Refetching on every miss, with no ceiling* turns a stream of junk
    tokens into a request amplifier pointed at the issuer. "Once per miss"
    is not a ceiling when every junk token names a different ``kid``, so
    refetches caused by an unknown ``kid`` on a *fresh* set share one window:
    at most one per ``refetch_interval`` seconds. The first is always
    allowed, which is what keeps rotation in immediate; a genuinely new key
    arriving inside a window opened by junk waits at most that long.
    Synchronous callers are single-flight: concurrent misses wait for one
    fetch and look again, rather than each making their own.

    *Never expiring* is the one this class got wrong first, and it is the
    worst of the three, because it fails silently and in the safe-looking
    direction. Rotation **in** was handled and withdrawal was not: a key the
    issuer had retired went on being accepted for the life of the process.
    In a long-lived container that is indefinitely, which makes revoking a
    compromised key mean "restart every consumer" — not a control anybody
    can rely on, and the product's own doctrine calls key rotation a control.

    So the key set expires on ``ttl``, the same ``GRANTOR_JWKS_CACHE_SECONDS``
    a consumer already believed bounded it.
    """

    def __init__(
        self,
        jwks_uri: str,
        *,
        keys: Mapping[str, Any] | None = None,
        ttl: float = DEFAULT_JWKS_TTL_SECONDS,
        refetch_interval: float = UNKNOWN_KID_REFETCH_SECONDS,
    ) -> None:
        self.jwks_uri = jwks_uri
        self.ttl = ttl
        self.refetch_interval = refetch_interval
        self._lock = threading.Lock()
        self._fetch_lock = threading.Lock()
        self._miss_refetched_at: float | None = None
        self._key_set: PyJWKSet | None = None
        self._expires_at = 0.0
        if keys is not None:
            self._store(keys)

    def _lookup(self, kid: str | None, *, require_fresh: bool = True) -> Any | None:
        with self._lock:
            key_set = self._key_set
            fresh = time.monotonic() < self._expires_at
        # A stale set is not consulted at all. Treating it as a miss means
        # the refetch path picks up a withdrawal as well as an addition —
        # the two halves of a rotation, rather than one.
        #
        # `require_fresh=False` is for the lookup immediately after a fetch,
        # where the set is current by construction. Without it a `ttl` of 0
        # discards the key it has just fetched and nothing ever verifies:
        # "always refetch" would mean "never works", which is a worse
        # failure than the one the TTL was added to fix.
        if key_set is None or (require_fresh and not fresh):
            return None
        for key in key_set.keys:
            if kid is None or key.key_id == kid:
                return key
        return None

    def _claim_refetch(self) -> bool:
        """Whether this miss may go to the issuer. Always, for an empty or
        stale set; for an unknown ``kid`` on a fresh set, once per window."""
        now = time.monotonic()
        with self._lock:
            if self._key_set is None or now >= self._expires_at:
                return True
            recent = self._miss_refetched_at
            if recent is not None and now - recent < self.refetch_interval:
                return False
            self._miss_refetched_at = now
            return True

    def _store(self, payload: Mapping[str, Any]) -> None:
        key_set = _key_set_from(payload)
        with self._lock:
            self._key_set = key_set
            self._expires_at = time.monotonic() + self.ttl

    def signing_key(
        self,
        raw: str,
        *,
        client: httpx.Client | None = None,
        timeout: float = HTTP_TIMEOUT_SECONDS,
    ) -> Any:
        kid = _key_id(raw)
        key = self._lookup(kid)
        if key is not None:
            return key
        with self._fetch_lock:
            # Another thread may have fetched while this one waited.
            key = self._lookup(kid)
            if key is not None:
                return key
            if not self._claim_refetch():
                raise TokenError("no signing key matches this token's kid")
            self._store(fetch_jwks(self.jwks_uri, client=client, timeout=timeout))
        key = self._lookup(kid, require_fresh=False)
        if key is None:
            raise TokenError("no signing key matches this token's kid")
        return key

    async def async_signing_key(
        self,
        raw: str,
        *,
        client: httpx.AsyncClient | None = None,
        timeout: float = HTTP_TIMEOUT_SECONDS,
    ) -> Any:
        kid = _key_id(raw)
        key = self._lookup(kid)
        if key is not None:
            return key
        # No single-flight here — a thread lock cannot be held across an
        # await — but the window is claimed before the fetch, so concurrent
        # misses on a fresh set still produce one request, not one each.
        if not self._claim_refetch():
            raise TokenError("no signing key matches this token's kid")
        self._store(await async_fetch_jwks(self.jwks_uri, client=client, timeout=timeout))
        key = self._lookup(kid, require_fresh=False)
        if key is None:
            raise TokenError("no signing key matches this token's kid")
        return key


def _key_set_from(payload: Mapping[str, Any]) -> PyJWKSet:
    try:
        return PyJWKSet.from_dict(dict(payload))
    except Exception as exc:  # noqa: BLE001 - PyJWT raises several types here
        raise DiscoveryError("JWKS document is not usable") from exc


_caches: dict[str, JwksCache] = {}
_caches_lock = threading.Lock()


def _cache_for(jwks_uri: str, ttl: float = DEFAULT_JWKS_TTL_SECONDS) -> JwksCache:
    with _caches_lock:
        cache = _caches.get(jwks_uri)
        if cache is None:
            cache = JwksCache(jwks_uri, ttl=ttl)
            _caches[jwks_uri] = cache
        elif cache.ttl != ttl:
            # A consumer that changed the setting means it; the cache is
            # process state and must not outlive the configuration.
            cache.ttl = ttl
        return cache


def clear_jwks_cache() -> None:
    """Drop every cached key set. The test hook, and the operational one."""
    with _caches_lock:
        _caches.clear()


def fetch_jwks(
    jwks_uri: str,
    *,
    client: httpx.Client | None = None,
    timeout: float = HTTP_TIMEOUT_SECONDS,
) -> Mapping[str, Any]:
    try:
        if client is not None:
            response = client.get(jwks_uri, timeout=timeout)
        else:
            with httpx.Client(timeout=timeout, follow_redirects=True) as owned:
                response = owned.get(jwks_uri)
    except httpx.HTTPError as exc:
        raise DiscoveryError(f"JWKS request failed: {type(exc).__name__}") from exc
    if response.status_code != 200:
        raise DiscoveryError(f"JWKS answered {response.status_code}")
    try:
        return response.json()
    except ValueError as exc:
        raise DiscoveryError("JWKS did not return JSON") from exc


async def async_fetch_jwks(
    jwks_uri: str,
    *,
    client: httpx.AsyncClient | None = None,
    timeout: float = HTTP_TIMEOUT_SECONDS,
) -> Mapping[str, Any]:
    try:
        if client is not None:
            response = await client.get(jwks_uri, timeout=timeout)
        else:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as owned:
                response = await owned.get(jwks_uri)
    except httpx.HTTPError as exc:
        raise DiscoveryError(f"JWKS request failed: {type(exc).__name__}") from exc
    if response.status_code != 200:
        raise DiscoveryError(f"JWKS answered {response.status_code}")
    try:
        return response.json()
    except ValueError as exc:
        raise DiscoveryError("JWKS did not return JSON") from exc


def decode_and_verify(
    raw: str,
    *,
    key: Any,
    algorithms: Iterable[str],
    issuer: str,
    audience: str | Iterable[str],
    leeway: int = LEEWAY_SECONDS,
    required_claims: Iterable[str] = ID_TOKEN_REQUIRED_CLAIMS,
) -> dict[str, Any]:
    """Verify a JWT and return its claims. The pure step.

    ``algorithms`` is pinned by the caller from the discovery document and
    is never read from the token's own header. A verifier that honours the
    header's ``alg`` lets the token choose how it is checked, which is the
    whole of the ``alg: none`` and algorithm-confusion families.

    The raised message names which check failed and carries no part of the
    token. A rejected token is precisely the one whose contents must not be
    trusted enough to log.
    """
    algorithms = list(algorithms)
    if not algorithms:
        raise TokenError("no acceptable signing algorithm")
    try:
        return jwt.decode(
            raw,
            key,
            algorithms=algorithms,
            audience=list(audience) if not isinstance(audience, str) else audience,
            issuer=issuer,
            leeway=leeway,
            options={"require": list(required_claims)},
        )
    except jwt.ExpiredSignatureError as exc:
        raise TokenError("token has expired") from exc
    except jwt.InvalidAudienceError as exc:
        raise TokenError("token audience is not this client") from exc
    except jwt.InvalidIssuerError as exc:
        raise TokenError("token was issued by a different issuer") from exc
    except jwt.MissingRequiredClaimError as exc:
        raise TokenError(f"token lacks a required claim: {exc.claim}") from exc
    except jwt.InvalidSignatureError as exc:
        raise TokenError("token signature does not verify") from exc
    except jwt.PyJWTError as exc:
        # The class name, never the exception text: PyJWT is careful, but a
        # future message that quotes a claim would otherwise reach a log.
        raise TokenError(f"token rejected: {type(exc).__name__}") from exc


def check_nonce(claims: Mapping[str, Any], nonce: str) -> None:
    """Compare the ID token's ``nonce`` with the one that was sent.

    Constant-time, and not because a timing attack on a nonce is likely —
    because the cost of ``compare_digest`` is nothing and the habit is what
    survives being copied into the next comparison, where it matters.
    """
    if not secrets.compare_digest(str(claims.get("nonce", "")), nonce):
        raise TokenError("nonce does not match the one this flow sent")


def _verify(
    raw: str,
    *,
    discovery: DiscoveryDocument,
    audience: str | Iterable[str],
    key: Any,
    nonce: str | None,
    leeway: int,
    required_claims: Iterable[str],
) -> dict[str, Any]:
    claims = decode_and_verify(
        raw,
        key=key,
        algorithms=discovery.signing_algorithms,
        issuer=discovery.issuer,
        audience=audience,
        leeway=leeway,
        required_claims=required_claims,
    )
    if nonce is not None:
        check_nonce(claims, nonce)
    return claims


def verify_id_token(
    raw: str,
    *,
    discovery: DiscoveryDocument,
    audience: str,
    nonce: str | None = None,
    jwks: JwksCache | None = None,
    client: httpx.Client | None = None,
    leeway: int = LEEWAY_SECONDS,
    jwks_ttl: float = DEFAULT_JWKS_TTL_SECONDS,
) -> dict[str, Any]:
    """Verify an ID token and return its claims.

    ``audience`` is this client's ``client_id`` — an ID token is addressed
    to the client that asked for it. Pass the ``nonce`` from the
    authorization request whenever there was one; omitting it skips the
    replay check, which is only correct if no nonce was sent.

    ``jwks`` lets a caller supply a key set instead of fetching one, which
    is how this function is tested offline.
    """
    cache = jwks or _cache_for(discovery.jwks_uri, jwks_ttl)
    key = cache.signing_key(raw, client=client)
    return _verify(
        raw,
        discovery=discovery,
        audience=audience,
        key=key.key,
        nonce=nonce,
        leeway=leeway,
        required_claims=ID_TOKEN_REQUIRED_CLAIMS,
    )


async def async_verify_id_token(
    raw: str,
    *,
    discovery: DiscoveryDocument,
    audience: str,
    nonce: str | None = None,
    jwks: JwksCache | None = None,
    client: httpx.AsyncClient | None = None,
    leeway: int = LEEWAY_SECONDS,
    jwks_ttl: float = DEFAULT_JWKS_TTL_SECONDS,
) -> dict[str, Any]:
    cache = jwks or _cache_for(discovery.jwks_uri, jwks_ttl)
    key = await cache.async_signing_key(raw, client=client)
    return _verify(
        raw,
        discovery=discovery,
        audience=audience,
        key=key.key,
        nonce=nonce,
        leeway=leeway,
        required_claims=ID_TOKEN_REQUIRED_CLAIMS,
    )


def check_access_token_origin(
    claims: Mapping[str, Any],
    *,
    tenant: str | None = None,
    client_ids: Iterable[str] | None = None,
) -> None:
    """Hold an already-verified access token to the tenant and clients this
    resource server accepts.

    Both are optional and both are recommended. The issuer is an
    *organization*, which may run several tenants and many applications;
    ``aud`` says the token is for this API, and these say it came from the
    tenant and the applications this API was built to serve. A token that
    names no tenant fails a pinned tenant — absence is not agreement.
    """
    if tenant is not None and claims.get("tenant") != tenant:
        raise TokenError("token was issued for a different tenant")
    if client_ids is not None and claims.get("client_id") not in set(client_ids):
        raise TokenError("token was issued to a client this API does not accept")


def verify_access_token(
    raw: str,
    *,
    discovery: DiscoveryDocument,
    audience: str | Iterable[str],
    tenant: str | None = None,
    client_ids: Iterable[str] | None = None,
    jwks: JwksCache | None = None,
    client: httpx.Client | None = None,
    leeway: int = LEEWAY_SECONDS,
    jwks_ttl: float = DEFAULT_JWKS_TTL_SECONDS,
) -> dict[str, Any]:
    """Verify an access token presented to *this* resource server.

    ``audience`` is **this API's** RFC 8707 resource identifier, not the
    browser application's ``client_id``. A token minted for the UI is not a
    token for an API, and a resource server that accepts one has made ``aud``
    decorative — which is the difference between an audience check and the
    appearance of one.

    ``tenant`` (the tenant's slug) and ``client_ids`` narrow it further —
    see :func:`check_access_token_origin`.
    """
    cache = jwks or _cache_for(discovery.jwks_uri, jwks_ttl)
    key = cache.signing_key(raw, client=client)
    claims = _verify(
        raw,
        discovery=discovery,
        audience=audience,
        key=key.key,
        nonce=None,
        leeway=leeway,
        required_claims=ACCESS_TOKEN_REQUIRED_CLAIMS,
    )
    check_access_token_origin(claims, tenant=tenant, client_ids=client_ids)
    return claims


async def async_verify_access_token(
    raw: str,
    *,
    discovery: DiscoveryDocument,
    audience: str | Iterable[str],
    tenant: str | None = None,
    client_ids: Iterable[str] | None = None,
    jwks: JwksCache | None = None,
    client: httpx.AsyncClient | None = None,
    leeway: int = LEEWAY_SECONDS,
    jwks_ttl: float = DEFAULT_JWKS_TTL_SECONDS,
) -> dict[str, Any]:
    cache = jwks or _cache_for(discovery.jwks_uri, jwks_ttl)
    key = await cache.async_signing_key(raw, client=client)
    claims = _verify(
        raw,
        discovery=discovery,
        audience=audience,
        key=key.key,
        nonce=None,
        leeway=leeway,
        required_claims=ACCESS_TOKEN_REQUIRED_CLAIMS,
    )
    check_access_token_origin(claims, tenant=tenant, client_ids=client_ids)
    return claims
