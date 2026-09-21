"""The issuer's discovery document, and the one check that matters about it.

One string is configured — the issuer. Every endpoint is read from here.
That is not tidiness: transcribing endpoints into configuration is how a
configuration goes stale while still looking correct, and the guide this
library follows records a week in which its own endpoint table named a
domain the product had already left.

The I/O and the parsing are separate on purpose. ``parse_discovery_document``
is pure, so the issuer-mismatch refusal — the security-relevant half — is
tested without a socket anywhere near it.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import httpx

from ._errors import DiscoveryError

__all__ = [
    "DiscoveryDocument",
    "discovery_url",
    "parse_discovery_document",
    "discover",
    "async_discover",
    "clear_discovery_cache",
    "DISCOVERY_TTL_SECONDS",
    "HTTP_TIMEOUT_SECONDS",
]

DISCOVERY_PATH = "/.well-known/openid-configuration"
DISCOVERY_TTL_SECONDS = 3600.0
HTTP_TIMEOUT_SECONDS = 15.0

# Endpoints without which no flow can start. ``userinfo_endpoint`` and
# ``end_session_endpoint`` are deliberately not here: an issuer may omit
# them and the flows that need them fail on their own terms, with a message
# naming what was missing, rather than making discovery itself unusable.
_REQUIRED = ("authorization_endpoint", "token_endpoint", "jwks_uri")

# The algorithms a signature may be verified with. Intersected with whatever
# discovery advertises rather than trusted from it.
#
# All asymmetric. If a symmetric algorithm ever reached this list, a
# verifier handed a public key would use it as an HMAC secret — the
# algorithm-confusion attack, and the public key is published in the JWKS
# for anyone to fetch. Neither implementation this package was extracted
# from pinned this; both passed the advertised list straight through.
_SAFE_ALGORITHMS = frozenset(
    {
        "RS256",
        "RS384",
        "RS512",
        "PS256",
        "PS384",
        "PS512",
        "ES256",
        "ES384",
        "ES512",
        "EdDSA",
    }
)

_DEFAULT_ALGORITHMS = ("RS256",)


@dataclass(frozen=True)
class DiscoveryDocument:
    """A validated ``openid-configuration``.

    The raw document stays reachable through :meth:`get` — this issuer emits
    ``claims_supported``, ``scopes_supported`` and more that a caller may
    legitimately want, and a dataclass that hid them would send people back
    to fetching the URL themselves.
    """

    issuer: str
    claims: Mapping[str, Any]

    def get(self, key: str, default: Any = None) -> Any:
        return self.claims.get(key, default)

    def require(self, key: str) -> str:
        """An endpoint, or a refusal naming the one that is absent."""
        value = self.claims.get(key)
        if not isinstance(value, str) or not value:
            raise DiscoveryError(f"discovery document lacks {key}")
        return value

    @property
    def authorization_endpoint(self) -> str:
        return self.require("authorization_endpoint")

    @property
    def token_endpoint(self) -> str:
        return self.require("token_endpoint")

    @property
    def jwks_uri(self) -> str:
        return self.require("jwks_uri")

    @property
    def userinfo_endpoint(self) -> str | None:
        value = self.claims.get("userinfo_endpoint")
        return value if isinstance(value, str) and value else None

    @property
    def end_session_endpoint(self) -> str | None:
        value = self.claims.get("end_session_endpoint")
        return value if isinstance(value, str) and value else None

    @property
    def revocation_endpoint(self) -> str | None:
        value = self.claims.get("revocation_endpoint")
        return value if isinstance(value, str) and value else None

    @property
    def signing_algorithms(self) -> tuple[str, ...]:
        """The algorithms a token from this issuer may be verified with.

        The advertised list, intersected with the asymmetric allowlist. An
        issuer that advertises nothing usable leaves ``RS256``, which is
        what every conforming OIDC provider signs with; an issuer that
        advertises only unsafe algorithms gets the same answer, and the
        signature check then fails honestly rather than succeeding against
        a key used for the wrong purpose.
        """
        advertised = self.claims.get("id_token_signing_alg_values_supported")
        if not isinstance(advertised, (list, tuple)):
            return _DEFAULT_ALGORITHMS
        safe = tuple(a for a in advertised if isinstance(a, str) and a in _SAFE_ALGORITHMS)
        return safe or _DEFAULT_ALGORITHMS


def discovery_url(issuer: str) -> str:
    """Where the document lives. Pure, and the only URL this library builds."""
    return f"{issuer.rstrip('/')}{DISCOVERY_PATH}"


def parse_discovery_document(payload: Any, *, issuer: str) -> DiscoveryDocument:
    """Validate a discovery payload against the issuer it was fetched for.

    **The ``issuer`` claim must equal the configured issuer.** A document
    naming a different one means the wrong server answered, or something
    answered for it. Either way it is a refusal, not a warning — every
    endpoint below is about to be taken from this document, so a document
    that lies about who it belongs to redirects a sign-in wherever it likes.
    """
    if not isinstance(payload, Mapping):
        raise DiscoveryError("discovery document is not a JSON object")

    expected = issuer.rstrip("/")
    named = payload.get("issuer")
    if not isinstance(named, str) or named.rstrip("/") != expected:
        raise DiscoveryError("discovery document names a different issuer")

    for key in _REQUIRED:
        value = payload.get(key)
        if not isinstance(value, str) or not value:
            raise DiscoveryError(f"discovery document lacks {key}")

    return DiscoveryDocument(issuer=expected, claims=dict(payload))


class _Cache:
    """Discovery documents by issuer, with a TTL.

    Keyed by issuer rather than held as a single slot, because a process may
    legitimately face two — a per-organization issuer for sign-in and the
    platform one for something else — and a single slot would have them
    evict each other on every call.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: dict[str, tuple[DiscoveryDocument, float]] = {}

    def get(self, issuer: str) -> DiscoveryDocument | None:
        with self._lock:
            entry = self._entries.get(issuer)
        if entry is None:
            return None
        document, expires_at = entry
        return document if time.monotonic() < expires_at else None

    def put(self, issuer: str, document: DiscoveryDocument, ttl: float) -> None:
        with self._lock:
            self._entries[issuer] = (document, time.monotonic() + ttl)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


_cache = _Cache()


def clear_discovery_cache() -> None:
    """Drop every cached document. The test hook, and the operational one."""
    _cache.clear()


def _document_from_response(response: httpx.Response, *, issuer: str) -> DiscoveryDocument:
    if response.status_code != 200:
        raise DiscoveryError(f"discovery answered {response.status_code}")
    try:
        payload = response.json()
    except ValueError as exc:
        raise DiscoveryError("discovery did not return JSON") from exc
    return parse_discovery_document(payload, issuer=issuer)


def discover(
    issuer: str,
    *,
    client: httpx.Client | None = None,
    ttl: float = DISCOVERY_TTL_SECONDS,
    timeout: float = HTTP_TIMEOUT_SECONDS,
    force: bool = False,
) -> DiscoveryDocument:
    """Fetch (or reuse) the issuer's discovery document."""
    key = issuer.rstrip("/")
    if not force:
        cached = _cache.get(key)
        if cached is not None:
            return cached

    url = discovery_url(key)
    try:
        if client is not None:
            response = client.get(url, timeout=timeout)
        else:
            with httpx.Client(timeout=timeout, follow_redirects=True) as owned:
                response = owned.get(url)
    except httpx.HTTPError as exc:
        raise DiscoveryError(f"discovery request failed: {type(exc).__name__}") from exc

    document = _document_from_response(response, issuer=key)
    _cache.put(key, document, ttl)
    return document


async def async_discover(
    issuer: str,
    *,
    client: httpx.AsyncClient | None = None,
    ttl: float = DISCOVERY_TTL_SECONDS,
    timeout: float = HTTP_TIMEOUT_SECONDS,
    force: bool = False,
) -> DiscoveryDocument:
    """:func:`discover`, without blocking the event loop."""
    key = issuer.rstrip("/")
    if not force:
        cached = _cache.get(key)
        if cached is not None:
            return cached

    url = discovery_url(key)
    try:
        if client is not None:
            response = await client.get(url, timeout=timeout)
        else:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as owned:
                response = await owned.get(url)
    except httpx.HTTPError as exc:
        raise DiscoveryError(f"discovery request failed: {type(exc).__name__}") from exc

    document = _document_from_response(response, issuer=key)
    _cache.put(key, document, ttl)
    return document
