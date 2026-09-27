"""Rotation has two halves and they fail independently.

Rotation **in** — a token signed with a key the cache has never seen — is
handled by refetching once on an unknown `kid`. Rotation **out** — a key
the issuer has removed, because it leaked — is only handled by something
that expires the cached key set.

This library shipped the first and not the second. A withdrawn key went on
being accepted for the life of the process, which in a long-lived container
is indefinitely, so revoking a compromised key meant restarting every
consumer. The product's own doctrine calls key rotation a control; a
control that needs a restart is not one.

The fetch counts are asserted throughout, because they are what tells the
two bad fixes apart. Never expiring passes nothing here. Refetching on
every verification passes the withdrawal case and turns the issuer into
your rate limiter — the counts catch it.
"""

from __future__ import annotations

import json

import grantor
import httpx
import pytest
from core_support import CLIENT_ID
from grantor import TokenError
from jwt.algorithms import RSAAlgorithm

pytestmark = pytest.mark.usefixtures("_no_cached_state")


class Clock:
    """A monotonic clock this test owns, so a TTL can be crossed at will."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock(monkeypatch):
    c = Clock()
    monkeypatch.setattr("grantor._tokens.time.monotonic", c)
    return c


@pytest.fixture
def issuer(signing_key, rotated_key, discovery_payload):
    """An issuer whose published key list this test can change."""
    (private_a, public_a), (private_b, public_b) = signing_key, rotated_key

    def jwk(public, kid):
        d = json.loads(RSAAlgorithm.to_jwk(public))
        d.update(kid=kid, use="sig", alg="RS256")
        return d

    state = {"published": [jwk(public_a, "A")], "jwks_fetches": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("jwks.json"):
            state["jwks_fetches"] += 1
            return httpx.Response(200, json={"keys": state["published"]})
        return httpx.Response(200, json=discovery_payload)

    state["client"] = httpx.Client(transport=httpx.MockTransport(handler))
    state["withdraw_a_publish_b"] = lambda: state.__setitem__("published", [jwk(public_b, "B")])
    state["keys"] = {"A": private_a, "B": private_b}
    return state


def _token(issuer, kid, mint):
    # An access token in the issuer's shape: it is verified as one below.
    return mint(
        kid=kid, key=issuer["keys"][kid], aud=CLIENT_ID, client_id=CLIENT_ID, scope="openid"
    )


def _verify(issuer, raw, discovery, ttl=3600.0):
    return grantor.verify_access_token(
        raw,
        discovery=discovery,
        audience=CLIENT_ID,
        client=issuer["client"],
        jwks_ttl=ttl,
    )


def test_a_withdrawn_key_stops_being_accepted_once_the_ttl_passes(issuer, discovery, mint, clock):
    """The defect this file exists for."""
    token_a = _token(issuer, "A", mint)
    assert _verify(issuer, token_a, discovery)["sub"]

    issuer["withdraw_a_publish_b"]()

    # Still inside the TTL: the cached set is honoured, deliberately. This
    # is the bound a consumer configures, not a promise of immediacy.
    assert _verify(issuer, token_a, discovery)["sub"]
    assert issuer["jwks_fetches"] == 1

    clock.advance(3601)

    with pytest.raises(TokenError, match="kid"):
        _verify(issuer, token_a, discovery)
    assert issuer["jwks_fetches"] == 2, "the expiry must cause exactly one refetch"


def test_rotation_in_still_works_without_waiting_for_the_ttl(issuer, discovery, mint):
    """The half that already worked, and that an over-eager fix would break.

    A key the cache has never seen is picked up immediately by the
    unknown-`kid` refetch. A fix that only expired the set would make every
    rotation a partial outage for the length of the TTL.
    """
    assert _verify(issuer, _token(issuer, "A", mint), discovery)["sub"]
    issuer["withdraw_a_publish_b"]()

    assert _verify(issuer, _token(issuer, "B", mint), discovery)["sub"]
    assert issuer["jwks_fetches"] == 2


def test_a_stream_of_junk_does_not_become_a_request_amplifier(issuer, discovery, mint):
    """The other bad fix: refetching on every verification.

    Unknown `kid`s refetch **once each**, not once per attempt within a
    fetch — but the ceiling that matters is that a valid token never
    refetches at all while the set is fresh.
    """
    assert _verify(issuer, _token(issuer, "A", mint), discovery)["sub"]
    before = issuer["jwks_fetches"]

    for _ in range(5):
        assert _verify(issuer, _token(issuer, "A", mint), discovery)["sub"]

    assert issuer["jwks_fetches"] == before, "a fresh key set must not be refetched"


def test_a_shorter_ttl_is_honoured(issuer, discovery, mint, clock):
    """`GRANTOR_JWKS_CACHE_SECONDS` has to actually bound it."""
    token_a = _token(issuer, "A", mint)
    assert _verify(issuer, token_a, discovery, ttl=60)["sub"]
    issuer["withdraw_a_publish_b"]()

    clock.advance(61)

    with pytest.raises(TokenError, match="kid"):
        _verify(issuer, token_a, discovery, ttl=60)


def test_a_zero_ttl_means_always_refetch_not_never_work(issuer, discovery, mint):
    """The edge the consumer's probe found in the fix itself.

    `ttl=0` expires the set the instant it is stored, so the lookup right
    after a fetch saw its own result as stale and discarded it — nothing
    ever verified. "Always refetch" turning into "never works" is a worse
    failure than the one the TTL was added to fix, and it is the shape a
    consumer gets by setting `GRANTOR_JWKS_CACHE_SECONDS=0` to be careful.
    """
    token_a = _token(issuer, "A", mint)

    assert _verify(issuer, token_a, discovery, ttl=0)["sub"]
    assert issuer["jwks_fetches"] == 1

    # And it really does refetch every time, which is what ttl=0 asks for.
    assert _verify(issuer, token_a, discovery, ttl=0)["sub"]
    assert issuer["jwks_fetches"] == 2

    issuer["withdraw_a_publish_b"]()
    with pytest.raises(TokenError, match="kid"):
        _verify(issuer, token_a, discovery, ttl=0)


def _junk(mint, issuer, n):
    """Tokens naming keys the issuer never published — signed with a real
    key so only the `kid` is wrong."""
    return [mint(kid=f"no-such-key-{i}", key=issuer["keys"]["A"], aud=CLIENT_ID) for i in range(n)]


def test_unknown_kids_share_one_refetch_per_window(issuer, discovery, mint, clock):
    """An unknown `kid` refetches, but a stream of them does not each get
    their own trip to the issuer: one per window, whatever the kids are."""
    assert _verify(issuer, _token(issuer, "A", mint), discovery)["sub"]
    before = issuer["jwks_fetches"]

    for raw in _junk(mint, issuer, 50):
        with pytest.raises(TokenError, match="kid"):
            _verify(issuer, raw, discovery)

    assert issuer["jwks_fetches"] - before == 1


def test_the_window_reopens(issuer, discovery, mint, clock):
    assert _verify(issuer, _token(issuer, "A", mint), discovery)["sub"]
    for raw in _junk(mint, issuer, 2):
        with pytest.raises(TokenError):
            _verify(issuer, raw, discovery)
    before = issuer["jwks_fetches"]

    clock.advance(31)
    with pytest.raises(TokenError):
        _verify(issuer, _junk(mint, issuer, 1)[0], discovery)

    assert issuer["jwks_fetches"] == before + 1


async def test_the_async_path_shares_the_window(issuer, discovery, mint, clock):
    assert _verify(issuer, _token(issuer, "A", mint), discovery)["sub"]
    before = issuer["jwks_fetches"]
    async_client = httpx.AsyncClient(transport=issuer["client"]._transport)

    for raw in _junk(mint, issuer, 10):
        with pytest.raises(TokenError):
            await grantor.async_verify_access_token(
                raw, discovery=discovery, audience=CLIENT_ID, client=async_client
            )

    assert issuer["jwks_fetches"] - before <= 1
