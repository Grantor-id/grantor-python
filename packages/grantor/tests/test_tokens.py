"""Verification, with a test named after each attack it refuses.

Every token here is minted locally against a key generated in-process, so
these are real signatures over real JWTs and nothing opens a socket. A test
that had to mock a socket to check a signature would be evidence the seam
was in the wrong place.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

import grantor
import httpx
import jwt
import pytest
from core_support import API_AUDIENCE, CLIENT_ID, ISSUER, KID, ROTATED_KID, jwk_for
from cryptography.hazmat.primitives import serialization
from grantor import TokenError


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _hs256(header: dict, payload: dict, secret: bytes) -> str:
    """Mint an HS256 JWT with an arbitrary secret, guard rails and all removed."""
    signing_input = f"{_b64(json.dumps(header).encode())}.{_b64(json.dumps(payload).encode())}"
    signature = hmac.new(secret, signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{_b64(signature)}"


def test_a_well_formed_id_token_verifies(discovery, jwks, mint):
    claims = grantor.verify_id_token(
        mint(nonce="n0nce", email="a@example.com"),
        discovery=discovery,
        audience=CLIENT_ID,
        nonce="n0nce",
        jwks=jwks,
    )
    assert claims["sub"]
    assert claims["email"] == "a@example.com"


def test_a_tampered_signature_is_rejected(discovery, jwks, mint):
    raw = mint()
    header, payload, signature = raw.split(".")
    tampered = f"{header}.{payload}.{signature[:-4]}AAAA"
    with pytest.raises(TokenError, match="signature"):
        grantor.verify_id_token(tampered, discovery=discovery, audience=CLIENT_ID, jwks=jwks)


def test_a_token_from_a_different_issuer_is_rejected(discovery, jwks, mint):
    with pytest.raises(TokenError, match="different issuer"):
        grantor.verify_id_token(
            mint(iss="https://evil.example.com"),
            discovery=discovery,
            audience=CLIENT_ID,
            jwks=jwks,
        )


def test_a_token_for_a_different_audience_is_rejected(discovery, jwks, mint):
    """The check that stops one application's token being another's."""
    with pytest.raises(TokenError, match="audience"):
        grantor.verify_id_token(
            mint(aud="some-other-client"),
            discovery=discovery,
            audience=CLIENT_ID,
            jwks=jwks,
        )


def test_an_expired_token_is_rejected(discovery, jwks, mint):
    past = int(time.time()) - 3600
    with pytest.raises(TokenError, match="expired"):
        grantor.verify_id_token(
            mint(iat=past, exp=past + 300),
            discovery=discovery,
            audience=CLIENT_ID,
            jwks=jwks,
        )


def test_a_token_just_over_the_line_survives_clock_skew(discovery, jwks, mint):
    """The issuer and the relying party are different hosts with different clocks."""
    now = int(time.time())
    claims = grantor.verify_id_token(
        mint(iat=now - 400, exp=now - 5),
        discovery=discovery,
        audience=CLIENT_ID,
        jwks=jwks,
    )
    assert claims["sub"]


def test_a_replayed_nonce_is_rejected(discovery, jwks, mint):
    """The token is valid; it just answers a question nobody asked."""
    with pytest.raises(TokenError, match="nonce"):
        grantor.verify_id_token(
            mint(nonce="from-an-older-flow"),
            discovery=discovery,
            audience=CLIENT_ID,
            nonce="this-flow",
            jwks=jwks,
        )


def test_a_token_with_no_nonce_at_all_is_rejected_when_one_was_sent(discovery, jwks, mint):
    with pytest.raises(TokenError, match="nonce"):
        grantor.verify_id_token(
            mint(), discovery=discovery, audience=CLIENT_ID, nonce="this-flow", jwks=jwks
        )


@pytest.mark.parametrize("claim", ["sub", "exp", "iat", "aud", "iss"])
def test_a_token_missing_a_required_claim_is_rejected(discovery, jwks, mint, claim):
    """Absent is not the same as wrong, and both are refusals.

    A token with no `sub` cannot identify anybody; one with no `exp` never
    stops being valid. Requiring them explicitly means a future issuer that
    stopped emitting one would fail loudly here rather than quietly
    everywhere else.
    """
    with pytest.raises(TokenError):
        grantor.verify_id_token(
            mint(drop=(claim,)), discovery=discovery, audience=CLIENT_ID, jwks=jwks
        )


def test_an_algorithm_confusion_attempt_is_rejected(discovery, jwks, signing_key):
    """The public key is published. It must never be usable as an HMAC secret.

    An attacker who fetches the JWKS has the issuer's public key, mints an
    HS256 token signed with it, and presents it. A verifier that honoured
    the token header's `alg` would compute the same HMAC and let them in as
    anybody. The algorithms come from discovery, filtered to asymmetric
    ones, and never from the token.
    """
    _, public = signing_key
    public_pem = public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    now = int(time.time())
    # Assembled by hand rather than with PyJWT, which refuses to use a PEM
    # as an HMAC secret. An attacker has no such scruples, and the point of
    # this test is what arrives at the verifier, not how it was made.
    forged = _hs256(
        {"kid": KID, "alg": "HS256", "typ": "JWT"},
        {"iss": ISSUER, "sub": "attacker", "aud": CLIENT_ID, "iat": now, "exp": now + 300},
        public_pem.encode(),
    )
    with pytest.raises(TokenError):
        grantor.verify_id_token(forged, discovery=discovery, audience=CLIENT_ID, jwks=jwks)


def test_an_alg_none_token_is_rejected(discovery, jwks):
    now = int(time.time())
    unsigned = jwt.encode(
        {"iss": ISSUER, "sub": "attacker", "aud": CLIENT_ID, "iat": now, "exp": now + 300},
        key="",
        algorithm="none",
        headers={"kid": KID},
    )
    with pytest.raises(TokenError):
        grantor.verify_id_token(unsigned, discovery=discovery, audience=CLIENT_ID, jwks=jwks)


def test_an_access_token_for_the_browser_app_is_not_a_token_for_the_api(discovery, jwks, mint):
    """The single most important check in a resource server.

    A token minted for the UI's own client id is not a token for this API.
    Accepting one makes `aud` decorative — which is the difference between
    an audience check and the appearance of one.
    """
    with pytest.raises(TokenError, match="audience"):
        grantor.verify_access_token(
            mint(aud=CLIENT_ID), discovery=discovery, audience=API_AUDIENCE, jwks=jwks
        )


def test_an_access_token_audienced_for_this_api_verifies(discovery, jwks, mint):
    claims = grantor.verify_access_token(
        mint(aud=API_AUDIENCE, scope="things:read", roles=["admin"]),
        discovery=discovery,
        audience=API_AUDIENCE,
        jwks=jwks,
    )
    assert claims["scope"] == "things:read"
    assert claims["roles"] == ["admin"]


def test_an_unknown_kid_refetches_once_and_then_rejects(discovery, mint, jwks_payload):
    """A key rotation must not become an outage, nor a fetch-per-request amplifier."""
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json=jwks_payload)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    cache = grantor.JwksCache(discovery.jwks_uri)
    with pytest.raises(TokenError, match="kid"):
        grantor.verify_id_token(
            mint(kid="never-existed"),
            discovery=discovery,
            audience=CLIENT_ID,
            jwks=cache,
            client=client,
        )
    assert calls["n"] == 1


def test_a_rotated_key_is_picked_up_without_a_restart(discovery, mint, rotated_key, jwks_payload):
    rotated_private, rotated_public = rotated_key
    served = {"payload": jwks_payload}

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=served["payload"])

    client = httpx.Client(transport=httpx.MockTransport(handler))
    cache = grantor.JwksCache(discovery.jwks_uri, keys=jwks_payload)

    # The issuer rotates; the new key is not in the cached set.
    served["payload"] = {"keys": [jwk_for(rotated_public, ROTATED_KID)]}
    claims = grantor.verify_id_token(
        mint(kid=ROTATED_KID, key=rotated_private),
        discovery=discovery,
        audience=CLIENT_ID,
        jwks=cache,
        client=client,
    )
    assert claims["sub"]


def test_no_rejection_message_ever_contains_the_token(discovery, jwks, mint):
    """The one test that keeps a debugging session from becoming a leak.

    A rejected token is precisely the one whose contents must not be
    trusted enough to log — and an exception message is a log.
    """
    raw = mint(aud="some-other-client", nonce="secret-nonce", email="person@example.com")
    with pytest.raises(TokenError) as excinfo:
        grantor.verify_id_token(raw, discovery=discovery, audience=CLIENT_ID, jwks=jwks)
    message = str(excinfo.value)
    assert raw not in message
    for fragment in raw.split("."):
        assert fragment not in message
    assert "secret-nonce" not in message
    assert "person@example.com" not in message


def test_check_nonce_is_usable_on_its_own():
    """A pure step, public, so an adapter composes it instead of copying it."""
    grantor.check_nonce({"nonce": "abc"}, "abc")
    with pytest.raises(TokenError):
        grantor.check_nonce({"nonce": "abc"}, "abd")


async def test_the_async_path_verifies_the_same_token(discovery, jwks, mint):
    claims = await grantor.async_verify_id_token(
        mint(nonce="n"), discovery=discovery, audience=CLIENT_ID, nonce="n", jwks=jwks
    )
    assert claims["sub"]


# --- pinning the tenant and the clients a resource server accepts ----------
#
# `iss` names an organization, and an organization may own several
# tenants. A resource server that knows which tenant it belongs to, or
# which applications may call it, can say so and have it enforced.


def test_a_pinned_tenant_accepts_its_own_tokens(discovery, jwks, mint):
    claims = grantor.verify_access_token(
        mint(aud=API_AUDIENCE, tenant="northwind", client_id=CLIENT_ID),
        discovery=discovery,
        audience=API_AUDIENCE,
        jwks=jwks,
        tenant="northwind",
    )
    assert claims["tenant"] == "northwind"


def test_a_pinned_tenant_refuses_another_tenants_token(discovery, jwks, mint):
    with pytest.raises(TokenError, match="tenant"):
        grantor.verify_access_token(
            mint(aud=API_AUDIENCE, tenant="southwind", client_id=CLIENT_ID),
            discovery=discovery,
            audience=API_AUDIENCE,
            jwks=jwks,
            tenant="northwind",
        )


def test_a_pinned_tenant_refuses_a_token_that_names_none(discovery, jwks, mint):
    with pytest.raises(TokenError, match="tenant"):
        grantor.verify_access_token(
            mint(aud=API_AUDIENCE, client_id=CLIENT_ID),
            discovery=discovery,
            audience=API_AUDIENCE,
            jwks=jwks,
            tenant="northwind",
        )


def test_an_allowed_client_list_refuses_everyone_else(discovery, jwks, mint):
    with pytest.raises(TokenError, match="client"):
        grantor.verify_access_token(
            mint(aud=API_AUDIENCE, client_id="someone-else"),
            discovery=discovery,
            audience=API_AUDIENCE,
            jwks=jwks,
            client_ids=[CLIENT_ID],
        )


def test_an_allowed_client_list_admits_its_members(discovery, jwks, mint):
    claims = grantor.verify_access_token(
        mint(aud=API_AUDIENCE, client_id=CLIENT_ID),
        discovery=discovery,
        audience=API_AUDIENCE,
        jwks=jwks,
        client_ids=[CLIENT_ID, "another-app"],
    )
    assert claims["client_id"] == CLIENT_ID


async def test_the_async_path_pins_the_same_way(discovery, jwks, mint):
    with pytest.raises(TokenError, match="tenant"):
        await grantor.async_verify_access_token(
            mint(aud=API_AUDIENCE, tenant="southwind", client_id=CLIENT_ID),
            discovery=discovery,
            audience=API_AUDIENCE,
            jwks=jwks,
            tenant="northwind",
        )
