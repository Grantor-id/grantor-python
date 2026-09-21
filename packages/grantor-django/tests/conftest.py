"""A stand-in issuer, good enough to be believed and entirely local.

Real RSA keys, real signatures, real discovery and JWKS documents — served
through ``httpx.MockTransport`` so the whole sign-in flow runs end to end
without a socket. What is faked is the network, never the cryptography: a
test that stubbed out signature verification would pass on a library that
had stopped doing it.
"""

from __future__ import annotations

import json
import time
from typing import Any
from urllib.parse import urlparse

import grantor
import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from django.contrib.auth import get_user_model
from grantor import GrantorClient
from grantor_django import client as client_module
from jwt.algorithms import RSAAlgorithm

ISSUER = "https://acme.api.grantor.id"
CLIENT_ID = "acme-web"
KID = "test-key-1"
SUB = "0d9b1a7e-1a62-4a0e-9b7a-1f0f2c3d4e5f"


@pytest.fixture(autouse=True)
def _no_cached_state():
    grantor.clear_caches()
    yield
    grantor.clear_caches()


@pytest.fixture(scope="session")
def keypair():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private, private.public_key()


@pytest.fixture
def issuer(keypair, monkeypatch):
    """A scripted issuer, and the knobs a test needs to make it misbehave."""
    private, public = keypair
    jwk = json.loads(RSAAlgorithm.to_jwk(public))
    jwk.update({"kid": KID, "use": "sig", "alg": "RS256"})

    state: dict[str, Any] = {
        "discovery": {
            "issuer": ISSUER,
            "authorization_endpoint": f"{ISSUER}/oauth/authorize",
            "token_endpoint": f"{ISSUER}/oauth/token",
            "userinfo_endpoint": f"{ISSUER}/oauth/userinfo",
            "jwks_uri": f"{ISSUER}/oauth/jwks.json",
            "end_session_endpoint": f"{ISSUER}/oauth/logout",
            "code_challenge_methods_supported": ["S256"],
            "id_token_signing_alg_values_supported": ["RS256"],
        },
        "jwks": {"keys": [jwk]},
        "claims": {},
        # The issuer echoes the `nonce` it was sent. Tests record it when
        # they follow the redirect; a test that wants a replay sets
        # `claims["nonce"]` and overrides the echo.
        "echo_nonce": "",
        "userinfo": {},
        "token_status": 200,
        "token_body": None,
        "used_codes": set(),
        "exchanges": [],
    }

    def id_token_for(claims: dict[str, Any]) -> str:
        now = int(time.time())
        payload = {
            "iss": ISSUER,
            "sub": SUB,
            "aud": CLIENT_ID,
            "iat": now,
            "exp": now + 300,
            "nonce": state["echo_nonce"],
            **claims,
        }
        return jwt.encode(payload, private, algorithm="RS256", headers={"kid": KID})

    def handler(request: httpx.Request) -> httpx.Response:
        path = urlparse(str(request.url)).path
        if path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(200, json=state["discovery"])
        if path == "/oauth/jwks.json":
            return httpx.Response(200, json=state["jwks"])
        if path == "/oauth/token":
            body = dict(
                pair.split("=", 1) for pair in request.content.decode().split("&") if "=" in pair
            )
            state["exchanges"].append(body)
            if state["token_status"] != 200:
                return httpx.Response(state["token_status"], json=state["token_body"])
            code = body.get("code", "")
            if code in state["used_codes"]:
                # Presenting a code twice revokes every token issued from
                # it: a replayed code is indistinguishable from a stolen one.
                return httpx.Response(400, json={"error": "invalid_grant"})
            state["used_codes"].add(code)
            return httpx.Response(
                200,
                json={
                    "access_token": "at",
                    "token_type": "Bearer",
                    "expires_in": 300,
                    "id_token": id_token_for(state["claims"]),
                },
            )
        if path == "/oauth/userinfo":
            return httpx.Response(200, json=state["userinfo"])
        return httpx.Response(404, json={"error": "not_found"})

    http = httpx.Client(transport=httpx.MockTransport(handler))

    def fake_get_client() -> GrantorClient:
        return GrantorClient(
            ISSUER,
            http=http,
            client_id=CLIENT_ID,
            client_secret="test-client-secret",
            redirect_uri=client_module.callback_url(),
        )

    monkeypatch.setattr(client_module, "get_client", fake_get_client)
    monkeypatch.setattr("grantor_django.views.get_client", fake_get_client)

    state["id_token_for"] = id_token_for
    return state


@pytest.fixture
def local_user(db):
    """Somebody who already has an account here, not yet linked."""
    User = get_user_model()
    user = User.objects.create_user(username="ana", email="ana@example.com", password="x")
    user.profile_obj = user.profile if hasattr(user, "profile") else None
    from djangoproject.models import Profile

    Profile.objects.create(user=user, grantor_sub="")
    user.refresh_from_db()
    return user
