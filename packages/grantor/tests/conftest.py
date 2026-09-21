"""Fixtures for the core's tests.

Everything here is local: keys minted in-process, a discovery document and a
JWKS built from them. No test in this package opens a socket, which is not
frugality — it is the check that the seams are in the right place. If a pure
function needed a socket to be tested, the function would be in the wrong
module.
"""

from __future__ import annotations

import time
from typing import Any

import grantor
import jwt
import pytest
from core_support import CLIENT_ID, ISSUER, KID, jwk_for
from cryptography.hazmat.primitives.asymmetric import rsa


def _keypair() -> tuple[Any, Any]:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private, private.public_key()


@pytest.fixture(autouse=True)
def _no_cached_state():
    """Discovery and JWKS are process state with a TTL.

    That is right in production and wrong between two tests that disagree
    about what the issuer says.
    """
    grantor.clear_caches()
    yield
    grantor.clear_caches()


@pytest.fixture(scope="session")
def signing_key():
    return _keypair()


@pytest.fixture(scope="session")
def rotated_key():
    return _keypair()


@pytest.fixture
def jwks_payload(signing_key) -> dict[str, Any]:
    _, public = signing_key
    return {"keys": [jwk_for(public, KID)]}


@pytest.fixture
def discovery_payload() -> dict[str, Any]:
    """A document shaped like the one the real issuer serves."""
    return {
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/oauth/authorize",
        "token_endpoint": f"{ISSUER}/oauth/token",
        "userinfo_endpoint": f"{ISSUER}/oauth/userinfo",
        "revocation_endpoint": f"{ISSUER}/oauth/revoke",
        "jwks_uri": f"{ISSUER}/oauth/jwks.json",
        "end_session_endpoint": f"{ISSUER}/oauth/logout",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email", "roles", "offline_access"],
    }


@pytest.fixture
def discovery(discovery_payload) -> grantor.DiscoveryDocument:
    return grantor.parse_discovery_document(discovery_payload, issuer=ISSUER)


@pytest.fixture
def jwks(jwks_payload) -> grantor.JwksCache:
    return grantor.JwksCache(f"{ISSUER}/oauth/jwks.json", keys=jwks_payload)


@pytest.fixture
def mint(signing_key):
    """Mint a token the way the issuer would, with anything overridable.

    Every rejection test is "the same token, one thing wrong", so the minter
    takes the claims apart rather than offering a menu of broken tokens.
    """
    private, _ = signing_key

    def _mint(
        *,
        kid: str = KID,
        key: Any | None = None,
        algorithm: str = "RS256",
        drop: tuple[str, ...] = (),
        **claims: Any,
    ) -> str:
        now = int(time.time())
        payload: dict[str, Any] = {
            "iss": ISSUER,
            "sub": "0d9b1a7e-1a62-4a0e-9b7a-1f0f2c3d4e5f",
            "aud": CLIENT_ID,
            "iat": now,
            "exp": now + 300,
        }
        payload.update(claims)
        # `drop` rather than passing None: PyJWT refuses to encode some
        # claims as None, and "the issuer did not emit this" is a missing
        # key, not a null one.
        for claim in drop:
            payload.pop(claim, None)
        return jwt.encode(
            payload,
            key if key is not None else private,
            algorithm=algorithm,
            headers={"kid": kid},
        )

    return _mint
