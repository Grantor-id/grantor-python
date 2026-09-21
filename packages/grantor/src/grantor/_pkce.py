"""PKCE, and the round-trip secrets that go with it.

PKCE is mandatory for every client of this issuer, confidential ones
included — it is OAuth 2.1, and the authorization endpoint refuses a
request without ``code_challenge`` and ``code_challenge_method=S256``. So
there is no switch here to turn it off, and ``plain`` is not implemented.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass

__all__ = [
    "PkcePair",
    "generate_verifier",
    "challenge_for",
    "generate_pkce",
    "generate_state",
    "generate_nonce",
    "CODE_CHALLENGE_METHOD",
]

CODE_CHALLENGE_METHOD = "S256"


@dataclass(frozen=True)
class PkcePair:
    """A verifier and the challenge derived from it.

    The verifier is a secret and the challenge is not: the challenge goes in
    the URL the browser carries, the verifier stays on the server until the
    code comes back. Keeping them in one object is a reminder that sending
    the wrong one is a silent downgrade.
    """

    verifier: str
    challenge: str
    method: str = CODE_CHALLENGE_METHOD


def generate_verifier(*, entropy_bytes: int = 48) -> str:
    """A fresh code verifier.

    48 bytes lands at 64 URL-safe characters, comfortably inside RFC 7636's
    43-to-128 window and well past its entropy floor.
    """
    return secrets.token_urlsafe(entropy_bytes)


def challenge_for(verifier: str) -> str:
    """The S256 challenge for a verifier. Pure, and the reason it is public.

    Base64url of the SHA-256 digest, unpadded — the padding is what a
    hand-rolled implementation most often gets wrong, and an issuer cannot
    tell a mis-encoded challenge from a wrong one.
    """
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def generate_pkce(*, entropy_bytes: int = 48) -> PkcePair:
    verifier = generate_verifier(entropy_bytes=entropy_bytes)
    return PkcePair(verifier=verifier, challenge=challenge_for(verifier))


def generate_state(*, entropy_bytes: int = 32) -> str:
    """CSRF protection for the round trip. Compared constant-time on return."""
    return secrets.token_urlsafe(entropy_bytes)


def generate_nonce(*, entropy_bytes: int = 32) -> str:
    """Replay protection for the ID token. Echoed back as a claim."""
    return secrets.token_urlsafe(entropy_bytes)
