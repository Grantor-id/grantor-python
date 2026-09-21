"""The protocol core of the Grantor client — no framework, no Django.

**Every pure step of the flow is public API here, not a private helper.**
``build_authorization_url``, ``verify_id_token``, ``parse_error``,
``exchange_code_request`` and the rest are importable and documented, and
:class:`GrantorClient` is a thin shell over them. That is the condition that
makes the split between this package and ``grantor-django`` worth having:
an adapter for a framework this package has never heard of composes these
instead of copying them. A core whose useful parts are all private is a core
that gets copy-pasted.

The rule the whole library is held to, and the reason it can exist beside a
promise that there is no proprietary SDK:

    The library may never require anything of the issuer that a stock OIDC
    library could not do. If a feature needs a change on the issuer side to
    work, that change must be an RFC, or the feature is wrong.

One string is configured — the issuer. Every endpoint is read from its
discovery document.

    >>> from grantor import GrantorClient
    >>> client = GrantorClient(
    ...     "https://acme.api.grantor.id",
    ...     client_id="...",
    ...     client_secret="...",
    ...     redirect_uri="https://app.example.com/auth/callback",
    ... )
    >>> request = client.start_authorization()   # doctest: +SKIP
    >>> # send the browser to request.url; keep state, nonce and code_verifier
"""

from __future__ import annotations

from ._discovery import (
    DISCOVERY_TTL_SECONDS,
    HTTP_TIMEOUT_SECONDS,
    DiscoveryDocument,
    async_discover,
    clear_discovery_cache,
    discover,
    discovery_url,
    parse_discovery_document,
)
from ._errors import (
    DiscoveryError,
    GrantorError,
    ProtocolError,
    TokenError,
    normalize_error,
    parse_error,
    parse_redirect_error,
)
from ._pkce import (
    CODE_CHALLENGE_METHOD,
    PkcePair,
    challenge_for,
    generate_nonce,
    generate_pkce,
    generate_state,
    generate_verifier,
)
from ._requests import (
    ClientAuth,
    TokenRequest,
    append_query,
    build_authorization_url,
    build_end_session_url,
    client_secret_basic,
    client_secret_post,
    exchange_code_request,
    public_client,
    refresh_token_request,
    revocation_request,
    userinfo_request,
)
from ._tokens import (
    ACCESS_TOKEN_REQUIRED_CLAIMS,
    ID_TOKEN_REQUIRED_CLAIMS,
    LEEWAY_SECONDS,
    JwksCache,
    async_fetch_jwks,
    async_verify_access_token,
    async_verify_id_token,
    check_nonce,
    clear_jwks_cache,
    decode_and_verify,
    fetch_jwks,
    verify_access_token,
    verify_id_token,
)
from .client import (
    DEFAULT_SCOPE,
    AsyncGrantorClient,
    AuthorizationRequest,
    GrantorClient,
    TokenResponse,
)

__version__ = "0.1.0a0"

__all__ = [
    "__version__",
    # Clients — thin shells over everything below them.
    "GrantorClient",
    "AsyncGrantorClient",
    "AuthorizationRequest",
    "TokenResponse",
    "DEFAULT_SCOPE",
    # Discovery.
    "DiscoveryDocument",
    "discover",
    "async_discover",
    "discovery_url",
    "parse_discovery_document",
    "clear_discovery_cache",
    "DISCOVERY_TTL_SECONDS",
    "HTTP_TIMEOUT_SECONDS",
    # PKCE and the round-trip secrets.
    "PkcePair",
    "generate_pkce",
    "generate_verifier",
    "challenge_for",
    "generate_state",
    "generate_nonce",
    "CODE_CHALLENGE_METHOD",
    # Request shaping — pure, and public for exactly that reason.
    "build_authorization_url",
    "exchange_code_request",
    "refresh_token_request",
    "userinfo_request",
    "revocation_request",
    "build_end_session_url",
    "append_query",
    "ClientAuth",
    "TokenRequest",
    "client_secret_basic",
    "client_secret_post",
    "public_client",
    # Verification.
    "verify_id_token",
    "async_verify_id_token",
    "verify_access_token",
    "async_verify_access_token",
    "decode_and_verify",
    "check_nonce",
    "JwksCache",
    "fetch_jwks",
    "async_fetch_jwks",
    "clear_jwks_cache",
    "LEEWAY_SECONDS",
    "ID_TOKEN_REQUIRED_CLAIMS",
    "ACCESS_TOKEN_REQUIRED_CLAIMS",
    # Errors, and the two envelopes they arrive in.
    "GrantorError",
    "DiscoveryError",
    "ProtocolError",
    "TokenError",
    "parse_error",
    "normalize_error",
    "parse_redirect_error",
]


def clear_caches() -> None:
    """Drop the discovery and JWKS caches.

    Both are process state with a TTL, which is right in production and
    wrong in a test that has just changed what the issuer says.
    """
    clear_discovery_cache()
    clear_jwks_cache()
