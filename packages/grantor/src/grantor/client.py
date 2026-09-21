"""A thin shell over the pure steps.

Every method here is a few lines: shape a request with :mod:`grantor._requests`,
send it with ``httpx``, normalize a refusal with :func:`grantor.parse_error`.
If a method ever grows logic of its own, that logic belongs in a pure
function beside the others, where it can be composed by an adapter and
tested without a socket.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

import httpx

from ._discovery import HTTP_TIMEOUT_SECONDS, DiscoveryDocument, async_discover, discover
from ._errors import GrantorError, ProtocolError, parse_error
from ._pkce import PkcePair, generate_nonce, generate_pkce, generate_state
from ._requests import (
    ClientAuth,
    TokenRequest,
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
    JwksCache,
    async_verify_access_token,
    async_verify_id_token,
    verify_access_token,
    verify_id_token,
)

__all__ = [
    "AuthorizationRequest",
    "TokenResponse",
    "GrantorClient",
    "AsyncGrantorClient",
    "DEFAULT_SCOPE",
]

DEFAULT_SCOPE = "openid profile email"


@dataclass(frozen=True)
class AuthorizationRequest:
    """Where to send the browser, and what must survive until it returns.

    The three secrets are grouped with the URL because they are useless
    apart from it and dangerous if mismatched. How they survive the round
    trip is the caller's problem and deliberately not this package's: the
    Django adapter puts them in a signed, short-TTL cookie rather than the
    session, so that a sign-in begun on one node can finish on another.
    """

    url: str
    state: str
    nonce: str
    code_verifier: str


@dataclass(frozen=True)
class TokenResponse:
    """A token endpoint answer.

    ``raw`` keeps the whole body, because an issuer may return fields this
    class does not name and losing them would send callers back to parsing
    the response themselves.

    ``__repr__`` is overridden: the default would print every token in this
    object the first time somebody logged it, or the first time a traceback
    rendered a local variable.
    """

    access_token: str
    # The OAuth token *type*, not a token: the scheme name the issuer
    # returns and the one this client sends back.
    token_type: str = "Bearer"  # noqa: S105
    expires_in: int | None = None
    refresh_token: str | None = None
    id_token: str | None = None
    scope: str | None = None
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False)

    def __repr__(self) -> str:
        held = [
            name
            for name, present in (
                ("access_token", True),
                ("refresh_token", self.refresh_token is not None),
                ("id_token", self.id_token is not None),
            )
            if present
        ]
        return f"TokenResponse(holds={held}, expires_in={self.expires_in!r})"

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> TokenResponse:
        access_token = payload.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise ProtocolError("token response carried no access token")
        expires_in = payload.get("expires_in")
        return cls(
            access_token=access_token,
            token_type=str(payload.get("token_type") or "Bearer"),
            expires_in=int(expires_in) if isinstance(expires_in, (int, float, str)) else None,
            refresh_token=payload.get("refresh_token"),
            id_token=payload.get("id_token"),
            scope=payload.get("scope"),
            raw=dict(payload),
        )


def _auth_for(client_id: str, client_secret: str | None, method: str) -> ClientAuth:
    if client_secret is None:
        return public_client(client_id)
    if method == "client_secret_post":
        return client_secret_post(client_id, client_secret)
    return client_secret_basic(client_id, client_secret)


def _json_or_refuse(response: httpx.Response) -> Mapping[str, Any]:
    if response.status_code != 200:
        raise ProtocolError(parse_error(response), status=response.status_code)
    try:
        payload = response.json()
    except ValueError as exc:
        raise ProtocolError("issuer did not return JSON", status=response.status_code) from exc
    if not isinstance(payload, Mapping):
        raise ProtocolError("issuer returned a non-object body", status=response.status_code)
    return payload


class _Base:
    """Configuration shared by the sync and async clients."""

    def __init__(
        self,
        issuer: str,
        *,
        client_id: str,
        client_secret: str | None = None,
        redirect_uri: str | None = None,
        scope: str | Iterable[str] = DEFAULT_SCOPE,
        resource: str | None = None,
        auth_method: str = "client_secret_basic",
        timeout: float = HTTP_TIMEOUT_SECONDS,
    ) -> None:
        self.issuer = issuer.rstrip("/")
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.scope = scope if isinstance(scope, str) else " ".join(scope)
        self.resource = resource
        self.timeout = timeout
        self._auth = _auth_for(client_id, client_secret, auth_method)

    def __repr__(self) -> str:
        # Never the default: this object holds a client secret.
        return f"{type(self).__name__}(issuer={self.issuer!r}, client_id={self.client_id!r})"

    def _redirect_uri(self, given: str | None) -> str:
        value = given or self.redirect_uri
        if not value:
            raise GrantorError("no redirect_uri was configured or supplied")
        return value

    def _authorization(
        self,
        discovery: DiscoveryDocument,
        *,
        redirect_uri: str | None,
        scope: str | Iterable[str] | None,
        resource: str | None,
        prompt: str | None,
        login_hint: str | None,
        extra: Mapping[str, Any] | None,
        pkce: PkcePair | None,
    ) -> AuthorizationRequest:
        pair = pkce or generate_pkce()
        state = generate_state()
        nonce = generate_nonce()
        url = build_authorization_url(
            discovery,
            client_id=self.client_id,
            redirect_uri=self._redirect_uri(redirect_uri),
            scope=scope if scope is not None else self.scope,
            state=state,
            nonce=nonce,
            code_challenge=pair.challenge,
            resource=resource if resource is not None else self.resource,
            prompt=prompt,
            login_hint=login_hint,
            extra=extra,
        )
        return AuthorizationRequest(url=url, state=state, nonce=nonce, code_verifier=pair.verifier)


class GrantorClient(_Base):
    """The synchronous client."""

    def __init__(self, issuer: str, *, http: httpx.Client | None = None, **kwargs: Any) -> None:
        super().__init__(issuer, **kwargs)
        self._http = http

    def discovery(self, *, force: bool = False) -> DiscoveryDocument:
        return discover(self.issuer, client=self._http, timeout=self.timeout, force=force)

    def start_authorization(
        self,
        *,
        redirect_uri: str | None = None,
        scope: str | Iterable[str] | None = None,
        resource: str | None = None,
        prompt: str | None = None,
        login_hint: str | None = None,
        extra: Mapping[str, Any] | None = None,
        pkce: PkcePair | None = None,
    ) -> AuthorizationRequest:
        return self._authorization(
            self.discovery(),
            redirect_uri=redirect_uri,
            scope=scope,
            resource=resource,
            prompt=prompt,
            login_hint=login_hint,
            extra=extra,
            pkce=pkce,
        )

    def _send(self, request: TokenRequest, *, method: str = "POST") -> httpx.Response:
        def call(client: httpx.Client) -> httpx.Response:
            if method == "GET":
                return client.get(
                    request.url, headers=request.headers or None, timeout=self.timeout
                )
            return client.post(
                request.url,
                data=request.data,
                auth=request.auth or httpx.USE_CLIENT_DEFAULT,
                headers=request.headers or None,
                timeout=self.timeout,
            )

        try:
            if self._http is not None:
                return call(self._http)
            with httpx.Client(timeout=self.timeout, follow_redirects=False) as owned:
                return call(owned)
        except httpx.HTTPError as exc:
            raise ProtocolError(f"issuer unreachable: {type(exc).__name__}") from exc

    def exchange_code(
        self,
        code: str,
        *,
        redirect_uri: str | None = None,
        code_verifier: str,
        resource: str | None = None,
    ) -> TokenResponse:
        """Exchange an authorization code. Never queue this.

        Codes live minutes and are single-use, and **presenting one twice
        revokes every token issued from it** — a replayed code is
        indistinguishable from a stolen one. A background job that retries
        is therefore a way to sign a person out, not a way to be resilient.
        """
        request = exchange_code_request(
            self.discovery(),
            auth=self._auth,
            code=code,
            redirect_uri=self._redirect_uri(redirect_uri),
            code_verifier=code_verifier,
            resource=resource if resource is not None else self.resource,
        )
        return TokenResponse.from_payload(_json_or_refuse(self._send(request)))

    def refresh(
        self,
        refresh_token: str,
        *,
        scope: str | Iterable[str] | None = None,
        resource: str | None = None,
    ) -> TokenResponse:
        """Refresh, and **store the new refresh token**.

        They rotate: this response retires the one just presented. Treat a
        rotation failure as a sign-out rather than retrying with the old
        value — presenting a retired token revokes the whole family.
        """
        request = refresh_token_request(
            self.discovery(),
            auth=self._auth,
            refresh_token=refresh_token,
            scope=scope,
            resource=resource if resource is not None else self.resource,
        )
        return TokenResponse.from_payload(_json_or_refuse(self._send(request)))

    def fetch_userinfo(self, access_token: str) -> Mapping[str, Any]:
        request = userinfo_request(self.discovery(), access_token=access_token)
        return _json_or_refuse(self._send(request, method="GET"))

    def revoke(self, token: str, *, token_type_hint: str | None = None) -> None:
        request = revocation_request(
            self.discovery(), auth=self._auth, token=token, token_type_hint=token_type_hint
        )
        response = self._send(request)
        # RFC 7009: a revocation of an unknown token is a success. Only a
        # real refusal is worth raising on.
        if response.status_code not in (200, 204):
            raise ProtocolError(parse_error(response), status=response.status_code)

    def verify_id_token(
        self, raw: str, *, nonce: str | None = None, jwks: JwksCache | None = None
    ) -> dict[str, Any]:
        return verify_id_token(
            raw,
            discovery=self.discovery(),
            audience=self.client_id,
            nonce=nonce,
            jwks=jwks,
            client=self._http,
        )

    def verify_access_token(
        self,
        raw: str,
        *,
        audience: str | Iterable[str] | None = None,
        jwks: JwksCache | None = None,
    ) -> dict[str, Any]:
        target = audience if audience is not None else (self.resource or self.client_id)
        return verify_access_token(
            raw, discovery=self.discovery(), audience=target, jwks=jwks, client=self._http
        )

    def end_session_url(
        self,
        id_token_hint: str,
        *,
        post_logout_redirect_uri: str | None = None,
        state: str | None = None,
    ) -> str:
        return build_end_session_url(
            self.discovery(),
            id_token_hint=id_token_hint,
            post_logout_redirect_uri=post_logout_redirect_uri,
            state=state,
        )


class AsyncGrantorClient(_Base):
    """The asynchronous client. Same surface, nothing blocking."""

    def __init__(
        self, issuer: str, *, http: httpx.AsyncClient | None = None, **kwargs: Any
    ) -> None:
        super().__init__(issuer, **kwargs)
        self._http = http

    async def discovery(self, *, force: bool = False) -> DiscoveryDocument:
        return await async_discover(
            self.issuer, client=self._http, timeout=self.timeout, force=force
        )

    async def start_authorization(
        self,
        *,
        redirect_uri: str | None = None,
        scope: str | Iterable[str] | None = None,
        resource: str | None = None,
        prompt: str | None = None,
        login_hint: str | None = None,
        extra: Mapping[str, Any] | None = None,
        pkce: PkcePair | None = None,
    ) -> AuthorizationRequest:
        return self._authorization(
            await self.discovery(),
            redirect_uri=redirect_uri,
            scope=scope,
            resource=resource,
            prompt=prompt,
            login_hint=login_hint,
            extra=extra,
            pkce=pkce,
        )

    async def _send(self, request: TokenRequest, *, method: str = "POST") -> httpx.Response:
        async def call(client: httpx.AsyncClient) -> httpx.Response:
            if method == "GET":
                return await client.get(
                    request.url, headers=request.headers or None, timeout=self.timeout
                )
            return await client.post(
                request.url,
                data=request.data,
                auth=request.auth or httpx.USE_CLIENT_DEFAULT,
                headers=request.headers or None,
                timeout=self.timeout,
            )

        try:
            if self._http is not None:
                return await call(self._http)
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False) as owned:
                return await call(owned)
        except httpx.HTTPError as exc:
            raise ProtocolError(f"issuer unreachable: {type(exc).__name__}") from exc

    async def exchange_code(
        self,
        code: str,
        *,
        redirect_uri: str | None = None,
        code_verifier: str,
        resource: str | None = None,
    ) -> TokenResponse:
        request = exchange_code_request(
            await self.discovery(),
            auth=self._auth,
            code=code,
            redirect_uri=self._redirect_uri(redirect_uri),
            code_verifier=code_verifier,
            resource=resource if resource is not None else self.resource,
        )
        return TokenResponse.from_payload(_json_or_refuse(await self._send(request)))

    async def refresh(
        self,
        refresh_token: str,
        *,
        scope: str | Iterable[str] | None = None,
        resource: str | None = None,
    ) -> TokenResponse:
        request = refresh_token_request(
            await self.discovery(),
            auth=self._auth,
            refresh_token=refresh_token,
            scope=scope,
            resource=resource if resource is not None else self.resource,
        )
        return TokenResponse.from_payload(_json_or_refuse(await self._send(request)))

    async def fetch_userinfo(self, access_token: str) -> Mapping[str, Any]:
        request = userinfo_request(await self.discovery(), access_token=access_token)
        return _json_or_refuse(await self._send(request, method="GET"))

    async def revoke(self, token: str, *, token_type_hint: str | None = None) -> None:
        request = revocation_request(
            await self.discovery(),
            auth=self._auth,
            token=token,
            token_type_hint=token_type_hint,
        )
        response = await self._send(request)
        if response.status_code not in (200, 204):
            raise ProtocolError(parse_error(response), status=response.status_code)

    async def verify_id_token(
        self, raw: str, *, nonce: str | None = None, jwks: JwksCache | None = None
    ) -> dict[str, Any]:
        return await async_verify_id_token(
            raw,
            discovery=await self.discovery(),
            audience=self.client_id,
            nonce=nonce,
            jwks=jwks,
            client=self._http,
        )

    async def verify_access_token(
        self,
        raw: str,
        *,
        audience: str | Iterable[str] | None = None,
        jwks: JwksCache | None = None,
    ) -> dict[str, Any]:
        target = audience if audience is not None else (self.resource or self.client_id)
        return await async_verify_access_token(
            raw, discovery=await self.discovery(), audience=target, jwks=jwks, client=self._http
        )

    async def end_session_url(
        self,
        id_token_hint: str,
        *,
        post_logout_redirect_uri: str | None = None,
        state: str | None = None,
    ) -> str:
        return build_end_session_url(
            await self.discovery(),
            id_token_hint=id_token_hint,
            post_logout_redirect_uri=post_logout_redirect_uri,
            state=state,
        )
