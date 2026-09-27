"""Shaping every request the flow makes, without making any of them.

This module is the reason the split between ``grantor`` and an adapter is
worth having. Each function here turns arguments into a URL or a
:class:`TokenRequest` and stops; the client in :mod:`grantor.client` is a
thin shell that hands those to ``httpx``. An adapter for a framework this
package has never heard of composes these instead of reimplementing them,
and every one of them is testable without a socket.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

from ._discovery import DiscoveryDocument
from ._errors import DiscoveryError
from ._pkce import CODE_CHALLENGE_METHOD

__all__ = [
    "TokenRequest",
    "ClientAuth",
    "client_secret_basic",
    "client_secret_post",
    "public_client",
    "build_authorization_url",
    "exchange_code_request",
    "refresh_token_request",
    "userinfo_request",
    "revocation_request",
    "build_end_session_url",
    "append_query",
]


def append_query(endpoint: str, params: Mapping[str, Any]) -> str:
    """Add parameters to an endpoint that may already carry some.

    An issuer is entitled to publish an endpoint with a query string on it,
    and a client that joins with ``?`` unconditionally produces a URL with
    two of them. Cheap to get right, invisible until the one issuer that
    does it.
    """
    pairs = {k: v for k, v in params.items() if v is not None}
    if not pairs:
        return endpoint
    separator = "&" if "?" in endpoint else "?"
    return f"{endpoint}{separator}{urlencode(pairs)}"


@dataclass(frozen=True)
class ClientAuth:
    """How this client proves who it is at the token endpoint.

    Three cases, and the issuer accepts all three: ``client_secret_basic``
    (an ``Authorization: Basic`` header), ``client_secret_post`` (the
    credentials in the form body), and a public client, which sends a
    ``client_id`` and no secret at all.

    The secret is left out of the ``repr``, so printing this object, or an
    error reporter capturing it as a local variable, never shows it.
    """

    client_id: str
    client_secret: str | None = field(default=None, repr=False)
    method: str = "client_secret_basic"

    def apply(self, data: dict[str, Any]) -> tuple[str, str] | None:
        """Fold this client's credentials into a form body.

        Returns the basic-auth pair when that is the method, so the caller
        hands it to the HTTP client, and ``None`` otherwise. ``client_id``
        always ends up in the body: the token endpoint needs to know which
        client is asking even when the secret travels in a header.
        """
        data["client_id"] = self.client_id
        if self.client_secret is None:
            return None
        if self.method == "client_secret_post":
            data["client_secret"] = self.client_secret
            return None
        return (self.client_id, self.client_secret)


def client_secret_basic(client_id: str, client_secret: str) -> ClientAuth:
    return ClientAuth(client_id, client_secret, "client_secret_basic")


def client_secret_post(client_id: str, client_secret: str) -> ClientAuth:
    return ClientAuth(client_id, client_secret, "client_secret_post")


def public_client(client_id: str) -> ClientAuth:
    """A client with no secret. PKCE is what protects it, and PKCE is not optional."""
    return ClientAuth(client_id, None, "none")


@dataclass(frozen=True)
class TokenRequest:
    """A POST, described but not sent.

    ``auth`` is the basic-auth pair when the client authenticates that way.
    It is a separate field rather than a pre-built header so that nothing
    here ever holds an encoded credential — the HTTP client assembles it at
    the moment of sending and it never sits in a value that might be logged.

    ``data``, ``auth`` and ``headers`` are left out of the ``repr``: between
    them they hold the authorization code, the PKCE verifier, refresh and
    access tokens and the client secret. The ``repr`` shows the URL and
    the names of the form fields, never their values.
    """

    url: str
    data: dict[str, Any] = field(repr=False)
    auth: tuple[str, str] | None = field(default=None, repr=False)
    headers: dict[str, str] = field(default_factory=dict, repr=False)

    def __repr__(self) -> str:
        return (
            f"TokenRequest(url={self.url!r}, fields={sorted(self.data)!r}, "
            f"basic_auth={self.auth is not None})"
        )


def build_authorization_url(
    discovery: DiscoveryDocument,
    *,
    client_id: str,
    redirect_uri: str,
    scope: str | Iterable[str],
    state: str,
    code_challenge: str,
    nonce: str | None = None,
    resource: str | None = None,
    prompt: str | None = None,
    login_hint: str | None = None,
    extra: Mapping[str, Any] | None = None,
) -> str:
    """Where to send the browser.

    ``code_challenge`` has no default and ``code_challenge_method`` is not a
    parameter: S256 is the only method this issuer accepts, and a client
    that could express ``plain`` would eventually express it.

    ``resource`` is RFC 8707 — name the API the access token is for, and
    ``aud`` comes back as that API's identifier rather than this client's
    id. Ask for it whenever the token is going to a resource server.
    """
    if isinstance(scope, str):
        scope_value = scope
    else:
        scope_value = " ".join(scope)

    params: dict[str, Any] = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope_value,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": CODE_CHALLENGE_METHOD,
        "nonce": nonce,
        "resource": resource,
        "prompt": prompt,
        "login_hint": login_hint,
    }
    if extra:
        params.update(extra)
    return append_query(discovery.authorization_endpoint, params)


def exchange_code_request(
    discovery: DiscoveryDocument,
    *,
    auth: ClientAuth,
    code: str,
    redirect_uri: str,
    code_verifier: str,
    resource: str | None = None,
) -> TokenRequest:
    """The authorization-code exchange, described.

    ``redirect_uri`` must be byte-identical to the one in the authorization
    request — a difference of one trailing slash is ``invalid_grant`` at the
    token endpoint, and the message does not say which of the two ways it
    could mean.
    """
    data: dict[str, Any] = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
    }
    if resource is not None:
        data["resource"] = resource
    basic = auth.apply(data)
    return TokenRequest(url=discovery.token_endpoint, data=data, auth=basic)


def refresh_token_request(
    discovery: DiscoveryDocument,
    *,
    auth: ClientAuth,
    refresh_token: str,
    scope: str | Iterable[str] | None = None,
    resource: str | None = None,
) -> TokenRequest:
    """A refresh, described.

    Refresh tokens **rotate**: the response carries a new one and retires
    the one just used. Store the new one and drop the old. Presenting a
    retired refresh token is indistinguishable from theft and revokes the
    whole family, so a caller that keeps a copy "just in case" signs its
    users out the first time it uses the copy.
    """
    data: dict[str, Any] = {"grant_type": "refresh_token", "refresh_token": refresh_token}
    if scope is not None:
        data["scope"] = scope if isinstance(scope, str) else " ".join(scope)
    if resource is not None:
        data["resource"] = resource
    basic = auth.apply(data)
    return TokenRequest(url=discovery.token_endpoint, data=data, auth=basic)


def userinfo_request(discovery: DiscoveryDocument, *, access_token: str) -> TokenRequest:
    """Userinfo, described — the fresh-claims path.

    This is where ``permissions`` lives; it is never in the ID token. It is
    also where a role change shows up promptly: the ID token in hand still
    says what it said when it was minted, while userinfo answers from the
    assignments as they stand now.
    """
    endpoint = discovery.userinfo_endpoint
    if endpoint is None:
        raise DiscoveryError("discovery document lacks userinfo_endpoint")
    return TokenRequest(
        url=endpoint,
        data={},
        headers={"Authorization": f"Bearer {access_token}"},
    )


def revocation_request(
    discovery: DiscoveryDocument,
    *,
    auth: ClientAuth,
    token: str,
    token_type_hint: str | None = None,
) -> TokenRequest:
    """RFC 7009 revocation, described."""
    endpoint = discovery.revocation_endpoint
    if endpoint is None:
        raise DiscoveryError("discovery document lacks revocation_endpoint")
    data: dict[str, Any] = {"token": token}
    if token_type_hint is not None:
        data["token_type_hint"] = token_type_hint
    basic = auth.apply(data)
    return TokenRequest(url=endpoint, data=data, auth=basic)


def build_end_session_url(
    discovery: DiscoveryDocument,
    *,
    id_token_hint: str,
    post_logout_redirect_uri: str | None = None,
    state: str | None = None,
) -> str:
    """RP-Initiated Logout 1.0.

    ``id_token_hint`` is required here, with no way to omit it, because
    omitting it is how sign-out silently stops working: without a hint there
    is nothing proving which application is asking, so there is nothing to
    validate the post-logout redirect against, and the browser is not
    redirected at all — it lands on a confirmation screen on the issuer's
    host. ``client_id`` does not substitute; anyone can name a client id and
    only the hint proves one.

    **An expired ID token is the normal case and is accepted.** The session
    being ended is expected to outlive the token that proves it, so the
    issuer verifies the signature and the issuer and does not check expiry.
    Keep the last ID token you were issued for exactly this.
    """
    endpoint = discovery.end_session_endpoint
    if endpoint is None:
        raise DiscoveryError("discovery document lacks end_session_endpoint")
    return append_query(
        endpoint,
        {
            "id_token_hint": id_token_hint,
            "post_logout_redirect_uri": post_logout_redirect_uri,
            "state": state,
        },
    )
