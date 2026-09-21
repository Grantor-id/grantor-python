"""The client, which should be thin enough that these tests are short.

If a test in here ever needs to set up more than a response, that is a sign
logic has crept out of the pure functions and into the shell.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import grantor
import httpx
import pytest
from core_support import CLIENT_ID, ISSUER
from grantor import GrantorClient, ProtocolError

SECRET = "sup3r-s3cret"  # noqa: S105 - a fixture, and the point of two tests below


def _transport(discovery_payload, routes):
    """Serve discovery, plus whatever this test cares about."""

    def handler(request: httpx.Request) -> httpx.Response:
        path = urlparse(str(request.url)).path
        if path == "/.well-known/openid-configuration":
            return httpx.Response(200, json=discovery_payload)
        route = routes.get(path)
        if route is None:
            return httpx.Response(404, json={"error": "not_found"})
        return route(request)

    return httpx.MockTransport(handler)


def _client(discovery_payload, routes=None, **kwargs) -> GrantorClient:
    http = httpx.Client(transport=_transport(discovery_payload, routes or {}))
    kwargs.setdefault("client_id", CLIENT_ID)
    kwargs.setdefault("client_secret", SECRET)
    kwargs.setdefault("redirect_uri", "https://app.example.com/auth/callback")
    return GrantorClient(ISSUER, http=http, **kwargs)


def test_start_authorization_mints_a_usable_round_trip(discovery_payload):
    client = _client(discovery_payload)
    request = client.start_authorization()
    params = {k: v[0] for k, v in parse_qs(urlparse(request.url).query).items()}

    assert params["code_challenge"] == grantor.challenge_for(request.code_verifier)
    assert params["state"] == request.state
    assert params["nonce"] == request.nonce
    assert params["redirect_uri"] == "https://app.example.com/auth/callback"


def test_two_sign_ins_never_share_a_state_or_a_verifier(discovery_payload):
    client = _client(discovery_payload)
    first, second = client.start_authorization(), client.start_authorization()
    assert first.state != second.state
    assert first.nonce != second.nonce
    assert first.code_verifier != second.code_verifier


def test_a_successful_exchange_returns_the_tokens(discovery_payload):
    seen = {}

    def token(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("authorization")
        seen["body"] = parse_qs(request.content.decode())
        return httpx.Response(
            200,
            json={
                "access_token": "at",
                "token_type": "Bearer",
                "expires_in": 300,
                "refresh_token": "rt",
                "id_token": "it",
                "scope": "openid profile",
            },
        )

    client = _client(discovery_payload, {"/oauth/token": token})
    tokens = client.exchange_code("the-code", code_verifier="ver")

    assert tokens.access_token == "at"
    assert tokens.refresh_token == "rt"
    assert tokens.id_token == "it"
    assert tokens.expires_in == 300
    assert seen["auth"].startswith("Basic ")
    assert seen["body"]["code_verifier"] == ["ver"]
    assert "client_secret" not in seen["body"]


def test_a_refusal_in_the_rfc_shape_raises_its_code(discovery_payload):
    def token(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"error": "invalid_grant", "error_description": "used"})

    client = _client(discovery_payload, {"/oauth/token": token})
    with pytest.raises(ProtocolError) as excinfo:
        client.exchange_code("replayed", code_verifier="ver")
    assert excinfo.value.code == "invalid_grant"
    assert excinfo.value.status == 400


def test_a_refusal_in_the_management_envelope_raises_its_code(discovery_payload):
    """The shape the second hand-rolled implementation could not parse."""

    def token(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            400, json={"error": {"code": "invalid_redirect_uri", "message": "not registered"}}
        )

    client = _client(discovery_payload, {"/oauth/token": token})
    with pytest.raises(ProtocolError) as excinfo:
        client.exchange_code("c", code_verifier="ver")
    assert excinfo.value.code == "invalid_redirect_uri"


def test_a_token_response_without_an_access_token_is_a_refusal(discovery_payload):
    def token(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"token_type": "Bearer"})

    client = _client(discovery_payload, {"/oauth/token": token})
    with pytest.raises(ProtocolError):
        client.exchange_code("c", code_verifier="ver")


def test_a_refresh_sends_the_refresh_grant(discovery_payload):
    seen = {}

    def token(request: httpx.Request) -> httpx.Response:
        seen["body"] = parse_qs(request.content.decode())
        return httpx.Response(200, json={"access_token": "at2", "refresh_token": "rt2"})

    client = _client(discovery_payload, {"/oauth/token": token})
    tokens = client.refresh("rt1")
    assert seen["body"]["grant_type"] == ["refresh_token"]
    assert tokens.refresh_token == "rt2"


def test_userinfo_is_read_with_the_access_token(discovery_payload):
    def userinfo(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer at"
        return httpx.Response(200, json={"sub": "u", "permissions": ["things:write"]})

    client = _client(discovery_payload, {"/oauth/userinfo": userinfo})
    claims = client.fetch_userinfo("at")
    assert claims["permissions"] == ["things:write"]


def test_revoking_an_unknown_token_is_a_success(discovery_payload):
    """RFC 7009 says so, and treating it as a failure makes sign-out flaky."""

    def revoke(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200)

    client = _client(discovery_payload, {"/oauth/revoke": revoke})
    client.revoke("anything")


def test_a_real_revocation_refusal_still_raises(discovery_payload):
    def revoke(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "invalid_client"})

    client = _client(discovery_payload, {"/oauth/revoke": revoke})
    with pytest.raises(ProtocolError, match="invalid_client"):
        client.revoke("tok")


def test_an_unreachable_issuer_is_not_a_traceback(discovery_payload):
    def token(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("timed out")

    client = _client(discovery_payload, {"/oauth/token": token})
    with pytest.raises(ProtocolError, match="unreachable"):
        client.exchange_code("c", code_verifier="ver")


def test_the_client_repr_does_not_print_its_secret(discovery_payload):
    """A repr reaches logs, tracebacks and debuggers without anyone deciding to put it there."""
    client = _client(discovery_payload)
    assert SECRET not in repr(client)
    assert CLIENT_ID in repr(client)


def test_a_token_response_repr_names_what_it_holds_not_what_it_is(discovery_payload):
    def token(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"access_token": "at", "refresh_token": "rt", "id_token": "it"}
        )

    client = _client(discovery_payload, {"/oauth/token": token})
    tokens = client.exchange_code("c", code_verifier="ver")
    printed = repr(tokens)
    assert "at" not in printed.replace("TokenResponse", "")
    assert "refresh_token" in printed
    assert "rt" not in printed


def test_sign_out_needs_only_the_hint(discovery_payload):
    client = _client(discovery_payload)
    url = client.end_session_url("the-id-token", post_logout_redirect_uri="https://app/bye")
    assert "id_token_hint=the-id-token" in url


async def test_the_async_client_exchanges_a_code(discovery_payload):
    def handler(request: httpx.Request) -> httpx.Response:
        path = urlparse(str(request.url)).path
        if path == "/.well-known/openid-configuration":
            return httpx.Response(200, json=discovery_payload)
        return httpx.Response(200, json={"access_token": "at"})

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client = grantor.AsyncGrantorClient(
        ISSUER,
        http=http,
        client_id=CLIENT_ID,
        client_secret=SECRET,
        redirect_uri="https://app.example.com/cb",
    )
    tokens = await client.exchange_code("c", code_verifier="ver")
    assert tokens.access_token == "at"
