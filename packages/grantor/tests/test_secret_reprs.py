"""No object that holds a credential prints it.

A ``repr`` reaches places nobody chose to send it: an error reporter that
captures frame locals, a debug page, a stray ``logger.debug("%r", ...)``.
Those redact by *variable name*, and ``request`` or ``auth`` is not a name
anybody redacts. So the objects redact themselves.

Every value below is distinctive, so a substring check cannot pass by
accident.
"""

from __future__ import annotations

import grantor
import httpx
import pytest
from core_support import CLIENT_ID, ISSUER
from grantor import (
    ClientAuth,
    client_secret_basic,
    client_secret_post,
    exchange_code_request,
    refresh_token_request,
    revocation_request,
    userinfo_request,
)

SECRET = "client-secret-7f3a9c"  # noqa: S105 - a fixture
CODE = "auth-code-5e21b8"
VERIFIER = "pkce-verifier-0c4d6e"
REFRESH = "refresh-token-9b8a7c"
ACCESS = "access-token-3d2c1b"


@pytest.mark.parametrize("auth", [client_secret_basic, client_secret_post])
def test_client_auth_does_not_print_its_secret(auth):
    held = auth(CLIENT_ID, SECRET)
    assert SECRET not in repr(held)
    assert CLIENT_ID in repr(held)


def test_a_client_auth_built_directly_does_not_print_its_secret():
    assert SECRET not in repr(ClientAuth(CLIENT_ID, SECRET))


@pytest.mark.parametrize("auth", [client_secret_basic, client_secret_post])
def test_a_code_exchange_request_prints_none_of_its_secrets(discovery, auth):
    request = exchange_code_request(
        discovery,
        auth=auth(CLIENT_ID, SECRET),
        code=CODE,
        redirect_uri="https://app.example.com/cb",
        code_verifier=VERIFIER,
    )
    shown = repr(request)
    for value in (SECRET, CODE, VERIFIER):
        assert value not in shown
    assert request.url in shown


def test_a_refresh_request_does_not_print_the_refresh_token(discovery):
    request = refresh_token_request(
        discovery, auth=client_secret_post(CLIENT_ID, SECRET), refresh_token=REFRESH
    )
    shown = repr(request)
    assert REFRESH not in shown
    assert SECRET not in shown


def test_a_revocation_request_does_not_print_the_token(discovery):
    request = revocation_request(
        discovery, auth=client_secret_basic(CLIENT_ID, SECRET), token=REFRESH
    )
    shown = repr(request)
    assert REFRESH not in shown
    assert SECRET not in shown


def test_a_userinfo_request_does_not_print_the_bearer_header(discovery):
    assert ACCESS not in repr(userinfo_request(discovery, access_token=ACCESS))


def test_an_authorization_request_does_not_print_the_verifier(discovery_payload):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=discovery_payload)

    client = grantor.GrantorClient(
        ISSUER,
        http=httpx.Client(transport=httpx.MockTransport(handler)),
        client_id=CLIENT_ID,
        redirect_uri="https://app.example.com/cb",
    )
    authorization = client.start_authorization()
    assert authorization.code_verifier not in repr(authorization)


def test_a_pkce_pair_does_not_print_the_verifier():
    pair = grantor.generate_pkce()
    shown = repr(pair)
    assert pair.verifier not in shown
    assert pair.challenge in shown
