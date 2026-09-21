"""PKCE and the pure request shaping.

Everything in here is a function from arguments to a URL or a described
request. That is the point: an adapter for another framework composes these,
and none of them needs a socket to be proven.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import grantor
import pytest
from conftest import API_AUDIENCE, CLIENT_ID
from grantor import DiscoveryError


def test_the_challenge_matches_the_rfc_7636_vector():
    """Appendix B of RFC 7636, byte for byte.

    The unpadded base64url encoding is the part a hand-rolled
    implementation gets wrong, and an issuer cannot tell a mis-encoded
    challenge from a wrong one — it just says the exchange failed.
    """
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert grantor.challenge_for(verifier) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def test_a_generated_challenge_verifies_against_its_verifier():
    pair = grantor.generate_pkce()
    assert grantor.challenge_for(pair.verifier) == pair.challenge
    assert pair.method == "S256"


def test_verifiers_are_within_the_rfc_length_window():
    assert 43 <= len(grantor.generate_verifier()) <= 128


def test_two_verifiers_are_never_the_same():
    assert grantor.generate_verifier() != grantor.generate_verifier()


def _params(url: str) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}


def test_the_authorization_url_always_carries_pkce(discovery):
    """There is no way to express a request without it.

    PKCE is mandatory for every client of this issuer, confidential ones
    included — it is OAuth 2.1. A client that could express `plain` would
    eventually express it, so the method is not a parameter.
    """
    url = grantor.build_authorization_url(
        discovery,
        client_id=CLIENT_ID,
        redirect_uri="https://app.example.com/auth/callback",
        scope="openid profile",
        state="st",
        nonce="no",
        code_challenge="ch",
    )
    params = _params(url)
    assert params["code_challenge"] == "ch"
    assert params["code_challenge_method"] == "S256"
    assert params["response_type"] == "code"
    assert params["state"] == "st"
    assert params["nonce"] == "no"


def test_an_absent_optional_parameter_is_omitted_not_sent_empty(discovery):
    url = grantor.build_authorization_url(
        discovery,
        client_id=CLIENT_ID,
        redirect_uri="https://app.example.com/cb",
        scope="openid",
        state="st",
        code_challenge="ch",
    )
    params = _params(url)
    assert "nonce" not in params
    assert "resource" not in params
    assert "prompt" not in params


def test_a_scope_may_be_given_as_a_list(discovery):
    url = grantor.build_authorization_url(
        discovery,
        client_id=CLIENT_ID,
        redirect_uri="https://app.example.com/cb",
        scope=["openid", "email", "roles"],
        state="st",
        code_challenge="ch",
    )
    assert _params(url)["scope"] == "openid email roles"


def test_the_resource_parameter_names_the_api_the_token_is_for(discovery):
    """RFC 8707. Without it, `aud` comes back as this client's id."""
    url = grantor.build_authorization_url(
        discovery,
        client_id=CLIENT_ID,
        redirect_uri="https://app.example.com/cb",
        scope="openid",
        state="st",
        code_challenge="ch",
        resource=API_AUDIENCE,
    )
    assert _params(url)["resource"] == API_AUDIENCE


def test_an_endpoint_that_already_has_a_query_gets_one_question_mark():
    """An issuer is entitled to publish an endpoint with a query on it."""
    url = grantor.append_query("https://issuer/authorize?tenant=acme", {"state": "st"})
    assert url == "https://issuer/authorize?tenant=acme&state=st"
    assert url.count("?") == 1


def test_client_secret_basic_keeps_the_secret_out_of_the_body(discovery):
    request = grantor.exchange_code_request(
        discovery,
        auth=grantor.client_secret_basic(CLIENT_ID, "s3cret"),
        code="the-code",
        redirect_uri="https://app.example.com/cb",
        code_verifier="ver",
    )
    assert request.auth == (CLIENT_ID, "s3cret")
    assert "client_secret" not in request.data
    assert request.data["client_id"] == CLIENT_ID


def test_client_secret_post_puts_it_in_the_body_instead(discovery):
    request = grantor.exchange_code_request(
        discovery,
        auth=grantor.client_secret_post(CLIENT_ID, "s3cret"),
        code="the-code",
        redirect_uri="https://app.example.com/cb",
        code_verifier="ver",
    )
    assert request.auth is None
    assert request.data["client_secret"] == "s3cret"


def test_a_public_client_sends_no_secret_at_all(discovery):
    """PKCE is what protects it, which is why PKCE is not optional."""
    request = grantor.exchange_code_request(
        discovery,
        auth=grantor.public_client(CLIENT_ID),
        code="the-code",
        redirect_uri="https://app.example.com/cb",
        code_verifier="ver",
    )
    assert request.auth is None
    assert "client_secret" not in request.data
    assert request.data["client_id"] == CLIENT_ID


def test_the_exchange_carries_the_verifier_and_the_same_redirect_uri(discovery):
    request = grantor.exchange_code_request(
        discovery,
        auth=grantor.public_client(CLIENT_ID),
        code="the-code",
        redirect_uri="https://app.example.com/cb",
        code_verifier="ver",
    )
    assert request.data["grant_type"] == "authorization_code"
    assert request.data["code_verifier"] == "ver"
    assert request.data["redirect_uri"] == "https://app.example.com/cb"


def test_a_refresh_is_shaped_as_a_refresh(discovery):
    request = grantor.refresh_token_request(
        discovery, auth=grantor.public_client(CLIENT_ID), refresh_token="rt"
    )
    assert request.data["grant_type"] == "refresh_token"
    assert request.data["refresh_token"] == "rt"


def test_userinfo_is_a_bearer_call(discovery):
    request = grantor.userinfo_request(discovery, access_token="at")
    assert request.headers["Authorization"] == "Bearer at"


def test_userinfo_without_an_endpoint_says_which_one_is_missing(discovery_payload):
    del discovery_payload["userinfo_endpoint"]
    document = grantor.parse_discovery_document(
        discovery_payload, issuer=discovery_payload["issuer"]
    )
    with pytest.raises(DiscoveryError, match="userinfo_endpoint"):
        grantor.userinfo_request(document, access_token="at")


def test_sign_out_cannot_be_built_without_the_hint(discovery):
    """Omitting the hint is how sign-out silently stops working.

    Without it there is nothing proving which application is asking, so
    nothing to validate the post-logout redirect against — the browser is
    not redirected at all and lands on a confirmation screen. `client_id`
    does not substitute: anyone can name one, only the hint proves one. So
    it is a required argument, not an optional one.
    """
    with pytest.raises(TypeError):
        grantor.build_end_session_url(discovery)  # type: ignore[call-arg]


def test_sign_out_carries_the_hint_and_the_destination(discovery):
    url = grantor.build_end_session_url(
        discovery,
        id_token_hint="the-id-token",
        post_logout_redirect_uri="https://app.example.com/goodbye",
        state="st",
    )
    params = _params(url)
    assert params["id_token_hint"] == "the-id-token"
    assert params["post_logout_redirect_uri"] == "https://app.example.com/goodbye"
    assert params["state"] == "st"
