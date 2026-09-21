"""One opt-in test that talks to the real issuer.

Deselected by default (`addopts = -m 'not live'`), because a library whose
gate goes red when somebody else's host has a bad afternoon teaches its
maintainers to ignore the gate. Run it deliberately:

    just test-live

What it proves is small and cannot be proved any other way: that the issuer
is reachable, that its discovery document is shaped as this package expects,
and that the JWKS it points at exists and parses. Everything about
*behaviour* is proved offline against locally minted keys.
"""

from __future__ import annotations

import os

import grantor
import pytest

pytestmark = pytest.mark.live

ISSUER = os.environ.get("GRANTOR_LIVE_ISSUER", "https://api.grantor.id")


@pytest.fixture(autouse=True)
def _fresh():
    grantor.clear_caches()
    yield
    grantor.clear_caches()


def test_the_issuer_publishes_a_document_that_names_itself():
    """The issuer-mismatch check, run against the real thing.

    If this fails, either the deployment is serving someone else's document
    or this test is pointed at the wrong host. Both are worth finding out.
    """
    document = grantor.discover(ISSUER)
    assert document.issuer == ISSUER.rstrip("/")


def test_every_endpoint_this_library_needs_is_published():
    document = grantor.discover(ISSUER)
    assert document.authorization_endpoint
    assert document.token_endpoint
    assert document.jwks_uri
    assert document.end_session_endpoint, "RP-initiated logout is not advertised"
    assert document.userinfo_endpoint


def test_the_issuer_requires_pkce_with_s256():
    """OAuth 2.1. If this ever stops being advertised, the flow changed under us."""
    methods = grantor.discover(ISSUER).get("code_challenge_methods_supported") or []
    assert "S256" in methods


def test_the_advertised_signing_algorithms_survive_the_allowlist():
    document = grantor.discover(ISSUER)
    assert document.signing_algorithms, "the issuer advertises no algorithm we will verify with"


def test_the_jwks_exists_and_parses_into_usable_keys():
    document = grantor.discover(ISSUER)
    payload = grantor.fetch_jwks(document.jwks_uri)
    assert payload.get("keys"), "the JWKS carries no keys"
