"""Both error envelopes — the single most valuable thing in this package.

Of the two hand-rolled implementations this was extracted from, one
normalized both shapes and one understood only the RFC shape. The two
refusals the second could not parse are exactly the two a new integration
meets first: a bad ``redirect_uri`` at ``/oauth/authorize`` and a
``post_logout_redirect_uri`` that is not on the client's second list.
"""

from __future__ import annotations

import httpx
import pytest
from grantor import ProtocolError, normalize_error, parse_error, parse_redirect_error


def test_the_rfc_shape_normalizes_to_its_code():
    """`{"error": "...", "error_description": "..."}` — token, revocation, userinfo, redirects."""
    payload = {"error": "invalid_grant", "error_description": "code already used"}
    assert normalize_error(payload, status=400) == "invalid_grant"


def test_the_management_envelope_normalizes_to_the_same_kind_of_code():
    """`{"error": {"code": ..., "message": ...}}` — a direct refusal, no redirect.

    This is what `/oauth/authorize` and `/oauth/logout` answer when the
    request named a destination the issuer could not verify. Both mean an
    address failed exact-match validation, so both must reduce to a code a
    caller can match on.
    """
    payload = {"error": {"code": "invalid_redirect_uri", "message": "not registered"}}
    assert normalize_error(payload, status=400) == "invalid_redirect_uri"


def test_a_body_that_is_neither_shape_degrades_rather_than_raising():
    """A parser for error bodies that can itself fail replaces the issuer's diagnosis."""
    assert normalize_error({"detail": "something"}, status=503) == "http_503"
    assert normalize_error("not even an object", status=502) == "http_502"
    assert normalize_error({"error": {}}, status=400) == "http_400"


def test_a_non_json_response_degrades_to_its_status():
    """The provider's edge is not the provider.

    An HTML page from an intermediary in front of the issuer is not a
    refusal by the issuer, and pretending to have parsed one would be worse
    than saying what actually arrived.
    """
    response = httpx.Response(403, text="<html>error code: 1010</html>")
    assert parse_error(response) == "http_403"


def test_parse_error_reads_a_real_response_of_each_shape():
    rfc = httpx.Response(400, json={"error": "invalid_scope"})
    management = httpx.Response(400, json={"error": {"code": "client-id-mismatch"}})
    assert parse_error(rfc) == "invalid_scope"
    assert parse_error(management) == "client-id-mismatch"


def test_an_error_travelling_back_on_a_redirect_is_read_from_the_query():
    assert parse_redirect_error({"error": "access_denied", "state": "abc"}) == "access_denied"


def test_a_clean_callback_carries_no_error():
    """So a callback view can ask first, instead of deciding what absence means."""
    assert parse_redirect_error({"code": "xyz", "state": "abc"}) is None
    assert parse_redirect_error({"error": ""}) is None


def test_a_protocol_error_says_only_the_code():
    error = ProtocolError("invalid_grant", status=400)
    assert str(error) == "invalid_grant"
    assert error.code == "invalid_grant"
    assert error.status == 400


def test_the_description_is_never_surfaced():
    """Descriptions are free text from the issuer and reach logs.

    The code is the part a caller matches on; the description is the part
    that could one day quote the request it refused.
    """
    payload = {"error": "invalid_grant", "error_description": "code sk_live_abc already used"}
    assert "sk_live_abc" not in normalize_error(payload, status=400)


@pytest.mark.parametrize("status", [400, 401, 403, 500])
def test_every_status_has_a_readable_fallback(status):
    assert normalize_error(None, status=status) == f"http_{status}"
