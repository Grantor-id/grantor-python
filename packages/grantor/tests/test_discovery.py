"""Discovery, and the refusal that is not a configuration nit."""

from __future__ import annotations

import grantor
import httpx
import pytest
from core_support import ISSUER
from grantor import DiscoveryError


def test_discovery_url_is_the_one_url_this_library_builds():
    assert grantor.discovery_url("https://acme.api.grantor.id/") == (
        "https://acme.api.grantor.id/.well-known/openid-configuration"
    )


def test_a_document_naming_another_issuer_is_refused(discovery_payload):
    """The attack, not a typo.

    Every endpoint below is about to be taken from this document. One that
    lies about whose it is can redirect a sign-in anywhere it likes, so it
    raises rather than warning — and the check is pure, so proving it needs
    no socket.
    """
    discovery_payload["issuer"] = "https://evil.example.com"
    with pytest.raises(DiscoveryError, match="different issuer"):
        grantor.parse_discovery_document(discovery_payload, issuer=ISSUER)


def test_a_trailing_slash_is_not_a_different_issuer(discovery_payload):
    discovery_payload["issuer"] = ISSUER + "/"
    document = grantor.parse_discovery_document(discovery_payload, issuer=ISSUER)
    assert document.issuer == ISSUER


@pytest.mark.parametrize("missing", ["authorization_endpoint", "token_endpoint", "jwks_uri"])
def test_a_document_without_an_endpoint_no_flow_can_start_without_is_refused(
    discovery_payload, missing
):
    del discovery_payload[missing]
    with pytest.raises(DiscoveryError, match=missing):
        grantor.parse_discovery_document(discovery_payload, issuer=ISSUER)


def test_an_optional_endpoint_may_be_absent(discovery_payload):
    """Absent is not broken.

    An issuer that publishes no end-session endpoint is unusual, not
    unusable — the flows that need one fail on their own terms, naming what
    was missing, rather than making discovery itself fail.
    """
    del discovery_payload["end_session_endpoint"]
    document = grantor.parse_discovery_document(discovery_payload, issuer=ISSUER)
    assert document.end_session_endpoint is None
    assert document.token_endpoint


def test_a_symmetric_algorithm_never_survives_the_allowlist(discovery_payload):
    """Algorithm confusion, closed at the source.

    If ``HS256`` reached the verifier's algorithm list, a token signed with
    the issuer's *public* key — which is published in the JWKS for anybody
    to fetch — would verify as an HMAC. Neither implementation this package
    was extracted from pinned this; both passed the advertised list through.
    """
    discovery_payload["id_token_signing_alg_values_supported"] = ["HS256", "none", "RS256"]
    document = grantor.parse_discovery_document(discovery_payload, issuer=ISSUER)
    assert document.signing_algorithms == ("RS256",)


def test_an_issuer_advertising_nothing_usable_still_gets_rs256(discovery_payload):
    discovery_payload["id_token_signing_alg_values_supported"] = ["HS256"]
    document = grantor.parse_discovery_document(discovery_payload, issuer=ISSUER)
    assert document.signing_algorithms == ("RS256",)


def test_the_raw_document_stays_reachable(discovery):
    """A dataclass that hid `scopes_supported` would send people back to curl."""
    assert "roles" in discovery.get("scopes_supported")


def test_discovery_is_fetched_once_and_then_cached(discovery_payload):
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json=discovery_payload)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    first = grantor.discover(ISSUER, client=client)
    second = grantor.discover(ISSUER, client=client)
    assert calls["n"] == 1
    assert first is second


def test_force_bypasses_the_cache(discovery_payload):
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json=discovery_payload)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    grantor.discover(ISSUER, client=client)
    grantor.discover(ISSUER, client=client, force=True)
    assert calls["n"] == 2


def test_two_issuers_do_not_evict_each_other(discovery_payload):
    """A process may legitimately face a per-organization issuer and the platform one."""
    other = "https://other.api.grantor.id"

    def handler(request: httpx.Request) -> httpx.Response:
        payload = dict(discovery_payload)
        if str(request.url).startswith(other):
            payload = {
                k: v.replace(ISSUER, other) if isinstance(v, str) else v for k, v in payload.items()
            }
        return httpx.Response(200, json=payload)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    assert grantor.discover(ISSUER, client=client).issuer == ISSUER
    assert grantor.discover(other, client=client).issuer == other
    assert grantor.discover(ISSUER, client=client).issuer == ISSUER


def test_a_non_json_body_is_a_discovery_error(discovery_payload):
    """The provider's edge is not the provider.

    An HTML page from something in front of the issuer is a failure to read
    as one, not a crash halfway through parsing.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>error code: 1010</html>")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(DiscoveryError, match="did not return JSON"):
        grantor.discover(ISSUER, client=client)


def test_a_transport_failure_names_no_url_or_body():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(DiscoveryError) as excinfo:
        grantor.discover(ISSUER, client=client)
    assert "ConnectError" in str(excinfo.value)


async def test_the_async_path_reads_the_same_document(discovery_payload):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=discovery_payload)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    document = await grantor.async_discover(ISSUER, client=client)
    assert document.token_endpoint == f"{ISSUER}/oauth/token"
