"""The system check, the `?next=` guard, and where `sub` is allowed to live."""

from __future__ import annotations

import pytest
from django.core.checks import run_checks
from django.test import RequestFactory
from django.urls import reverse
from grantor_django import conf
from grantor_django.views import safe_next

pytestmark = pytest.mark.django_db


def _grantor_errors():
    return [e for e in run_checks() if str(e.id).startswith("grantor_django.")]


def test_a_correct_configuration_raises_nothing():
    assert _grantor_errors() == []


@pytest.mark.parametrize(
    "name", [*conf.REQUIRED_SETTINGS, *conf.SESSION_LOGIN_SETTINGS, "GRANTOR_AUDIENCE"]
)
def test_a_missing_required_setting_fails_at_boot(settings, name):
    """Not at the first sign-in, when the person looking cannot fix it.

    This project mounts the session views *and* configures the resource
    server, so all of these apply to it.
    """
    setattr(settings, name, "")
    messages = [e.msg for e in _grantor_errors()]
    assert any(name in m for m in messages)


def test_a_project_without_the_session_views_is_not_asked_for_a_callback(settings):
    """A resource server has no callback of its own, and no client id either.

    Demanding them would refuse to boot a consumer that is using this
    library entirely correctly — which is exactly the shape of the first
    application it was extracted from.
    """
    settings.ROOT_URLCONF = "djangoproject.urls_api_only"
    settings.GRANTOR_CLIENT_ID = ""
    settings.GRANTOR_CALLBACK_BASE_URL = ""

    messages = [e.msg for e in _grantor_errors()]
    assert not any("GRANTOR_CLIENT_ID" in m or "GRANTOR_CALLBACK_BASE_URL" in m for m in messages)


def test_that_project_is_still_asked_for_an_audience(settings):
    """What it does need, it is still asked for."""
    settings.ROOT_URLCONF = "djangoproject.urls_api_only"
    settings.GRANTOR_AUDIENCE = ""

    assert any("GRANTOR_AUDIENCE" in e.msg for e in _grantor_errors())


def test_an_http_issuer_is_refused(settings):
    """It would carry an authorization code and a client secret in the clear."""
    settings.GRANTOR_ISSUER = "http://acme.api.grantor.id"
    assert any("https" in e.msg for e in _grantor_errors())


def test_a_relative_callback_base_is_refused(settings):
    """It is what the issuer redirects a browser to, so it has to be absolute."""
    settings.GRANTOR_CALLBACK_BASE_URL = "/app"
    assert any("absolute" in e.msg for e in _grantor_errors())


def test_an_unknown_auth_method_is_refused(settings):
    settings.GRANTOR_AUTH_METHOD = "private_key_jwt"
    assert any("GRANTOR_AUTH_METHOD" in e.msg for e in _grantor_errors())


def test_every_problem_is_reported_at_once(settings):
    """One restart per mistake is a slow way to fix three mistakes."""
    settings.GRANTOR_ISSUER = "http://nope"
    settings.GRANTOR_CLIENT_ID = ""
    settings.GRANTOR_AUTH_METHOD = "nonsense"
    assert len(_grantor_errors()) >= 3


@pytest.mark.parametrize(
    "hostile",
    [
        "https://evil.example.com/phish",
        "//evil.example.com/phish",
        "http://evil.example.com",
        "https://testserver.evil.example.com/",
        "javascript:alert(1)",
    ],
)
def test_an_off_site_next_is_never_honoured(hostile):
    """An open redirect on a login endpoint is phishing hosted on your own domain.

    The URL the person checks before clicking is genuinely yours, right up
    to the moment it is not.
    """
    request = RequestFactory().get("/identity/sso/start")
    assert safe_next(request, hostile, "/") == "/"


@pytest.mark.parametrize("allowed", ["/dashboard", "/reports?range=30d", "/a/b/c"])
def test_an_on_site_next_is_honoured(allowed):
    request = RequestFactory().get("/identity/sso/start")
    assert safe_next(request, allowed, "/") == allowed


def test_the_next_destination_survives_the_round_trip(client, issuer, local_user):
    from urllib.parse import parse_qs, urlparse

    from djangoproject.models import Profile

    Profile.objects.filter(user=local_user).update(
        grantor_sub="0d9b1a7e-1a62-4a0e-9b7a-1f0f2c3d4e5f"
    )
    start = client.get(reverse("grantor_django:start"), {"next": "/dashboard"})
    params = {k: v[0] for k, v in parse_qs(urlparse(start["Location"]).query).items()}
    issuer["echo_nonce"] = params["nonce"]

    response = client.get(
        reverse("grantor_django:callback"), {"code": "c", "state": params["state"]}
    )
    assert response["Location"] == "/dashboard"


def test_sub_is_read_from_the_model_the_project_owns(settings):
    """A library that demanded its own user table could not be adopted incrementally."""
    assert conf.subject_field() == ("profile", "grantor_sub")
    settings.GRANTOR_SUBJECT_FIELD = "grantor_sub"
    assert conf.subject_field() == (None, "grantor_sub")


def test_the_transaction_cookie_is_lax_and_not_strict(client, issuer):
    """Strict would strip it on the issuer's redirect and fail every sign-in.

    It would also fail in a way that looks like an expired transaction,
    which is the wrong thing to be told.
    """
    client.get(reverse("grantor_django:start"))
    cookie = client.cookies["grantor_txn"]
    assert cookie["samesite"] == "Lax"
    assert cookie["httponly"]


def test_a_dark_deploy_boots_without_any_grantor_configuration(settings):
    """Deploy the code first, turn it on later.

    A project rolling this out behind a flag has the app installed and the
    URLs mounted before any client id exists. Refusing to boot until one
    does would make the dark deploy impossible, which is the whole point of
    a dark deploy.
    """
    settings.GRANTOR_ENABLED = False
    settings.GRANTOR_CLIENT_ID = ""
    settings.GRANTOR_ISSUER = ""

    assert _grantor_errors() == []


def test_a_half_finished_rollout_still_hears_about_a_malformed_value(settings):
    """Not required is not the same as not checked."""
    settings.GRANTOR_ENABLED = False
    settings.GRANTOR_ISSUER = "http://acme.api.grantor.id"

    assert any("https" in e.msg for e in _grantor_errors())


def test_every_route_is_absent_while_it_is_off(client, settings):
    """404, not 500 — a route that is not enabled does not exist yet.

    **All three**, sign-out included. It is the one of them that can do
    something irreversible: a live `/sso/logout` under a flag that is
    supposed to be off reaches the real issuer and ends a real session.
    A switch that two of three routes honour is not a switch.
    """
    settings.GRANTOR_ENABLED = False

    assert client.get(reverse("grantor_django:start")).status_code == 404
    assert client.get(reverse("grantor_django:callback")).status_code == 404
    assert client.post(reverse("grantor_django:logout")).status_code == 404


def test_sign_out_still_works_when_it_is_on(client, issuer, local_user, settings):
    """The guard must not have closed the door on the working case."""
    settings.GRANTOR_ENABLED = True
    client.force_login(local_user)

    response = client.post(reverse("grantor_django:logout"))

    assert response.status_code == 302
    assert "_auth_user_id" not in client.session


def test_the_transaction_cookie_is_scoped_to_where_the_views_are_mounted(client, issuer):
    """It carries a PKCE verifier. It has no business on every request.

    This project mounts the library at `identity/`, so the cookie belongs
    to `/identity/sso` — derived from the URLconf rather than configured,
    and rather than left at `/`.
    """
    client.get(reverse("grantor_django:start"))
    assert client.cookies["grantor_txn"]["path"] == "/identity/sso"


def test_the_destination_parameter_can_be_renamed(client, issuer, settings, local_user):
    """An adopter's front end already builds this URL."""
    from urllib.parse import parse_qs, urlparse

    settings.GRANTOR_NEXT_PARAM = "redirectTo"
    start = client.get(reverse("grantor_django:start"), {"redirectTo": "/inbox"})
    params = {k: v[0] for k, v in parse_qs(urlparse(start["Location"]).query).items()}
    issuer["echo_nonce"] = params["nonce"]

    from djangoproject.models import Profile

    Profile.objects.filter(user=local_user).update(
        grantor_sub="0d9b1a7e-1a62-4a0e-9b7a-1f0f2c3d4e5f"
    )
    response = client.get(
        reverse("grantor_django:callback"), {"code": "c", "state": params["state"]}
    )
    assert response["Location"] == "/inbox"
