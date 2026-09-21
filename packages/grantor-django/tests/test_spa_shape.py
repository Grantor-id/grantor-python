"""The other shape a Django project comes in.

A browser application on its own origin, a Django API behind it, and a
session that is not Django's — a JWT cookie pair, typically. That is not an
exotic deployment; it is roughly half of them, and a library that could only
serve same-origin Django sessions could not be adopted by the second
consumer this phase exists for.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import pytest
from django.urls import reverse
from django_support import SUB
from djangoproject.models import Profile
from grantor_django.views import relative_path_only

pytestmark = pytest.mark.django_db

UI = "https://app.example.com"


@pytest.fixture
def spa(settings):
    settings.GRANTOR_FRONTEND_BASE_URL = UI
    settings.GRANTOR_ERROR_REDIRECT_URL = "/login"
    settings.GRANTOR_ERROR_PARAM = "sso_error"
    settings.GRANTOR_ESTABLISH_SESSION = "djangoproject.spa.establish"
    return settings


def _sign_in(client, issuer, next_url=None):
    query = {"next": next_url} if next_url else {}
    start = client.get(reverse("grantor_django:start"), query)
    params = {k: v[0] for k, v in parse_qs(urlparse(start["Location"]).query).items()}
    issuer["echo_nonce"] = params["nonce"]
    return client.get(reverse("grantor_django:callback"), {"code": "c", "state": params["state"]})


def test_a_sign_in_lands_on_the_browser_application(client, issuer, spa, local_user):
    Profile.objects.filter(user=local_user).update(grantor_sub=SUB)
    response = _sign_in(client, issuer, "/dashboard")

    assert response["Location"] == f"{UI}/dashboard"


def test_the_project_keeps_its_own_session_scheme(client, issuer, spa, local_user):
    """Django's session is never touched; this project's cookies are set instead."""
    Profile.objects.filter(user=local_user).update(grantor_sub=SUB)
    response = _sign_in(client, issuer)

    assert "_auth_user_id" not in client.session
    assert response.cookies["djangoproject_access"].value.startswith("access-for-")
    assert response.cookies["djangoproject_access"]["httponly"]


def test_the_hook_is_handed_the_issuers_tokens_too(client, issuer, spa, local_user):
    """So a project can keep whichever of them it needs — the ID token, usually."""
    Profile.objects.filter(user=local_user).update(grantor_sub=SUB)
    response = _sign_in(client, issuer)

    assert response.cookies["djangoproject_saw_id_token"].value == "yes"


def test_a_failure_uses_the_name_this_projects_front_end_already_reads(client, issuer, spa):
    response = _sign_in(client, issuer)
    assert response["Location"] == f"{UI}/login?sso_error=account_not_found"


@pytest.mark.parametrize(
    "hostile",
    ["https://evil.example.com/x", "//evil.example.com", "http://evil", "evil.example.com"],
)
def test_next_can_never_name_a_host_at_all(client, issuer, spa, local_user, hostile):
    """A narrower promise than "same host", not a looser one.

    With a frontend base configured, `next` contributes a path and nothing
    else — there is no value it can take that reaches another origin.
    """
    Profile.objects.filter(user=local_user).update(grantor_sub=SUB)
    response = _sign_in(client, issuer, hostile)

    assert response["Location"].startswith(f"{UI}/")
    assert "evil.example.com" not in response["Location"]


def test_a_backslash_is_not_a_safe_path():
    """Browsers normalize `\\` to `/`, so checking only for `//` misses this."""
    assert relative_path_only("/\\evil.example.com", "/") == "/"
    assert relative_path_only("//evil.example.com", "/") == "/"
    assert relative_path_only("/fine", "/") == "/fine"
