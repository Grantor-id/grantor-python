"""Signing out, in the order that matters.

Local session first, issuer second. A failure at the issuer then still
leaves the person signed out here, which is the half this application is
answerable for.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import pytest
from django.urls import reverse
from django_support import SUB
from djangoproject.models import Profile

pytestmark = pytest.mark.django_db


def _sign_in(client, issuer, user):
    Profile.objects.filter(user=user).update(grantor_sub=SUB)
    start = client.get(reverse("grantor_django:start"))
    params = {k: v[0] for k, v in parse_qs(urlparse(start["Location"]).query).items()}
    issuer["echo_nonce"] = params["nonce"]
    client.get(reverse("grantor_django:callback"), {"code": "c", "state": params["state"]})


def test_signing_out_ends_the_issuer_session_too(client, issuer, local_user):
    """Somebody who signs out and is silently signed back in has been lied to."""
    _sign_in(client, issuer, local_user)
    assert "_auth_user_id" in client.session

    response = client.post(reverse("grantor_django:logout"))

    assert response.status_code == 302
    assert response["Location"].startswith("https://acme.api.grantor.id/oauth/logout?")
    assert "_auth_user_id" not in client.session


def test_the_hint_is_sent_so_the_issuer_can_validate_the_destination(client, issuer, local_user):
    """Without it the browser is not redirected at all.

    There is nothing proving which application is asking, so there is
    nothing to check the post-logout URI against, and the person lands on a
    confirmation screen on the issuer's host instead of coming home.
    """
    _sign_in(client, issuer, local_user)
    response = client.post(reverse("grantor_django:logout"))
    params = {k: v[0] for k, v in parse_qs(urlparse(response["Location"]).query).items()}

    assert params["id_token_hint"]
    assert params["post_logout_redirect_uri"] == "https://app.example.com/goodbye"


def test_the_id_token_is_kept_for_exactly_that_and_is_not_readable_from_the_page(
    client, issuer, local_user
):
    _sign_in(client, issuer, local_user)
    cookie = client.cookies["grantor_id_token"]
    assert cookie.value
    assert cookie["httponly"]
    assert cookie["samesite"] == "Lax"


def test_the_id_token_cookie_is_dropped_on_sign_out(client, issuer, local_user):
    _sign_in(client, issuer, local_user)
    response = client.post(reverse("grantor_django:logout"))
    assert response.cookies["grantor_id_token"].value == ""


def test_a_local_session_with_no_id_token_still_signs_out(client, issuer, local_user):
    """A session from before this library was installed is not a broken sign-out."""
    client.force_login(local_user)
    response = client.post(reverse("grantor_django:logout"))

    assert response["Location"] == "/"
    assert "_auth_user_id" not in client.session


def test_the_issuer_being_unreachable_does_not_keep_anybody_signed_in(
    client, issuer, local_user, monkeypatch
):
    """The whole reason for the order.

    Local first, issuer second, and the issuer failing is a redirect home
    rather than an error page belonging to somebody who is still logged in.
    """
    _sign_in(client, issuer, local_user)

    from grantor import DiscoveryError

    def explode(*args, **kwargs):
        raise DiscoveryError("issuer unreachable")

    monkeypatch.setattr("grantor_django.views.get_client", explode)
    response = client.post(reverse("grantor_django:logout"))

    assert response["Location"] == "/"
    assert "_auth_user_id" not in client.session


def test_sign_out_is_not_a_get(client, issuer, local_user):
    """A GET sign-out is a link anybody can put on any page.

    It would end this session *and* the issuer's, on somebody else's say-so.
    Django's own LogoutView made the same move for the same reason.
    """
    client.force_login(local_user)
    response = client.get(reverse("grantor_django:logout"))

    assert response.status_code == 405
    assert "_auth_user_id" in client.session
