"""What two real consumers found on their way in.

Each of these was invisible from inside the library and obvious from inside
a project using it — which is the argument for proving a library by
replacing code that exists rather than by writing a greenfield integration.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import pytest
from django.urls import reverse
from django_support import SUB
from djangoproject.models import Profile

pytestmark = pytest.mark.django_db


def _sign_in(client, issuer, **claims):
    start = client.get(reverse("grantor_django:start"))
    params = {k: v[0] for k, v in parse_qs(urlparse(start["Location"]).query).items()}
    issuer["echo_nonce"] = params["nonce"]
    issuer["claims"] = claims
    return client.get(reverse("grantor_django:callback"), {"code": "c", "state": params["state"]})


# --- (c) last_login ---------------------------------------------------------


def test_last_login_moves_even_when_the_project_keeps_its_own_session(
    client, issuer, local_user, settings
):
    """`login()` fires `user_logged_in`; a replacement hook does not.

    Nothing errors when a consumer supplies `GRANTOR_ESTABLISH_SESSION` —
    the column simply stops moving, and "when did this person last sign in"
    quietly becomes "when did they last use a password".
    """
    settings.GRANTOR_ESTABLISH_SESSION = "djangoproject.spa.establish"
    Profile.objects.filter(user=local_user).update(grantor_sub=SUB)
    assert local_user.last_login is None

    _sign_in(client, issuer)

    local_user.refresh_from_db()
    assert local_user.last_login is not None


# --- (d) the linking timestamp ---------------------------------------------


def test_linking_an_account_moves_its_updated_at(client, issuer, local_user):
    """`update_fields` makes Django skip `auto_now` columns.

    So the row that just acquired an identity was the one row with no
    record of when — on the single event most worth a timestamp.
    """
    before = Profile.objects.get(user=local_user).updated_at

    _sign_in(client, issuer, email="ana@example.com", email_verified=True)

    profile = Profile.objects.get(user=local_user)
    assert profile.grantor_sub == SUB
    assert profile.updated_at > before


# --- (h) the ID-token cookie ------------------------------------------------


def test_the_library_does_not_write_a_cookie_the_project_is_managing(
    client, issuer, local_user, settings
):
    """A project with its own session hook keeps its own cookies.

    Both writes used the same name, so whichever ran second won — and they
    disagreed about lifetime. Ordering is not a contract, and nothing tested
    it, which is what made this latent rather than merely fixed.
    """
    settings.GRANTOR_ESTABLISH_SESSION = "djangoproject.spa.establish"
    Profile.objects.filter(user=local_user).update(grantor_sub=SUB)

    response = _sign_in(client, issuer)

    assert "grantor_id_token" not in response.cookies


def test_it_still_writes_one_when_it_is_the_only_session_manager(client, issuer, local_user):
    Profile.objects.filter(user=local_user).update(grantor_sub=SUB)

    response = _sign_in(client, issuer)

    assert response.cookies["grantor_id_token"].value


# --- (i) SameSite as a setting ---------------------------------------------


def test_samesite_can_be_widened_for_a_front_end_on_another_origin(client, issuer, settings):
    """The library supports that shape, so it has to support its cookies."""
    settings.GRANTOR_COOKIE_SAMESITE = "None"

    client.get(reverse("grantor_django:start"))

    assert client.cookies["grantor_txn"]["samesite"] == "None"


def test_lax_is_still_the_default(client, issuer):
    """Right for nearly everybody, and required by the callback's redirect."""
    client.get(reverse("grantor_django:start"))
    assert client.cookies["grantor_txn"]["samesite"] == "Lax"


# --- the exported sign-in subset -------------------------------------------


def test_the_sign_in_subset_carries_its_own_namespace():
    """The namespace is load-bearing, so it must not be the consumer's job.

    `reverse("grantor_django:callback")` is what builds the redirect URI,
    the transaction cookie's path and the system check. A consumer who
    assembles their own subset and omits the namespace gets a silently
    wrong redirect URI, refused at the issuer for a reason nothing on their
    side explains.
    """
    from grantor_django.urls import app_name, sign_in_urls, urlpatterns

    patterns, namespace = sign_in_urls
    assert namespace == app_name == "grantor_django"
    assert [p.name for p in patterns] == ["start", "callback"]
    # And the full mount is the superset, so `include()` still publishes all
    # three — the subset is a choice, not a change.
    assert [p.name for p in urlpatterns] == ["start", "callback", "logout"]
