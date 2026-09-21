"""The sign-in, the attacks on it, and the sign-out.

The happy path is one test. The rest are refusals, because a login view is
mostly a list of things it declines to do.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import pytest
from django.urls import reverse
from django_support import CLIENT_ID, SUB
from djangoproject.models import Profile

pytestmark = pytest.mark.django_db


def _authorize(client, issuer):
    """Follow the redirect to the issuer, as a browser would.

    The issuer echoes the `nonce` it was handed, so the fixture records it
    here — a test that wants a replayed nonce sets `claims["nonce"]` and
    overrides the echo.
    """
    response = client.get(reverse("grantor_django:start"))
    params = {k: v[0] for k, v in parse_qs(urlparse(response["Location"]).query).items()}
    issuer["echo_nonce"] = params.get("nonce", "")
    return response, params


def _callback(client, *, code="the-code", state=None, **extra):
    query = {"code": code, **extra}
    if state is not None:
        query["state"] = state
    return client.get(reverse("grantor_django:callback"), query)


def test_start_sends_the_browser_to_the_issuer_with_pkce(client, issuer):
    response, params = _authorize(client, issuer)
    assert response.status_code == 302
    assert response["Location"].startswith("https://acme.api.grantor.id/oauth/authorize?")
    assert params["code_challenge_method"] == "S256"
    assert params["client_id"] == CLIENT_ID
    assert params["response_type"] == "code"
    assert params["nonce"]


def test_the_redirect_uri_is_derived_from_the_urlconf_not_a_second_setting(client, issuer):
    """This project mounts the library at `identity/`, not `auth/`.

    A URI assembled from a hardcoded path would pass every other test in
    this file and fail in production against the registered redirect URI.
    """
    _, params = _authorize(client, issuer)
    assert params["redirect_uri"] == "https://app.example.com/identity/sso/callback"


def test_a_person_with_a_matching_sub_signs_in(client, issuer, local_user):
    Profile.objects.filter(user=local_user).update(grantor_sub=SUB)
    _, params = _authorize(client, issuer)
    response = _callback(client, state=params["state"])

    assert response.status_code == 302
    assert response["Location"] == "/"
    assert client.session.get("_auth_user_id") == str(local_user.pk)


def test_a_verified_email_links_an_unlinked_account_exactly_once(client, issuer, local_user):
    issuer["claims"] = {"email": "ana@example.com", "email_verified": True}
    _, params = _authorize(client, issuer)
    response = _callback(client, state=params["state"])

    assert response.status_code == 302
    profile = Profile.objects.get(user=local_user)
    assert profile.grantor_sub == SUB
    assert client.session.get("_auth_user_id") == str(local_user.pk)


def test_an_unverified_email_never_links(client, issuer, local_user):
    """**This test must never be deleted.**

    An unverified address is a claim, not an identity. Anybody who can type
    a string into an `email` field at some tenant could otherwise claim this
    person's account here. `email_verified` is per-tenant: it says they
    proved it to *this* tenant, which is the only assertion worth anything.
    """
    issuer["claims"] = {"email": "ana@example.com", "email_verified": False}
    _, params = _authorize(client, issuer)
    response = _callback(client, state=params["state"])

    assert response["Location"].endswith("grantor_error=account_not_found")
    assert Profile.objects.get(user=local_user).grantor_sub == ""
    assert "_auth_user_id" not in client.session


def test_a_truthy_but_not_true_email_verified_never_links(client, issuer, local_user):
    """`"false"` is truthy. So is `"no"`, and so is `0.0`'s string form.

    The check is `is True`, not a truth test, because the difference between
    the two is an account takeover.
    """
    issuer["claims"] = {"email": "ana@example.com", "email_verified": "false"}
    _, params = _authorize(client, issuer)
    response = _callback(client, state=params["state"])

    assert response["Location"].endswith("grantor_error=account_not_found")
    assert Profile.objects.get(user=local_user).grantor_sub == ""


def test_a_verified_email_cannot_steal_an_already_linked_account(client, issuer, local_user):
    """The fallback is for an unlinked account and no other kind."""
    Profile.objects.filter(user=local_user).update(grantor_sub="somebody-elses-sub")
    issuer["claims"] = {"email": "ana@example.com", "email_verified": True}
    _, params = _authorize(client, issuer)
    response = _callback(client, state=params["state"])

    assert response["Location"].endswith("grantor_error=account_not_found")
    assert Profile.objects.get(user=local_user).grantor_sub == "somebody-elses-sub"


def test_a_state_mismatch_is_refused(client, issuer, local_user):
    """The CSRF defence for the round trip."""
    Profile.objects.filter(user=local_user).update(grantor_sub=SUB)
    _authorize(client, issuer)
    response = _callback(client, state="not-the-state-we-sent")

    assert response["Location"].endswith("grantor_error=expired")
    assert "_auth_user_id" not in client.session


def test_a_callback_with_no_transaction_at_all_is_refused(client, issuer):
    response = _callback(client, state="anything")
    assert response["Location"].endswith("grantor_error=expired")


def test_a_tampered_transaction_cookie_is_refused(client, issuer):
    _, params = _authorize(client, issuer)
    client.cookies["grantor_txn"] = "forged:value"
    response = _callback(client, state=params["state"])
    assert response["Location"].endswith("grantor_error=expired")


def test_a_replayed_code_is_refused(client, issuer, local_user, caplog):
    """Codes are single-use, and presenting one twice revokes its tokens.

    The person gets one stable word — a front end has to render copy for
    whatever lands in that URL, and the issuer's vocabulary is unbounded.
    The issuer's actual code goes to the log, where the operator is.
    """
    Profile.objects.filter(user=local_user).update(grantor_sub=SUB)
    _, first = _authorize(client, issuer)
    _callback(client, state=first["state"])

    client.logout()
    _, second = _authorize(client, issuer)
    with caplog.at_level("WARNING", logger="grantor_django"):
        response = _callback(client, state=second["state"])

    assert response["Location"].endswith("grantor_error=exchange_failed")
    assert "invalid_grant" in caplog.text
    assert "_auth_user_id" not in client.session


def test_a_failed_nonce_is_refused(client, issuer, local_user):
    """A valid token that answers a question nobody asked."""
    Profile.objects.filter(user=local_user).update(grantor_sub=SUB)
    issuer["claims"] = {"nonce": "from-an-older-flow"}
    _, params = _authorize(client, issuer)
    response = _callback(client, state=params["state"])

    assert response["Location"].endswith("grantor_error=issuer_error")
    assert "_auth_user_id" not in client.session


def test_a_person_who_declines_consent_is_told_so_and_nothing_else(client, issuer):
    _, params = _authorize(client, issuer)
    response = client.get(
        reverse("grantor_django:callback"), {"error": "access_denied", "state": params["state"]}
    )
    assert response["Location"].endswith("grantor_error=denied")


def test_the_transaction_cookie_is_deleted_on_every_exit(client, issuer, local_user):
    """Single-use, including — especially — on failure."""
    _, params = _authorize(client, issuer)
    assert client.cookies["grantor_txn"].value

    response = _callback(client, state="wrong")
    assert response.cookies["grantor_txn"].value == ""


def test_userinfo_fills_in_an_email_the_id_token_did_not_carry(client, issuer, local_user):
    issuer["claims"] = {}
    issuer["userinfo"] = {"sub": SUB, "email": "ana@example.com", "email_verified": True}
    _, params = _authorize(client, issuer)
    response = _callback(client, state=params["state"])

    assert response.status_code == 302
    assert Profile.objects.get(user=local_user).grantor_sub == SUB


def test_the_verified_id_token_wins_over_userinfo_on_overlap(client, issuer, local_user):
    """Userinfo is unsigned. Where the two disagree, the signature decides."""
    issuer["claims"] = {"email": "ana@example.com", "email_verified": True}
    issuer["userinfo"] = {"sub": "someone-else", "email": "attacker@example.com"}
    _, params = _authorize(client, issuer)
    _callback(client, state=params["state"])

    assert Profile.objects.get(user=local_user).grantor_sub == SUB
