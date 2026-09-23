"""An admin with no local password, and the ways in that it refuses."""

from __future__ import annotations

import itertools
import time
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
from django.contrib.auth import get_user_model
from django.urls import reverse
from django_support import ISSUER, KID, SUB

ADMIN_CLIENT_ID = "acme-admin"

pytestmark = pytest.mark.django_db


@pytest.fixture
def admin_issuer(issuer, keypair):
    """The scripted issuer, answering for the admin's own client.

    A separate client id, and therefore a separate audience — sharing one
    between the admin and the application would make a token for the
    application a token for the admin.
    """
    private, _ = keypair

    def mint(roles, **claims):
        now = int(time.time())
        payload = {
            "iss": ISSUER,
            "sub": SUB,
            "aud": ADMIN_CLIENT_ID,
            "iat": now,
            "exp": now + 300,
            "nonce": issuer["echo_nonce"],
            "roles": roles,
            **claims,
        }
        return jwt.encode(payload, private, algorithm="RS256", headers={"kid": KID})

    issuer["mint_admin"] = mint
    return issuer


_codes = itertools.count()


def _sign_in(client, admin_issuer, roles, **claims):
    """One sign-in, with a code nobody has used.

    A fresh code per call because the scripted issuer enforces single use,
    as the real one does — a test that reused one would be testing the
    replay defence by accident and failing for the wrong reason.
    """
    start = client.get(reverse("admin:login"))
    params = {k: v[0] for k, v in parse_qs(urlparse(start["Location"]).query).items()}
    admin_issuer["echo_nonce"] = params["nonce"]
    admin_issuer["claims"] = {"roles": roles, "aud": ADMIN_CLIENT_ID, **claims}
    return client.get(
        reverse("admin:grantor_callback"),
        {"code": f"code-{next(_codes)}", "state": params["state"]},
    ), params


def test_the_login_view_redirects_to_the_issuer_and_renders_no_form(client, admin_issuer):
    """The form is replaced, not hidden. A hidden form is a form someone finds."""
    response = client.get(reverse("admin:login"))

    assert response.status_code == 302
    assert response["Location"].startswith("https://acme.api.grantor.id/oauth/authorize?")
    assert b"password" not in response.content


def test_the_admin_asks_for_the_roles_scope(client, admin_issuer):
    """It is what says whether this person may be here at all."""
    response = client.get(reverse("admin:login"))
    params = {k: v[0] for k, v in parse_qs(urlparse(response["Location"]).query).items()}

    assert "roles" in params["scope"].split()
    assert params["client_id"] == ADMIN_CLIENT_ID
    assert params["code_challenge_method"] == "S256"


def test_somebody_with_the_role_gets_in(client, admin_issuer):
    response, _ = _sign_in(client, admin_issuer, ["superadmin"])

    assert response.status_code == 302
    user = get_user_model().objects.get(username=SUB)
    assert user.is_staff and user.is_superuser
    assert client.session.get("_auth_user_id") == str(user.pk)


def test_an_admin_user_has_no_usable_password_even_in_principle(client, admin_issuer):
    _sign_in(client, admin_issuer, ["superadmin"])
    assert not get_user_model().objects.get(username=SUB).has_usable_password()


def test_somebody_without_the_role_is_refused_not_shown_a_blank_admin(client, admin_issuer):
    """A refusal, not an empty admin — and not a record either.

    Where the flags of an account that *already* exists get corrected on the
    way out, see `test_a_standing_account_still_has_its_flags_corrected`.
    """
    response, _ = _sign_in(client, admin_issuer, ["billing"])

    assert response.status_code == 403
    assert "_auth_user_id" not in client.session
    assert not get_user_model().objects.filter(username=SUB).exists()


def test_a_revoked_role_takes_effect_on_the_next_sign_in(client, admin_issuer):
    """The whole argument for re-reading it every time.

    Revoking at the issuer takes effect the next time they authenticate,
    rather than whenever somebody remembers to untick a box here.
    """
    _sign_in(client, admin_issuer, ["superadmin"])
    user = get_user_model().objects.get(username=SUB)
    assert user.is_superuser

    client.logout()
    second, _ = _sign_in(client, admin_issuer, [])

    assert second.status_code == 403
    user.refresh_from_db()
    assert not user.is_staff
    assert not user.is_superuser


def test_a_state_mismatch_is_refused(client, admin_issuer):
    client.get(reverse("admin:login"))
    response = client.get(reverse("admin:grantor_callback"), {"code": "c", "state": "not-ours"})
    assert response.status_code == 403


def test_a_callback_with_no_transaction_is_refused(client, admin_issuer):
    response = client.get(reverse("admin:grantor_callback"), {"code": "c", "state": "x"})
    assert response.status_code == 403


def test_the_issuers_own_refusal_is_surfaced_not_retried(client, admin_issuer):
    """A retry loop against a refusal is a redirect that never settles."""
    client.get(reverse("admin:login"))
    response = client.get(reverse("admin:grantor_callback"), {"error": "access_denied"})
    assert response.status_code == 403


def test_signing_out_of_the_admin_ends_the_issuer_session_too(client, admin_issuer):
    """On this surface a session believed closed is a privileged one."""
    _sign_in(client, admin_issuer, ["superadmin"])
    assert "_auth_user_id" in client.session

    response = client.post(reverse("admin:logout"))

    assert response["Location"].startswith("https://acme.api.grantor.id/oauth/logout?")
    params = {k: v[0] for k, v in parse_qs(urlparse(response["Location"]).query).items()}
    assert params["id_token_hint"]
    assert "_auth_user_id" not in client.session


def test_somebody_who_never_had_the_role_leaves_no_record_behind(client, admin_issuer):
    """A refusal must not populate the user table.

    Otherwise anybody who can reach the issuer can create rows here, and a
    row in a table called `user` on an admin surface reads like an account
    whether or not its flags say so.
    """
    response, _ = _sign_in(client, admin_issuer, ["viewer"])

    assert response.status_code == 403
    assert get_user_model().objects.count() == 0


def test_a_standing_account_still_has_its_flags_corrected(client, admin_issuer):
    """The other half: an existing record is told the truth even on a refusal.

    Never creating and never updating are different rules, and only the
    first one is right.
    """
    _sign_in(client, admin_issuer, ["superadmin"])
    assert get_user_model().objects.get(username=SUB).is_superuser

    client.logout()
    _sign_in(client, admin_issuer, ["viewer"])

    user = get_user_model().objects.get(username=SUB)
    assert not user.is_staff
    assert not user.is_superuser


def test_a_refusal_at_the_token_endpoint_is_logged_not_just_raised(client, admin_issuer, caplog):
    """A bare 403 page is correct for a browser and useless for an operator.

    Django renders PermissionDenied with no detail at all, so without this
    line an admin that has stopped letting people in leaves nothing behind
    saying why. The normalized code is safe to log and is the diagnosis.
    """
    admin_issuer["token_status"] = 400
    admin_issuer["token_body"] = {"error": {"code": "invalid_redirect_uri"}}

    with caplog.at_level("WARNING", logger="grantor_django.admin"):
        response, _ = _sign_in(client, admin_issuer, ["superadmin"])

    assert response.status_code == 403
    assert "invalid_redirect_uri" in caplog.text


@pytest.mark.parametrize(
    "hostile",
    ["https://evil.example.com/x", "//evil.example.com", "/\\evil.example.com", "http://evil"],
)
def test_the_admin_sign_in_is_not_an_open_redirect(client, admin_issuer, hostile):
    """`?next=` sends the browser somewhere **after a successful sign-in**.

    That is the moment a person is most likely to trust what they are
    looking at, on the most privileged surface the product has. The session
    views already guarded this; the admin path did not.
    """
    start = client.get(f"{reverse('admin:login')}?next={hostile}")
    params = {k: v[0] for k, v in parse_qs(urlparse(start["Location"]).query).items()}
    admin_issuer["echo_nonce"] = params["nonce"]
    admin_issuer["claims"] = {"roles": ["superadmin"], "aud": ADMIN_CLIENT_ID}

    response = client.get(
        reverse("admin:grantor_callback"),
        {"code": f"code-{next(_codes)}", "state": params["state"]},
    )

    assert response.status_code == 302
    assert "evil.example.com" not in response["Location"]
    assert "evil" not in response["Location"]


def test_an_on_site_next_still_works(client, admin_issuer):
    """The guard must not have closed the door on the working case."""
    start = client.get(f"{reverse('admin:login')}?next=/admin/auth/user/")
    params = {k: v[0] for k, v in parse_qs(urlparse(start["Location"]).query).items()}
    admin_issuer["echo_nonce"] = params["nonce"]
    admin_issuer["claims"] = {"roles": ["superadmin"], "aud": ADMIN_CLIENT_ID}

    response = client.get(
        reverse("admin:grantor_callback"),
        {"code": f"code-{next(_codes)}", "state": params["state"]},
    )

    assert response["Location"] == "/admin/auth/user/"


def test_an_account_with_its_own_password_is_not_taken_over_by_admin_sign_in(client, admin_issuer):
    """The admin only ever manages accounts it created: those have no usable
    password. A row that has one was made by some other path, and granting
    it staff rights would give that password the admin as well."""
    local = get_user_model().objects.create_user(username=SUB, password="a local password 1")

    response, _ = _sign_in(client, admin_issuer, ["superadmin"])

    assert response.status_code == 403
    local.refresh_from_db()
    assert not local.is_staff
    assert not local.is_superuser
    assert local.check_password("a local password 1")
