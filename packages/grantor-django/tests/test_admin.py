"""An admin with no local password, and the ways in that it refuses."""

from __future__ import annotations

import itertools
import time
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
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


# --- only the admin's own sign-in opens the admin ----------------------------


def _staff(username=SUB):
    User = get_user_model()
    user = User.objects.create(username=username, is_staff=True, is_superuser=True)
    user.set_unusable_password()
    user.save()
    return user


def test_a_session_from_another_sign_in_does_not_open_the_admin(client, admin_issuer):
    """Staff flags are set by the admin sign-in from the role *at that
    moment*. A session that did not come through it — the application's
    own sign-in, say — has not had the role re-read, so it is sent to sign
    in rather than let in on flags that may be stale."""
    client.force_login(_staff())

    response = client.get(reverse("admin:index"))

    assert response.status_code == 302
    assert reverse("admin:login") in response["Location"]


def test_the_admin_sign_in_opens_it(client, admin_issuer):
    _sign_in(client, admin_issuer, ["superadmin"])
    assert client.get(reverse("admin:index")).status_code == 200


def test_signing_out_of_the_admin_is_not_a_get(client, admin_issuer):
    """A GET sign-out is a link anybody can put on any page.

    Django's own admin signs out with a POST form (4.2 and 5.x both), and
    the library's session sign-out is POST-only. The admin matches them.
    """
    _sign_in(client, admin_issuer, ["superadmin"])
    assert "_auth_user_id" in client.session

    response = client.get(reverse("admin:logout"))

    assert response.status_code == 405
    assert response["Allow"] == "POST"
    assert "_auth_user_id" in client.session


def test_the_admin_pages_sign_out_with_a_post_form(client, admin_issuer):
    """The template Django ships posts to the logout URL, so POST-only
    breaks nothing a signed-in admin can click."""
    _sign_in(client, admin_issuer, ["superadmin"])
    page = client.get(reverse("admin:index")).content.decode()
    assert f'method="post" action="{reverse("admin:logout")}"' in page


# --- the admin finds a person the way the session sign-in does (AUTH-326) ----
#
# The test project keeps `sub` on a `Profile`, through GRANTOR_SUBJECT_FIELD,
# and its username is something else entirely. That is the shape of the
# adopter that found this: the admin looked the person up by username == sub,
# found nobody, built a second row for somebody who already had one, and on a
# project whose username is a unique email, failed the insert with a 500.


def _person(username="ana", email="ana@example.com", sub=SUB):
    """Somebody who already has an account here, linked or not, and who has
    no local password: the shape every account the library makes has."""
    from djangoproject.models import Profile

    User = get_user_model()
    user = User.objects.create(username=username, email=email)
    user.set_unusable_password()
    user.save()
    Profile.objects.create(user=user, grantor_sub=sub)
    return user


def test_a_person_linked_through_the_subject_field_signs_in_as_themselves(client, admin_issuer):
    ana = _person()

    response, _ = _sign_in(client, admin_issuer, ["superadmin"])

    assert response.status_code == 302
    assert client.session.get("_auth_user_id") == str(ana.pk)
    assert get_user_model().objects.count() == 1
    ana.refresh_from_db()
    assert ana.is_staff and ana.is_superuser


def test_a_linked_person_whose_role_was_revoked_loses_the_admin(client, admin_issuer):
    """Revocation reaches the row the subject field names, not a stranger."""
    ana = _person()
    _sign_in(client, admin_issuer, ["superadmin"])
    client.logout()

    second, _ = _sign_in(client, admin_issuer, ["viewer"])

    assert second.status_code == 403
    ana.refresh_from_db()
    assert not ana.is_staff and not ana.is_superuser
    assert get_user_model().objects.count() == 1


def test_a_verified_email_links_an_unlinked_person_once(client, admin_issuer):
    """The same one-shot bootstrap the session sign-in uses."""
    ana = _person(sub="")

    response, _ = _sign_in(
        client, admin_issuer, ["superadmin"], email="ana@example.com", email_verified=True
    )

    assert response.status_code == 302
    assert client.session.get("_auth_user_id") == str(ana.pk)
    assert ana.profile.__class__.objects.get(user=ana).grantor_sub == SUB
    assert get_user_model().objects.count() == 1


def test_an_unverified_email_links_nobody(client, admin_issuer):
    ana = _person(sub="")

    _sign_in(client, admin_issuer, ["superadmin"], email="ana@example.com", email_verified=False)

    ana.refresh_from_db()
    assert not ana.is_staff
    assert ana.profile.__class__.objects.get(user=ana).grantor_sub == ""


def test_somebody_without_the_role_is_not_linked_by_email_either(client, admin_issuer):
    """A refusal leaves no trace, and a link is a trace."""
    ana = _person(sub="")

    response, _ = _sign_in(
        client, admin_issuer, ["viewer"], email="ana@example.com", email_verified=True
    )

    assert response.status_code == 403
    assert ana.profile.__class__.objects.get(user=ana).grantor_sub == ""


# The exact shape of the adopter that found this: `sub` on the user model
# itself, and the email as the username. `last_name` stands in for that
# project's `sub` column; it is the user model's own field, which is the
# point.


@pytest.fixture
def username_is_email(settings, monkeypatch):
    settings.GRANTOR_SUBJECT_FIELD = "last_name"
    monkeypatch.setattr(get_user_model(), "USERNAME_FIELD", "email")


def _staff_by_email(sub=""):
    User = get_user_model()
    user = User.objects.create(username="ana", email="ana@example.com", last_name=sub)
    user.set_unusable_password()
    user.save()
    return user


def test_where_the_username_is_the_email_a_linked_person_signs_in(
    client, admin_issuer, username_is_email
):
    ana = _staff_by_email(sub=SUB)

    response, _ = _sign_in(client, admin_issuer, ["superadmin"], email="ana@example.com")

    assert response.status_code == 302
    assert client.session.get("_auth_user_id") == str(ana.pk)
    assert get_user_model().objects.count() == 1


def test_where_the_username_is_the_email_it_is_never_rewritten_from_a_claim(
    client, admin_issuer, username_is_email
):
    """The issuer's address may differ; the username is who they are here."""
    ana = _staff_by_email(sub=SUB)

    _sign_in(client, admin_issuer, ["superadmin"], email="Ana@Elsewhere.example")

    ana.refresh_from_db()
    assert ana.email == "ana@example.com"


def test_where_the_username_is_the_email_a_new_person_gets_the_sub_in_its_field(
    client, admin_issuer, username_is_email
):
    response, _ = _sign_in(client, admin_issuer, ["superadmin"], email="bia@example.com")

    assert response.status_code == 302
    bia = get_user_model().objects.get(email="bia@example.com")
    assert bia.last_name == SUB
    assert bia.is_staff and not bia.has_usable_password()


def test_a_new_account_never_takes_a_username_somebody_already_holds(
    client, admin_issuer, username_is_email
):
    """A new row for an address that is already somebody's is not a new
    person. It is refused, not a 500, and the standing row is left exactly
    as it was."""
    ana = _staff_by_email()

    response, _ = _sign_in(client, admin_issuer, ["superadmin"], email="ana@example.com")

    assert response.status_code == 403
    assert get_user_model().objects.count() == 1
    ana.refresh_from_db()
    assert not ana.is_staff and ana.last_name == ""


# --- the session survives the next request (AUTH-330) -----------------------
#
# The callback logged the person in under ModelBackend by name. Django keeps
# that path in the session and, on the next request, refuses to load a user
# through a backend that is not in AUTHENTICATION_BACKENDS: the session reads
# as anonymous, the admin sends them to sign in, the issuer signs them in
# again, and the browser ends on "too many redirects". This module's own
# advice is to leave ModelBackend out, so following it produced the loop.


@pytest.mark.parametrize(
    "installed",
    [
        ["grantor_django.backends.GrantorBackend"],
        ["django.contrib.auth.backends.ModelBackend"],
        [
            "grantor_django.backends.GrantorBackend",
            "django.contrib.auth.backends.ModelBackend",
        ],
    ],
)
def test_the_admin_opens_after_sign_in_whatever_backends_are_installed(
    client, admin_issuer, settings, installed
):
    settings.AUTHENTICATION_BACKENDS = installed

    response, _ = _sign_in(client, admin_issuer, ["superadmin"])

    assert response.status_code == 302
    assert client.get(reverse("admin:index")).status_code == 200


def test_an_admin_with_no_backend_that_can_load_people_says_so(client, admin_issuer, settings):
    """Refused at the callback with the reason, rather than a redirect loop
    that names nothing."""
    settings.AUTHENTICATION_BACKENDS = ["djangoproject.nowhere.NoBackend"]

    with pytest.raises(ImproperlyConfigured, match="AUTHENTICATION_BACKENDS"):
        _sign_in(client, admin_issuer, ["superadmin"])
