"""The way back in, and the two locks on it.

This product has an incident on record in which enforcing a second factor
locked out the only enrolled account. A library that ships no way back is
arranging for that again — and a way back that nobody tested is the same
thing with extra confidence.
"""

from __future__ import annotations

from io import StringIO

import pytest
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.urls import reverse

pytestmark = pytest.mark.django_db


@pytest.fixture
def locked_out_admin():
    """An account in the state this admin actually leaves them in.

    **No `is_staff`**, and no usable password. That is not an edge case: an
    admin installed as designed has no `ModelBackend`, creates its users
    with an unusable password, and sets `is_staff` from a Grantor role *at
    sign-in*. A deployment whose issuer is refusing everybody therefore has
    zero staff rows and zero usable passwords.

    This fixture used to pass `is_staff=True`, and that single keyword is
    why the whole break-glass suite passed against a command that could not
    open the door. Django's `AdminAuthenticationForm.confirm_login_allowed`
    rejects a non-staff user *before* the password is even considered.
    """
    User = get_user_model()
    user = User.objects.create(username="ada", email="ada@example.com")
    user.set_unusable_password()
    user.save()
    assert not user.is_staff, "the fixture must reproduce the real deployment"
    return user


def _run(*args, **kwargs):
    out = StringIO()
    call_command("grantor_break_glass", *args, stdout=out, **kwargs)
    return out.getvalue()


def _password_from(output: str) -> str:
    """The password the command printed — read the way an operator reads it."""
    for line in output.splitlines():
        if "password:" in line:
            return line.split("password:", 1)[1].strip()
    raise AssertionError(f"no password in output:\n{output}")


def test_it_refuses_without_the_acknowledgement(locked_out_admin):
    """One flag away from a local credential is too close."""
    with pytest.raises(CommandError, match="--i-understand"):
        _run("ada")
    locked_out_admin.refresh_from_db()
    assert not locked_out_admin.has_usable_password()


def test_it_refuses_an_account_that_does_not_exist():
    with pytest.raises(CommandError, match="no account matches"):
        _run("nobody@example.com", "--i-understand")


def test_the_account_can_be_named_by_email(locked_out_admin):
    output = _run("ada@example.com", "--i-understand")
    locked_out_admin.refresh_from_db()
    assert locked_out_admin.has_usable_password()
    assert "BREAK GLASS" in output


def test_the_password_alone_does_not_open_the_admin(client, locked_out_admin, issuer):
    """Two deliberate acts, so neither one alone opens the door.

    The command hands out a password; the setting decides whether any form
    will take one. With the setting off, the login view is still a redirect
    to the issuer and there is nothing to type a password into.
    """
    _run("ada", "--i-understand")
    response = client.get(reverse("admin:login"))

    assert response.status_code == 302
    assert response["Location"].startswith("https://acme.api.grantor.id/oauth/authorize?")


def test_with_both_in_place_there_is_a_form(client, locked_out_admin, settings, issuer):
    settings.GRANTOR_ADMIN_BREAK_GLASS = True
    _run("ada", "--i-understand")

    response = client.get(reverse("admin:login"))
    assert response.status_code == 200
    assert b'name="password"' in response.content


def test_break_glass_actually_opens_the_admin(client, locked_out_admin, settings, issuer):
    """The test this suite existed to have and did not.

    Everything else here checks that the command *ran*. This checks that
    somebody gets in — through the real form, with the password it printed,
    from the state a locked-out deployment is genuinely in.
    """
    settings.GRANTOR_ADMIN_BREAK_GLASS = True
    password = _password_from(_run("ada", "--i-understand"))

    response = client.post(
        reverse("admin:login"),
        {"username": "ada", "password": password, "next": reverse("admin:index")},
        follow=True,
    )

    assert response.status_code == 200
    assert client.session.get("_auth_user_id") == str(locked_out_admin.pk)


def test_closing_it_shuts_the_door_it_opened(client, locked_out_admin, settings, issuer):
    """`--close` has to undo the whole of what `--open` granted.

    Removing the password and leaving a staff row behind is not closing the
    glass — it leaves a standing admin account on a surface whose entire
    security argument is that no such account exists.
    """
    settings.GRANTOR_ADMIN_BREAK_GLASS = True
    password = _password_from(_run("ada", "--i-understand"))
    _run("ada", "--close")

    locked_out_admin.refresh_from_db()
    assert not locked_out_admin.has_usable_password()
    assert not locked_out_admin.is_staff

    response = client.post(reverse("admin:login"), {"username": "ada", "password": password})
    assert client.session.get("_auth_user_id") is None
    assert response.status_code == 200


def test_it_refuses_an_account_that_does_not_exist_and_says_what_to_do(db):
    """The case where nobody is left. Erroring is fine; erroring uselessly is not."""
    with pytest.raises(CommandError) as excinfo:
        _run("nobody@example.com", "--i-understand")
    assert "--create" in str(excinfo.value)


def test_create_provisions_one_when_there_is_nobody_left(client, db, settings, issuer):
    """Explicit, never implicit. Under duress, and still a deliberate act."""
    settings.GRANTOR_ADMIN_BREAK_GLASS = True
    password = _password_from(_run("ada@example.com", "--i-understand", "--create"))

    user = get_user_model().objects.get(email="ada@example.com")
    assert user.is_staff

    client.post(
        reverse("admin:login"),
        {"username": user.get_username(), "password": password},
        follow=True,
    )
    assert client.session.get("_auth_user_id") == str(user.pk)


def test_it_does_not_hand_out_superuser(locked_out_admin):
    """Staff is enough to reach the form, and the smaller thing to have created."""
    _run("ada", "--i-understand")
    locked_out_admin.refresh_from_db()
    assert locked_out_admin.is_staff
    assert not locked_out_admin.is_superuser


def test_closing_it_takes_the_password_away_again(locked_out_admin):
    """The step people forget, because by then it is working again."""
    _run("ada", "--i-understand")
    locked_out_admin.refresh_from_db()
    assert locked_out_admin.has_usable_password()

    output = _run("ada", "--close")
    locked_out_admin.refresh_from_db()
    assert not locked_out_admin.has_usable_password()
    assert "GRANTOR_ADMIN_BREAK_GLASS = False" in output


def test_it_says_what_to_check_in_the_audit_trail_afterwards(locked_out_admin):
    """A way back that leaves nobody able to say what happened is half a way back."""
    output = _run("ada", "--i-understand")

    assert "audit trail" in output
    assert "does NOT appear there" in output
    assert "--close" in output


def test_it_says_that_it_bypasses_the_role_check(locked_out_admin):
    """The command used to claim the opposite, and that was wrong.

    It said "the role check still applies: this gets you to the form, not
    past it" — describing a later obstacle as if it were a guard. Nothing
    about a break-glass sign-in consults the issuer. That is the point, and
    it is also the reason the window must be closed rather than left open
    once it is working; a sentence implying a residual guard is a reason not
    to hurry.
    """
    output = _run("ada", "--i-understand")
    assert "BYPASSES the Grantor role check" in output
    assert "closed" in output


def test_it_says_so_when_no_password_could_ever_work(locked_out_admin, settings):
    """A project following this admin's doctrine omits `ModelBackend`.

    And then the password this command prints cannot authenticate at all,
    however correct. Better said here than discovered at 3am.
    """
    settings.AUTHENTICATION_BACKENDS = ["grantor_django.backends.GrantorBackend"]
    output = _run("ada", "--i-understand")
    assert "ModelBackend is NOT installed" in output


def test_it_says_the_setting_is_not_an_environment_variable(locked_out_admin):
    """A real consumer set the env var, force-deployed, and nothing changed.

    Nothing in the project mapped it across, so the library still saw
    `False`. Projects will make that mistake by default.
    """
    output = _run("ada", "--i-understand")
    assert "not an environment variable" in output
    assert "env.bool" in output


def test_a_break_glass_password_used_anywhere_else_does_not_open_the_admin(
    client, locked_out_admin, settings, issuer
):
    """Two acts: the password *and* the setting. With the setting off, the
    password must not work through some other login the project has."""
    password = _password_from(_run("ada", "--i-understand"))
    assert client.login(username="ada", password=password)

    response = client.get(reverse("admin:index"))

    assert response.status_code == 302


def test_turning_the_setting_off_closes_sessions_it_opened(
    client, locked_out_admin, settings, issuer
):
    settings.GRANTOR_ADMIN_BREAK_GLASS = True
    password = _password_from(_run("ada", "--i-understand"))
    client.post(
        reverse("admin:login"),
        {"username": "ada", "password": password, "next": reverse("admin:index")},
    )
    assert client.get(reverse("admin:index")).status_code == 200

    settings.GRANTOR_ADMIN_BREAK_GLASS = False

    assert client.get(reverse("admin:index")).status_code == 302
