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
    User = get_user_model()
    user = User.objects.create(username="ada", email="ada@example.com", is_staff=True)
    user.set_unusable_password()
    user.save()
    return user


def _run(*args, **kwargs):
    out = StringIO()
    call_command("grantor_break_glass", *args, stdout=out, **kwargs)
    return out.getvalue()


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


def test_the_role_check_still_applies_behind_the_form(locked_out_admin):
    """It gets you to the form, not past the role.

    The command never grants a role and never touches the issuer, so a
    break-glass sign-in is still somebody who has to belong here.
    """
    output = _run("ada", "--i-understand")
    assert "role check still applies" in output
