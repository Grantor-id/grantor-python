"""A row a consumer has deleted must not be able to sign in.

The bug: `find_by_subject` filters across a relation, and **a related-field
join reads the related table directly** — the related model's manager never
runs. So a `Profile` manager that excludes soft-deleted rows is bypassed,
and a deleted profile authenticates.

That is not a tidiness failure. It is "attach a person to the wrong
account", which is the single thing the `sub` rule exists to prevent.
"""

from __future__ import annotations

import pytest
from django.utils import timezone
from django_support import SUB
from djangoproject.models import Profile
from grantor_django.backends import GrantorBackend

pytestmark = pytest.mark.django_db


def _authenticate(sub=SUB, **claims):
    return GrantorBackend().authenticate(None, grantor_claims={"sub": sub, **claims})


@pytest.fixture
def scoped(settings):
    """The project states which rows are real, once."""
    settings.GRANTOR_USER_QUERYSET = "djangoproject.querysets.live_users"


def test_a_soft_deleted_profile_cannot_sign_in(local_user, scoped):
    Profile.all_objects.filter(user=local_user).update(grantor_sub=SUB, deleted_at=timezone.now())

    assert _authenticate() is None


def test_a_live_profile_still_can(local_user, scoped):
    """The guard must not have closed the door on everybody."""
    Profile.all_objects.filter(user=local_user).update(grantor_sub=SUB)

    assert _authenticate() == local_user


def test_a_deleted_row_does_not_leave_a_second_live_account_signing_in(
    local_user, scoped, django_user_model
):
    """The two-accounts-one-subject state, end to end.

    The conditional unique index is on **live** rows, so a deleted profile
    keeps its `sub` and the same subject can be linked to a new account.
    With the join reading past the manager, both then authenticate — and
    which one you get depends on row order, which is the worst possible
    answer to "who is this".
    """
    Profile.all_objects.filter(user=local_user).update(grantor_sub=SUB, deleted_at=timezone.now())
    replacement = django_user_model.objects.create_user(
        username="ana-again", email="ana@example.com", password="x"
    )
    Profile.objects.create(user=replacement, grantor_sub=SUB)

    assert _authenticate() == replacement


def test_the_email_fallback_will_not_link_a_deleted_profile(local_user, scoped):
    """The other lookup that crosses the relation, and the dangerous one.

    Linking here writes a `sub` onto a row, so bypassing the manager would
    not merely let somebody in — it would attach an identity to a record the
    project believes is gone.
    """
    Profile.all_objects.filter(user=local_user).update(deleted_at=timezone.now())

    assert _authenticate(email="ana@example.com", email_verified=True) is None, (
        "a deleted profile was linked to a live subject"
    )


def test_without_the_setting_the_default_is_unchanged(local_user):
    """A project that has no such manager is not made to configure one."""
    Profile.all_objects.filter(user=local_user).update(grantor_sub=SUB)

    assert _authenticate() == local_user


# ── The default, with nothing configured (AUTH-225) ───────────────────────
#
# Everything above configures `GRANTOR_USER_QUERYSET` first. That is what
# made the original fix look complete and left it inert: its default was
# `User._default_manager.all()`, which is exactly what the join already
# read, so a project that installed the fixed release and set nothing was
# still exposed — with a green suite, because no test ran without the
# setting.
#
# These run with **no** setting. They are the ones that fail if the safe
# default is ever reverted.


def test_by_default_a_soft_deleted_profile_cannot_sign_in(local_user):
    """No `GRANTOR_USER_QUERYSET`. The consumer configured nothing."""
    Profile.all_objects.filter(user=local_user).update(grantor_sub=SUB, deleted_at=timezone.now())

    assert _authenticate() is None


def test_by_default_a_live_profile_still_can(local_user):
    Profile.all_objects.filter(user=local_user).update(grantor_sub=SUB)

    assert _authenticate() == local_user


def test_by_default_the_email_bootstrap_will_not_claim_a_deleted_profile(local_user):
    """The other door into the same room.

    A deleted profile has no `sub`, so it looks unlinked — and the email
    bootstrap claims unlinked accounts. Without the manager, proving the
    address was enough to take over a deleted person's account.
    """
    local_user.email = "ada@example.com"
    local_user.save(update_fields=["email"])
    Profile.all_objects.filter(user=local_user).update(deleted_at=timezone.now())

    assert _authenticate(email="ada@example.com", email_verified=True) is None


def test_by_default_a_deleted_row_does_not_leave_a_second_live_account(
    local_user, django_user_model
):
    """Two accounts, one subject — the state the whole rule exists to stop.

    The deleted profile keeps its `sub`. A live account links the same
    subject. If the deleted row can still authenticate, one subject
    resolves to two people and which one you get is an ordering accident.
    """
    Profile.all_objects.filter(user=local_user).update(grantor_sub=SUB, deleted_at=timezone.now())
    successor = django_user_model.objects.create(username="successor")
    Profile.all_objects.create(user=successor, grantor_sub=SUB)

    assert _authenticate() == successor
