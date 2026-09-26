"""``NULL`` means "not linked yet" as surely as ``""`` does (AUTH-232).

The bootstrap found its unlinked candidate with ``filter(<field>="")``. In
SQL ``= ''`` never matches ``NULL``, so on a project whose subject column is
``null=True`` the verified-email bootstrap matched nobody, and a real
person's **first** sign-in was refused with ``account_not_found``.

Everything worked the moment a ``sub`` existed, which is why a test that
seeds one could never have caught it. These tests seed none.
"""

from __future__ import annotations

import pytest
from django_support import SUB
from djangoproject.models import NullableSubjectProfile
from grantor_django.backends import GrantorBackend

pytestmark = pytest.mark.django_db

VERIFIED = {"email": "erika@example.com", "email_verified": True}


@pytest.fixture
def nullable(settings):
    settings.GRANTOR_SUBJECT_FIELD = "nullable_profile.sub"


@pytest.fixture
def erika(django_user_model):
    """Registered here, never signed in through the issuer: ``sub`` is NULL."""
    user = django_user_model.objects.create_user(
        username="erika", email="erika@example.com", password="x"
    )
    NullableSubjectProfile.objects.create(user=user, sub=None)
    return user


def _authenticate(**claims):
    return GrantorBackend().authenticate(None, grantor_claims={"sub": SUB, **claims})


def _stored_sub(user):
    return NullableSubjectProfile.objects.get(user=user).sub


def test_a_first_sign_in_links_a_null_subject(nullable, erika):
    assert _authenticate(**VERIFIED) == erika
    assert _stored_sub(erika) == SUB


def test_once_linked_the_subject_alone_signs_them_in(nullable, erika):
    _authenticate(**VERIFIED)

    assert _authenticate() == erika  # no email at all: `sub` is the identity


def test_the_empty_string_still_means_unlinked(nullable, erika):
    NullableSubjectProfile.objects.filter(user=erika).update(sub="")

    assert _authenticate(**VERIFIED) == erika


def test_an_unverified_address_still_links_nobody(nullable, erika):
    assert _authenticate(email="erika@example.com", email_verified=False) is None
    assert _stored_sub(erika) is None


def test_a_null_subject_links_on_the_stated_queryset_route_too(nullable, erika, settings):
    """``GRANTOR_USER_QUERYSET`` takes the join route instead of the related
    model's manager. Both routes must agree about what "unlinked" means."""
    settings.GRANTOR_USER_QUERYSET = "djangoproject.querysets.every_user"

    assert _authenticate(**VERIFIED) == erika
    assert _stored_sub(erika) == SUB


def test_the_join_route_does_not_mistake_a_missing_row_for_an_unlinked_one(
    nullable, settings, django_user_model
):
    """A LEFT JOIN makes ``nullable_profile__sub IS NULL`` true for a user
    with no profile at all. That person is not "unlinked": there is no row
    to write the ``sub`` into, and treating them as a candidate would fail
    on the write rather than refuse cleanly."""
    settings.GRANTOR_USER_QUERYSET = "djangoproject.querysets.every_user"
    django_user_model.objects.create_user(
        username="no-profile", email="erika@example.com", password="x"
    )

    assert _authenticate(**VERIFIED) is None
