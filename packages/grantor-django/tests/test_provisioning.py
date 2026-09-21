"""Provisioning a person this project has never seen — off unless asked for.

Both answers are legitimate. A resource server with no signup of its own
wants an account on first sight; an application whose signup policy lives
somewhere else wants a refusal. The library must not force the first, and it
must not pick it silently.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import pytest
from django.contrib.auth import get_user_model
from django.urls import reverse
from django_support import SUB

pytestmark = pytest.mark.django_db


def _sign_in(client, issuer, **claims):
    issuer["claims"] = claims
    start = client.get(reverse("grantor_django:start"))
    params = {k: v[0] for k, v in parse_qs(urlparse(start["Location"]).query).items()}
    issuer["echo_nonce"] = params["nonce"]
    return client.get(reverse("grantor_django:callback"), {"code": "c", "state": params["state"]})


def test_an_unknown_subject_is_refused_by_default(client, issuer, settings):
    settings.GRANTOR_SUBJECT_FIELD = "username"
    response = _sign_in(client, issuer, email="new@example.com", email_verified=True)

    assert response["Location"].endswith("grantor_error=account_not_found")
    assert not get_user_model().objects.filter(username=SUB).exists()


def test_a_project_that_asks_for_provisioning_gets_it(client, issuer, settings):
    settings.GRANTOR_SUBJECT_FIELD = "username"
    settings.GRANTOR_CREATE_UNKNOWN_USERS = True
    response = _sign_in(client, issuer, email="new@example.com", email_verified=True)

    assert response["Location"] == "/"
    user = get_user_model().objects.get(username=SUB)
    assert user.email == "new@example.com"


def test_a_provisioned_person_has_no_local_password_even_in_principle(client, issuer, settings):
    """They arrived through the issuer. They must not acquire a credential here."""
    settings.GRANTOR_SUBJECT_FIELD = "username"
    settings.GRANTOR_CREATE_UNKNOWN_USERS = True
    _sign_in(client, issuer, email="new@example.com", email_verified=True)

    user = get_user_model().objects.get(username=SUB)
    assert not user.has_usable_password()


def test_an_inactive_person_is_refused(client, issuer, settings, local_user):
    from djangoproject.models import Profile

    Profile.objects.filter(user=local_user).update(grantor_sub=SUB)
    local_user.is_active = False
    local_user.save(update_fields=["is_active"])

    response = _sign_in(client, issuer)
    assert response["Location"].endswith("grantor_error=account_not_found")
