"""The round trip does not depend on the session, and here is the proof.

The transaction rides in its own signed cookie precisely so that a sign-in
begun on one node can finish on another, and so that `state` is never used
as a storage key. A project running on the signed-cookie session backend —
no session table at all — must sign in exactly the same way.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import pytest
from django.urls import reverse
from django_support import SUB
from djangoproject.models import Profile

pytestmark = pytest.mark.django_db

BACKENDS = [
    "django.contrib.sessions.backends.db",
    "django.contrib.sessions.backends.signed_cookies",
    "django.contrib.sessions.backends.cache",
]


@pytest.mark.parametrize("engine", BACKENDS)
def test_a_sign_in_completes_on_every_session_backend(client, issuer, local_user, settings, engine):
    settings.SESSION_ENGINE = engine
    Profile.objects.filter(user=local_user).update(grantor_sub=SUB)

    start = client.get(reverse("grantor_django:start"))
    params = {k: v[0] for k, v in parse_qs(urlparse(start["Location"]).query).items()}
    issuer["echo_nonce"] = params["nonce"]

    response = client.get(
        reverse("grantor_django:callback"), {"code": "c", "state": params["state"]}
    )

    assert response.status_code == 302
    assert response["Location"] == "/"
    assert client.session.get("_auth_user_id") == str(local_user.pk)


@pytest.mark.parametrize("engine", BACKENDS)
def test_the_transaction_never_lands_in_the_session(client, issuer, settings, engine):
    settings.SESSION_ENGINE = engine
    client.get(reverse("grantor_django:start"))

    assert "grantor_txn" in client.cookies
    assert not any("state" in str(k) or "verifier" in str(k) for k in client.session.keys())
