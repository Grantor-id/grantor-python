"""The quickstart is sufficient, not merely correct (AUTH-233).

`tests/integration/test_quickstart_snippets.py` reconciles every string the
quickstart publishes against a project that runs, and it is a good test. It
cannot catch a **missing** line: it constrains what is shown, never whether
what is shown is enough.

That gap shipped. The quickstart never mentioned `AUTHENTICATION_BACKENDS`,
so a reader following it exactly kept Django's default — `ModelBackend`
alone — and `authenticate(request, grantor_claims=...)` walked a chain with
nothing able to answer. Every sign-in was refused, and the callback named
the cause `account_not_found`, sending the reader to inspect a database
that was fine.

So this file asserts the other property: a project configured with what the
quickstart publishes **signs somebody in**. It is deliberately a round trip
through the real callback rather than a unit call, because "the reader can
sign in" is the claim being made and nothing smaller is that claim.
"""

from __future__ import annotations

import json
import pathlib
from urllib.parse import parse_qs, urlparse

import pytest
from django.urls import reverse
from django_support import SUB
from djangoproject.models import Profile

pytestmark = pytest.mark.django_db

QUICKSTART = json.loads(
    (pathlib.Path(__file__).resolve().parents[3] / "docs" / "quickstart.json").read_text()
)

#: Django's own default, which is what a reader keeps by doing nothing.
DJANGO_DEFAULT = ["django.contrib.auth.backends.ModelBackend"]


def backends_the_quickstart_publishes() -> list[str]:
    """The list a reader would end up with, executed rather than parsed.

    Executing it is the point: a snippet that does not evaluate to a usable
    list is itself a defect, and a regex over the text would hide that.
    """
    namespace: dict[str, object] = {}
    exec(QUICKSTART["authentication_backends"], namespace)  # noqa: S102
    value = namespace["AUTHENTICATION_BACKENDS"]
    assert isinstance(value, list), "the snippet must evaluate to a list"
    return [str(item) for item in value]


def complete_a_sign_in(client, issuer):
    start = client.get(reverse("grantor_django:start"))
    params = {k: v[0] for k, v in parse_qs(urlparse(start["Location"]).query).items()}
    issuer["echo_nonce"] = params["nonce"]
    return client.get(reverse("grantor_django:callback"), {"code": "c", "state": params["state"]})


def test_the_snippet_names_the_backend_this_library_ships():
    published = backends_the_quickstart_publishes()

    assert "grantor_django.backends.GrantorBackend" in published


def test_a_reader_following_the_quickstart_can_sign_in(client, issuer, local_user, settings):
    """The assertion this arrangement was supposed to make and did not."""
    settings.AUTHENTICATION_BACKENDS = backends_the_quickstart_publishes()
    Profile.objects.filter(user=local_user).update(grantor_sub=SUB)

    response = complete_a_sign_in(client, issuer)

    assert response.status_code == 302
    assert client.session.get("_auth_user_id") == str(local_user.pk)


def test_and_without_that_line_they_cannot(client, issuer, local_user, settings):
    """The defect itself, kept as a test so the line stays load-bearing.

    If this ever stops failing, `GrantorBackend` is being installed by some
    other route and the quickstart's claim has quietly changed — which is
    worth noticing, whether it turns out to be good news or not.
    """
    settings.AUTHENTICATION_BACKENDS = DJANGO_DEFAULT
    Profile.objects.filter(user=local_user).update(grantor_sub=SUB)

    response = complete_a_sign_in(client, issuer)

    assert client.session.get("_auth_user_id") is None
    assert response.status_code in (302, 400)


def test_the_published_list_is_what_the_test_project_runs(settings):
    """Same reconciliation the sibling file does for every other snippet.

    The project keeps `ModelBackend` beside it because it also has an
    ordinary password login; the quickstart shows the same pair for the
    same reason, with the note that removing it closes the password path.
    """
    published = backends_the_quickstart_publishes()

    assert published == list(settings.AUTHENTICATION_BACKENDS)


@pytest.mark.parametrize(
    "line",
    [
        "grantor_django.backends.GrantorBackend",
        "django.contrib.auth.backends.ModelBackend",
    ],
)
def test_both_halves_of_the_decision_are_visible(line):
    """A reader has to be able to see the choice in order to make it."""
    assert line in QUICKSTART["authentication_backends"]
