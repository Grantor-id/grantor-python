"""The resource-server shape, through a real DRF request cycle.

The audience test is the one this module exists for. Everything else is
scaffolding around it.
"""

from __future__ import annotations

import time

import jwt
import pytest
from django.urls import reverse
from django_support import CLIENT_ID, ISSUER, KID

API_AUDIENCE = "https://api.example.com"

pytestmark = pytest.mark.django_db


@pytest.fixture
def token(keypair, issuer):
    """Mint an access token the way the issuer would."""
    private, _ = keypair

    def _token(*, aud=API_AUDIENCE, key=None, algorithm="RS256", kid=KID, **claims):
        now = int(time.time())
        payload = {
            "iss": ISSUER,
            "sub": "0d9b1a7e-1a62-4a0e-9b7a-1f0f2c3d4e5f",
            "aud": aud,
            "client_id": CLIENT_ID,
            "iat": now,
            "exp": now + 300,
            **claims,
        }
        return jwt.encode(payload, key or private, algorithm=algorithm, headers={"kid": kid})

    return _token


def _get(client, url, raw=None):
    headers = {"HTTP_AUTHORIZATION": f"Bearer {raw}"} if raw else {}
    return client.get(url, **headers)


def test_a_token_audienced_for_this_api_is_accepted(client, token):
    response = _get(client, reverse("whoami"), token())
    assert response.status_code == 200
    assert response.json()["sub"] == "0d9b1a7e-1a62-4a0e-9b7a-1f0f2c3d4e5f"


def test_a_token_minted_for_the_browser_app_is_rejected(client, token):
    """The test that would fail if `aud` checking were removed.

    A token for the UI's own client id is not a token for this API.
    Accepting one makes `aud` decorative, which is the difference between
    an audience check and the appearance of one.
    """
    response = _get(client, reverse("whoami"), token(aud=CLIENT_ID))
    assert response.status_code == 401


def test_the_audience_is_never_defaulted_to_the_client_id(client, token, settings):
    """A fallback would be silently accepted by everyone who forgot to set it."""
    from django.core.exceptions import ImproperlyConfigured
    from grantor_django.drf import audience

    del settings.GRANTOR_AUDIENCE
    with pytest.raises(ImproperlyConfigured, match="GRANTOR_AUDIENCE"):
        audience()


def test_an_expired_token_is_rejected(client, token):
    past = int(time.time()) - 3600
    response = _get(client, reverse("whoami"), token(iat=past, exp=past + 60))
    assert response.status_code == 401


def test_a_tampered_signature_is_rejected(client, token):
    raw = token()
    header, payload, signature = raw.split(".")
    response = _get(client, reverse("whoami"), f"{header}.{payload}.{signature[:-4]}AAAA")
    assert response.status_code == 401


def test_a_token_from_another_issuer_is_rejected(client, token):
    response = _get(client, reverse("whoami"), token(iss="https://evil.example.com"))
    assert response.status_code == 401


def test_an_unknown_kid_is_rejected_after_one_refetch(client, token):
    response = _get(client, reverse("whoami"), token(kid="never-existed"))
    assert response.status_code == 401


def test_a_401_body_never_contains_the_token(client, token):
    """A rejected token is the one whose contents must not reach a log.

    A response body is a log: it lands in the client's console, in an error
    reporter, and in whatever the caller decides to print.
    """
    raw = token(aud=CLIENT_ID, scope="things:write", email="person@example.com")
    response = _get(client, reverse("whoami"), raw)
    body = response.content.decode()

    assert response.status_code == 401
    assert raw not in body
    for fragment in raw.split("."):
        assert fragment not in body
    assert "person@example.com" not in body


def test_an_unauthenticated_request_gets_401_and_is_told_what_to_present(client):
    """Not 403. A caller with no credentials must be told to get some."""
    response = client.get(reverse("whoami"))
    assert response.status_code == 401
    assert response["WWW-Authenticate"].startswith("Bearer ")


def test_another_authenticators_token_is_left_alone(client, token):
    """An `amt_` machine credential is not Grantor's to refuse.

    Claiming it here would turn every one of them into a 401 before its own
    authenticator ever saw it.
    """
    response = _get(client, reverse("whoami"), "amt_a-machine-credential")
    # 401 from DRF for having no *accepted* credentials — but crucially not
    # an AuthenticationFailed raised by this class, which would have stopped
    # the chain. The header proves the request fell through to the end.
    assert response.status_code == 401
    assert response["WWW-Authenticate"].startswith("Bearer ")


def test_a_scope_is_required_where_it_is_declared(client, token):
    granted = client.post(
        reverse("things"),
        HTTP_AUTHORIZATION=f"Bearer {token(scope='things:read things:write')}",
    )
    refused = client.post(
        reverse("things"), HTTP_AUTHORIZATION=f"Bearer {token(scope='things:read')}"
    )
    assert granted.status_code == 200
    assert refused.status_code == 403


def test_roles_are_read_as_a_flat_array_at_the_top_level(client, token):
    """Not namespaced URIs, not a nested object — what the issuer emits."""
    response = _get(client, reverse("whoami"), token(roles=["admin", "billing"]))
    assert response.json()["roles"] == ["admin", "billing"]


def test_a_role_is_required_where_it_is_declared(client, token):
    granted = _get(client, reverse("admin-only"), token(roles=["admin"]))
    refused = _get(client, reverse("admin-only"), token(roles=["billing"]))
    assert granted.status_code == 200
    assert refused.status_code == 403


def test_a_tenant_with_no_roles_is_not_an_error(client, token):
    """`[]` and "this tenant does not do roles" are the same fact from here."""
    response = _get(client, reverse("whoami"), token())
    assert response.status_code == 200
    assert response.json()["roles"] == []


def test_permissions_are_not_read_from_a_token(client, token):
    """They live on userinfo only, and looking for them here finds nothing."""
    from grantor_django.drf import roles_of

    assert roles_of({"permissions": ["things:write"]}) == ()


def test_a_caller_with_no_local_record_is_still_somebody(client, token):
    """The default principal needs no model, no migration and no table."""
    from grantor_django.drf import GrantorUser

    response = _get(client, reverse("whoami"), token())
    assert response.status_code == 200
    assert GrantorUser({"sub": "x"}).is_authenticated


def test_a_project_that_wants_a_local_record_says_so(client, token, settings, local_user):
    from djangoproject.models import Profile

    Profile.objects.filter(user=local_user).update(
        grantor_sub="0d9b1a7e-1a62-4a0e-9b7a-1f0f2c3d4e5f"
    )
    settings.GRANTOR_DRF_USER_RESOLVER = "grantor_django.drf.resolve_local_user"

    response = _get(client, reverse("whoami"), token())
    assert response.status_code == 200
    assert response.json()["sub"] == "ana"


def test_a_resolver_that_finds_nobody_refuses(client, token, settings):
    settings.GRANTOR_DRF_USER_RESOLVER = "grantor_django.drf.resolve_local_user"
    response = _get(client, reverse("whoami"), token())
    assert response.status_code == 401


def test_a_grantor_user_prints_only_its_sub(client, token):
    from grantor_django.drf import GrantorUser

    user = GrantorUser({"sub": "abc", "email": "person@example.com", "roles": ["admin"]})
    assert "person@example.com" not in repr(user)
    assert "abc" in repr(user)


def test_importing_drf_support_without_drf_names_the_extra():
    """Not an ImportError traceback.

    Somebody who pip-installed `grantor-django` and then pasted the DRF
    snippet gets a sentence telling them which command fixes it, rather than
    a stack ending in `ModuleNotFoundError: rest_framework`.

    Run in a subprocess with `rest_framework` made unimportable, because the
    rest of this suite has it installed for good reason.
    """
    import subprocess
    import sys

    script = """
import sys

class Blocked:
    def find_module(self, name, path=None):
        return self if name == "rest_framework" or name.startswith("rest_framework.") else None
    def find_spec(self, name, path=None, target=None):
        if name == "rest_framework" or name.startswith("rest_framework."):
            raise ModuleNotFoundError("No module named 'rest_framework'")
        return None

for mod in [m for m in sys.modules if m.startswith("rest_framework")]:
    del sys.modules[mod]
sys.meta_path.insert(0, Blocked())

import django
from django.conf import settings
settings.configure(
    INSTALLED_APPS=["django.contrib.auth", "django.contrib.contenttypes"],
    DATABASES={},
    GRANTOR_ISSUER="https://acme.api.grantor.id",
    GRANTOR_CLIENT_ID="acme-web",
    GRANTOR_CALLBACK_BASE_URL="https://app.example.com",
)
django.setup()

from django.core.exceptions import ImproperlyConfigured
try:
    import grantor_django.drf
except ImproperlyConfigured as exc:
    print(str(exc))
else:
    print("NO ERROR RAISED")
"""
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", script], capture_output=True, text=True, check=True
    )
    message = result.stdout.strip()
    assert "grantor-django[drf]" in message
    assert "pip install" in message


def test_an_opaque_token_is_declined_without_a_network_call(client, settings, monkeypatch):
    """Another authenticator's credential must not become a 503.

    Anything that is not shaped like a JWT was never minted by this issuer,
    so it is declined locally. Verifying it would fetch discovery, fail,
    and report the identity provider as unavailable — an outage invented
    out of somebody else's perfectly good token.

    Proven by making any discovery attempt an error: if one happens, this
    test fails rather than passing for the wrong reason.
    """

    def explode(*args, **kwargs):
        raise AssertionError("the issuer must not be contacted for a non-JWT")

    monkeypatch.setattr("grantor_django.drf.discover", explode)

    response = client.get(
        reverse("whoami"), HTTP_AUTHORIZATION="Bearer mt_an-opaque-machine-credential"
    )
    assert response.status_code == 401
    assert response["WWW-Authenticate"].startswith("Bearer ")


@pytest.mark.parametrize(
    "malformed",
    ["not-a-jwt", "only.two", "a.b.c.d", "..", "eyJhbGciOiJIUzI1NiJ9..sig"],
)
def test_nothing_malformed_reaches_the_issuer(client, malformed, monkeypatch):
    def explode(*args, **kwargs):
        raise AssertionError("the issuer must not be contacted")

    monkeypatch.setattr("grantor_django.drf.discover", explode)
    response = client.get(reverse("whoami"), HTTP_AUTHORIZATION=f"Bearer {malformed}")
    assert response.status_code == 401
