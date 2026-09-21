"""Settings, read in one place and checked at boot.

The whole configuration is four required strings. Everything else — every
endpoint — comes from the issuer's discovery document, because transcribing
endpoints into a configuration is how a configuration goes stale while still
looking correct.

The Django system check registered in :mod:`grantor_django.apps` runs
:func:`check_configuration` at startup, so a missing setting is a refusal to
boot rather than a traceback at somebody's first sign-in — by which time the
person looking at the error is not the person who can fix it.
"""

from __future__ import annotations

from typing import Any

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

__all__ = [
    "REQUIRED_SETTINGS",
    "get",
    "issuer",
    "client_id",
    "client_secret",
    "callback_base_url",
    "scope",
    "subject_field",
    "check_configuration",
]

REQUIRED_SETTINGS = (
    "GRANTOR_ISSUER",
    "GRANTOR_CLIENT_ID",
    "GRANTOR_CALLBACK_BASE_URL",
)

_DEFAULTS: dict[str, Any] = {
    "GRANTOR_CLIENT_SECRET": None,
    "GRANTOR_SCOPE": "openid profile email",
    "GRANTOR_AUTH_METHOD": "client_secret_basic",
    # Where ``sub`` lives on the host project's own models. A dotted path
    # relative to the user model, so ``"profile.grantor_sub"`` reaches
    # through a related object. The library never ships a migration for a
    # table it does not own — a library that demands its own user table is
    # one that cannot be adopted incrementally.
    "GRANTOR_SUBJECT_FIELD": "grantor_sub",
    # Refusing an unknown subject is the safe default, and it is what the
    # implementation this was extracted from does. Provisioning on first
    # sight is legitimate — a resource server with no signup of its own
    # wants exactly that — but a library that does it unasked would create
    # accounts in projects whose signup policy lives somewhere else.
    "GRANTOR_CREATE_UNKNOWN_USERS": False,
    "GRANTOR_LOGIN_REDIRECT_URL": "/",
    "GRANTOR_LOGOUT_REDIRECT_URL": "/",
    # Where a failed sign-in lands, with ``?grantor_error=<code>``. The code
    # is from the normalized vocabulary and is safe to show; nothing about
    # claims or tokens travels with it.
    "GRANTOR_ERROR_REDIRECT_URL": None,
    "GRANTOR_POST_LOGOUT_REDIRECT_URI": None,
    "GRANTOR_TXN_COOKIE_NAME": "grantor_txn",
    "GRANTOR_TXN_MAX_AGE": 600,
    "GRANTOR_ID_TOKEN_COOKIE_NAME": "grantor_id_token",
    "GRANTOR_COOKIE_SECURE": None,  # None → the opposite of DEBUG
    "GRANTOR_TIMEOUT": 15.0,
    # How long a discovery document and its JWKS are reused. The name is
    # the one the consumers already use, so adopting this library is a code
    # change and not a configuration migration.
    "GRANTOR_JWKS_CACHE_SECONDS": 3600,
    # A dotted path to a zero-argument callable returning an `httpx.Client`,
    # for a project that must reach the issuer through a proxy, present a
    # client certificate, or trust a private CA. One seam, used by every
    # request this package makes — the sign-in flow and the resource server
    # alike — so those cannot end up configured differently.
    "GRANTOR_HTTP_CLIENT_FACTORY": None,
}


def get(name: str) -> Any:
    """One setting, with this library's default when the project has none."""
    if hasattr(settings, name):
        return getattr(settings, name)
    if name in _DEFAULTS:
        return _DEFAULTS[name]
    raise ImproperlyConfigured(f"{name} is not a grantor-django setting")


def issuer() -> str:
    return str(get("GRANTOR_ISSUER")).rstrip("/")


def client_id() -> str:
    return str(get("GRANTOR_CLIENT_ID"))


def client_secret() -> str | None:
    value = get("GRANTOR_CLIENT_SECRET")
    return str(value) if value else None


def callback_base_url() -> str:
    return str(get("GRANTOR_CALLBACK_BASE_URL")).rstrip("/")


def scope() -> str:
    value = get("GRANTOR_SCOPE")
    return value if isinstance(value, str) else " ".join(value)


def subject_field() -> tuple[str | None, str]:
    """``GRANTOR_SUBJECT_FIELD`` split into (related accessor, field name).

    ``"grantor_sub"`` → ``(None, "grantor_sub")`` — the field is on the user.
    ``"profile.grantor_sub"`` → ``("profile", "grantor_sub")``.
    """
    raw = str(get("GRANTOR_SUBJECT_FIELD"))
    if "." in raw:
        related, _, field = raw.rpartition(".")
        return related, field
    return None, raw


def http_client() -> Any:
    """The project's own ``httpx.Client``, or ``None`` for a fresh one each time."""
    path = get("GRANTOR_HTTP_CLIENT_FACTORY")
    if not path:
        return None
    from django.utils.module_loading import import_string

    return import_string(path)()


def cookie_secure() -> bool:
    value = get("GRANTOR_COOKIE_SECURE")
    if value is None:
        return not settings.DEBUG
    return bool(value)


def check_configuration() -> list[str]:
    """Every complaint this configuration deserves, as plain sentences.

    Returns messages rather than raising, so the system check can report all
    of them at once instead of one per restart.
    """
    problems: list[str] = []

    for name in REQUIRED_SETTINGS:
        value = getattr(settings, name, None)
        if not value or not isinstance(value, str):
            problems.append(f"{name} must be set to a non-empty string.")

    raw_issuer = getattr(settings, "GRANTOR_ISSUER", "")
    if isinstance(raw_issuer, str) and raw_issuer and not raw_issuer.startswith("https://"):
        # http:// would carry an authorization code and a client secret in
        # the clear. Localhost is not exempted here on purpose: an issuer is
        # a remote host by definition.
        problems.append("GRANTOR_ISSUER must be an https:// URL.")

    raw_callback = getattr(settings, "GRANTOR_CALLBACK_BASE_URL", "")
    if isinstance(raw_callback, str) and raw_callback and "://" not in raw_callback:
        problems.append(
            "GRANTOR_CALLBACK_BASE_URL must be an absolute URL — it is what the "
            "issuer redirects the browser back to, and it must match a redirect "
            "URI registered for this client exactly, trailing slash included."
        )

    method = getattr(settings, "GRANTOR_AUTH_METHOD", "client_secret_basic")
    if method not in ("client_secret_basic", "client_secret_post"):
        problems.append(
            "GRANTOR_AUTH_METHOD must be 'client_secret_basic' or 'client_secret_post'."
        )

    return problems
