"""A DRF API that answers to a Grantor access token.

The second integration shape: an API with no sign-in of its own,
authenticating each request from a token the issuer minted.

    REST_FRAMEWORK = {
        "DEFAULT_AUTHENTICATION_CLASSES": ["grantor_django.drf.GrantorJWTAuthentication"],
    }
    GRANTOR_AUDIENCE = "https://api.example.com"   # this API's RFC 8707 resource id

**The audience must be this API, not the browser app.** A token minted for
the UI's own ``client_id`` is not a token for this API, and accepting one
makes ``aud`` decorative — which is the difference between an audience check
and the appearance of one. There is deliberately no fallback to
``GRANTOR_CLIENT_ID``: a fallback would be silently accepted by every
consumer that forgot to set the audience, and would undo the one check this
module exists for.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import jwt
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils.module_loading import import_string
from grantor import DiscoveryError, GrantorError, TokenError, discover, verify_access_token

from . import conf

try:
    from rest_framework import authentication, exceptions, permissions
except ModuleNotFoundError as exc:  # pragma: no cover - exercised by a subprocess test
    raise ImproperlyConfigured(
        "grantor_django.drf requires Django REST Framework, which is an optional "
        "extra of this package. Install it with:  pip install 'grantor-django[drf]'"
    ) from exc

__all__ = [
    "GrantorJWTAuthentication",
    "GrantorUser",
    "HasGrantorScope",
    "HasGrantorRole",
    "scopes_of",
    "roles_of",
    "audience",
]


def audience() -> str:
    """This API's resource identifier, and a refusal if nobody set one.

    Raised rather than defaulted. See the module docstring: a default here
    would be the bug.
    """
    value = getattr(settings, "GRANTOR_AUDIENCE", None)
    if not value or not isinstance(value, str):
        raise ImproperlyConfigured(
            "GRANTOR_AUDIENCE must name this API's resource identifier — the value "
            "a client asks for with the RFC 8707 `resource` parameter. It is "
            "deliberately not defaulted to GRANTOR_CLIENT_ID: that would accept a "
            "token minted for the browser application as if it were a token for "
            "this API."
        )
    return value


class GrantorUser:
    """A person identified by a token, with no local record.

    The default principal, because it is the shape that needs nothing from
    the host project — no model, no migration, no table. An API that wants a
    local record points ``GRANTOR_DRF_USER_RESOLVER`` at a callable and gets
    whatever that returns instead. Both are legitimate and the library
    forces neither.

    Satisfies the small part of Django's user contract that DRF actually
    reads: ``is_authenticated``, ``is_anonymous``, and something to print.
    """

    is_authenticated = True
    is_anonymous = False
    is_active = True

    def __init__(self, claims: Mapping[str, Any]) -> None:
        self.claims = dict(claims)
        self.sub = str(claims.get("sub", ""))

    # `sub` is the stable identifier — a UUID naming the person to this
    # issuer, unchanged when they change their address. Email is a claim
    # about them; this is who they are.
    @property
    def pk(self) -> str:
        return self.sub

    id = pk

    @property
    def roles(self) -> tuple[str, ...]:
        return roles_of(self.claims)

    @property
    def scopes(self) -> frozenset[str]:
        return scopes_of(self.claims)

    def __str__(self) -> str:
        return self.sub

    def __repr__(self) -> str:
        # `sub` is the only identifier this library prints, and only after
        # the token carrying it has been verified.
        return f"GrantorUser(sub={self.sub!r})"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, GrantorUser) and other.sub == self.sub

    def __hash__(self) -> int:
        return hash(("GrantorUser", self.sub))


def scopes_of(claims: Mapping[str, Any]) -> frozenset[str]:
    """The token's scopes, as a set. ``scope`` is a space-delimited string."""
    raw = claims.get("scope")
    if isinstance(raw, str):
        return frozenset(raw.split())
    if isinstance(raw, (list, tuple)):
        return frozenset(str(item) for item in raw)
    return frozenset()


def roles_of(claims: Mapping[str, Any]) -> tuple[str, ...]:
    """The token's roles.

    ``roles`` is **a flat array of role names at the top level** — not
    namespaced URIs, not a nested object. A tenant that has adopted no roles
    gets ``[]`` and a successful response; "no roles" and "this tenant does
    not do roles" are the same fact from here.

    ``permissions`` is deliberately not read from a token. It lives on
    userinfo only: an ID token travels, lands in cookies and is a sign-out
    hint, while a permission list is unbounded in a way a role list is not.
    Code that looks for ``permissions`` in a token is looking for something
    that is not there.
    """
    raw = claims.get("roles")
    if isinstance(raw, (list, tuple)):
        return tuple(str(item) for item in raw)
    return ()


def _looks_like_a_jwt(raw: str) -> bool:
    """Three non-empty base64url segments, and a header that parses.

    Cheap, local, and decisive: anything that fails this was never a token
    from this issuer, so declining it is not a refusal — it is leaving it
    for whoever it belongs to.
    """
    if raw.count(".") != 2 or not all(part for part in raw.split(".")):
        return False
    try:
        jwt.get_unverified_header(raw)
    except Exception:
        return False
    return True


def _resolver():
    path = getattr(settings, "GRANTOR_DRF_USER_RESOLVER", None)
    return import_string(path) if path else None


class GrantorJWTAuthentication(authentication.BaseAuthentication):
    """Authenticate a caller from a Grantor access token.

    Verified by signature against the issuer's JWKS — never decode-and-trust
    — with the audience being this API.
    """

    keyword = "Bearer"

    def authenticate(self, request: Any) -> tuple[Any, Mapping[str, Any]] | None:
        header = authentication.get_authorization_header(request).decode("latin-1")
        prefix = f"{self.keyword} "
        if not header.startswith(prefix):
            # Not ours. Returning None lets another authenticator have it,
            # rather than turning "no credentials" into a refusal.
            return None
        raw = header[len(prefix) :].strip()
        if not raw or self._belongs_to_someone_else(raw):
            return None
        if not _looks_like_a_jwt(raw):
            # Decline before touching the network. An API may mint its own
            # opaque credentials under the same `Bearer` scheme, and trying
            # to verify one of those would fetch discovery, fail, and answer
            # 503 — turning another authenticator's perfectly good token
            # into an outage report. Shape first, issuer second.
            return None

        try:
            http = conf.http_client()
            claims = verify_access_token(
                raw,
                discovery=discover(
                    conf.issuer(),
                    client=http,
                    ttl=conf.get("GRANTOR_JWKS_CACHE_SECONDS"),
                ),
                audience=audience(),
                client=http,
                # The name always said JWKS. Until now it bounded only the
                # discovery document, so a consumer's key-cache setting was
                # not bounding keys.
                jwks_ttl=conf.get("GRANTOR_JWKS_CACHE_SECONDS"),
            )
        except TokenError as exc:
            # The reason names the check that failed and never any part of
            # the token; the body the caller gets says even less.
            raise exceptions.AuthenticationFailed("invalid access token") from exc
        except DiscoveryError as exc:
            # The issuer being unreachable is not the caller's fault, and
            # answering 401 would tell them to re-authenticate pointlessly.
            raise IssuerUnavailable() from exc
        except GrantorError as exc:
            raise IssuerUnavailable() from exc

        return self.get_user(claims), claims

    def _belongs_to_someone_else(self, raw: str) -> bool:
        """Leave another authenticator's tokens alone.

        An API may mint its own credentials — a machine token for an agent,
        say — under the same ``Bearer`` scheme. Claiming those here would
        turn every one of them into a 401 before their own authenticator
        ever saw them.
        """
        prefixes = getattr(settings, "GRANTOR_DRF_IGNORE_TOKEN_PREFIXES", ())
        return any(raw.startswith(p) for p in prefixes)

    def get_user(self, claims: Mapping[str, Any]) -> Any:
        """Turn verified claims into whatever this project calls a person.

        Default: a :class:`GrantorUser`, which needs no local record at all.
        Set ``GRANTOR_DRF_USER_RESOLVER`` to a dotted path taking the claims
        and returning a user to map onto a local row instead — or subclass
        this and override.
        """
        resolver = _resolver()
        if resolver is None:
            return GrantorUser(claims)
        user = resolver(claims)
        if user is None:
            raise exceptions.AuthenticationFailed("no account for this token")
        return user

    def authenticate_header(self, request: Any) -> str:
        # Without this DRF answers 403 to an unauthenticated request instead
        # of 401, and a client with no credentials is never told to get some.
        return f'{self.keyword} realm="api"'


class IssuerUnavailable(exceptions.APIException):
    status_code = 503
    default_detail = "the identity provider is unavailable"
    default_code = "issuer_unavailable"


def HasGrantorScope(*required: str) -> type:  # noqa: N802 - a DRF permission factory
    """Require every named scope.

        permission_classes = [HasGrantorScope("things:write")]

    Returns a class rather than an instance, because that is what DRF
    instantiates.
    """
    wanted = frozenset(required)

    class _HasGrantorScope(permissions.BasePermission):
        message = f"this endpoint requires the scope(s): {', '.join(sorted(wanted))}"

        def has_permission(self, request: Any, view: Any) -> bool:
            return wanted.issubset(scopes_of(request.auth or {}))

    _HasGrantorScope.__name__ = f"HasGrantorScope({', '.join(sorted(wanted))})"
    return _HasGrantorScope


def HasGrantorRole(*required: str, require_all: bool = False) -> type:  # noqa: N802
    """Require a role — any of them by default, all of them on request.

        permission_classes = [HasGrantorRole("admin")]

    Roles are read from the token as it was minted. A role removed at the
    issuer is gone from the next *userinfo* call, while a token already in
    somebody's hand still says what it said. If a revocation must take
    effect promptly, read userinfo — that is not something this permission
    class can decide for you.
    """
    wanted = frozenset(required)

    class _HasGrantorRole(permissions.BasePermission):
        message = f"this endpoint requires the role(s): {', '.join(sorted(wanted))}"

        def has_permission(self, request: Any, view: Any) -> bool:
            held = frozenset(roles_of(request.auth or {}))
            return wanted.issubset(held) if require_all else bool(wanted & held)

    _HasGrantorRole.__name__ = f"HasGrantorRole({', '.join(sorted(wanted))})"
    return _HasGrantorRole


def resolve_local_user(claims: Mapping[str, Any]) -> Any | None:
    """A ready-made ``GRANTOR_DRF_USER_RESOLVER`` that links like sign-in does.

        GRANTOR_DRF_USER_RESOLVER = "grantor_django.drf.resolve_local_user"

    Same rules as the authentication backend, including the one that
    matters: the email fallback is used once and only on a verified address.
    """
    from .backends import GrantorBackend

    return GrantorBackend().authenticate(None, grantor_claims=claims)
