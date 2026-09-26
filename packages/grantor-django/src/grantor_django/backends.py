"""Issuer identity → local user.

``sub`` is the identity. Email is a one-shot bootstrap, used **exactly
once** and **only when the issuer asserts it as verified**, for a person who
already has an account here and is arriving through the issuer for the first
time.

That gate is the most important line in this package. An unverified address
is a claim, not an identity: anybody who can put a string in an ``email``
field of an account at some tenant could otherwise claim somebody else's
account here. ``email_verified`` is per-tenant — it says they proved it to
*this* tenant, which is the only assertion that means anything.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import BaseBackend
from django.core.exceptions import FieldDoesNotExist
from django.db import IntegrityError, transaction
from django.db.models import Q
from django.utils.module_loading import import_string

from . import conf

__all__ = ["GrantorBackend", "subject_of", "find_by_subject", "link_by_verified_email"]

logger = logging.getLogger("grantor_django")


def _user_queryset():
    """The set of people this project considers real.

    This is the **user-model** half of a lookup, and on its own it is not
    the guard. When ``sub`` lives behind a relation, the row that decides
    the match is in the related table, and ``_users_whose_subject`` is what
    asks that model's own manager for it — see there for why.

    ``GRANTOR_USER_QUERYSET`` names a callable returning the queryset to
    use, for a project whose answer is not its default manager. Setting it
    replaces the related-model route entirely, so it must exclude the same
    rows that route would have; the ``W001`` system check says so at boot.
    """
    path = conf.get("GRANTOR_USER_QUERYSET")
    if path:
        return import_string(path)()
    return get_user_model()._default_manager.all()


def subject_of(user: Any) -> str:
    """Read ``sub`` off wherever this project keeps it."""
    related, field = conf.subject_field()
    target = getattr(user, related, None) if related else user
    if target is None:
        return ""
    return getattr(target, field, "") or ""


def _set_subject(user: Any, sub: str) -> Any:
    """Write ``sub`` back, and return the object that must be saved."""
    related, field = conf.subject_field()
    target = getattr(user, related) if related else user
    setattr(target, field, sub)
    return target


def _subject_relation() -> Any | None:
    """The relation ``GRANTOR_SUBJECT_FIELD`` reaches through, or ``None``.

    ``None`` when ``sub`` lives on the user model itself, in which case
    ``_default_manager`` already is the project's answer and there is
    nothing to route around.
    """
    related, _ = conf.subject_field()
    if not related:
        return None
    try:
        return get_user_model()._meta.get_field(related)
    except FieldDoesNotExist:
        # A malformed setting is the system check's problem, not a lookup's.
        return None


def _users_whose_subject(value: str) -> Any | None:
    """Users whose subject row matches, found through the related model's
    **own** manager. ``None`` when that route does not apply.

    This is the safe default, and it is the whole of the fix. A
    related-field join *from* the user model reads the related table
    directly: the related model's manager never runs, so a project whose
    `Profile` manager excludes soft-deleted rows has those rows silently
    back in scope. Asking that manager instead is what every hand-rolled
    implementation did before this library existed, and the extraction lost
    it.

    Returns ``None`` — meaning "fall back to the plain join" — in two
    cases, both deliberate:

    * ``sub`` is on the user model, so there is no second manager to honour.
    * ``GRANTOR_USER_QUERYSET`` is set, so the project has stated its own
      answer and it wins. That is what the setting is for, and overriding a
      stated answer with an inferred one would be worse than either.
    """
    if conf.get("GRANTOR_USER_QUERYSET"):
        return None
    rel = _subject_relation()
    if rel is None:
        return None
    _, field = conf.subject_field()
    match = _unlinked(field) if value == "" else Q(**{field: value})
    return rel.related_model._default_manager.filter(match).values_list(
        rel.field.attname, flat=True
    )


def _unlinked(lookup: str, row: str | None = None) -> Q:
    """Not linked yet, in both of the spellings a project may have chosen.

    ``""`` and ``NULL`` mean the same thing here, and the library should not
    care which one a project picked: ``null=True`` with ``unique=True`` is the
    natural pairing, because NULLs never collide. Matching only ``""`` made
    the bootstrap match nobody on such a column, so a real person's first
    sign-in was refused, while every test that seeded a ``sub`` stayed green
    (AUTH-232).

    ``row`` is the relation the lookup crosses, when it crosses one. Across
    a LEFT JOIN, ``<row>__<field> IS NULL`` is also true for a user with no
    row at all, and that person is not unlinked: there is nowhere to write
    the ``sub``. So the row has to exist.
    """
    match = Q(**{lookup: ""}) | Q(**{f"{lookup}__isnull": True})
    if row:
        match &= Q(**{f"{row}__isnull": False})
    return match


def _lookup(prefix: str) -> str:
    related, field = conf.subject_field()
    return f"{related}__{field}" if related else field


def find_by_subject(sub: str) -> Any | None:
    if not sub:
        return None
    holders = _users_whose_subject(sub)
    if holders is not None:
        return _user_queryset().filter(pk__in=holders).first()
    return _user_queryset().filter(**{_lookup("sub"): sub}).first()


def link_by_verified_email(claims: Mapping[str, Any], sub: str) -> Any | None:
    """The one-shot bootstrap, and everything it refuses.

    Refuses unless the issuer says ``email_verified is True`` — not truthy,
    ``True``. A string ``"false"`` is truthy, and an issuer that answered
    with one would otherwise open the takeover this check exists to close.

    Only an account that is **not already linked** can be claimed this way,
    so the fallback can never move an identity off a ``sub`` that already
    owns it.
    """
    email = claims.get("email") or ""
    if not email or claims.get("email_verified") is not True:
        return None

    unlinked = _users_whose_subject("")
    if unlinked is not None:
        # Same reasoning as `find_by_subject`: an unlinked *and live* row.
        # Without this, a soft-deleted profile with no `sub` was claimable
        # by anybody who could prove that email address.
        candidate = _user_queryset().filter(email__iexact=email, pk__in=unlinked).first()
    else:
        related, _ = conf.subject_field()
        candidate = (
            _user_queryset()
            .filter(email__iexact=email)
            .filter(_unlinked(_lookup("sub"), related))
            .first()
        )
    if candidate is None:
        return None

    target = _set_subject(candidate, sub)
    try:
        with transaction.atomic():
            # Deliberately a full save rather than `update_fields=[field]`.
            # `update_fields` makes Django skip every column not named,
            # `auto_now` ones included — so the linked row's `updated_at`
            # came out byte-identical before and after, and the one event
            # most worth a timestamp was the one event with none.
            target.save()
    except IntegrityError:
        # A concurrent callback linked this sub first. Whoever won owns it,
        # and the loser must not overwrite them.
        return find_by_subject(sub)
    # `sub` is the only identifier this library ever logs, and only after
    # the token carrying it has been verified.
    logger.info("grantor: account linked on verified email, sub %s", sub)
    return candidate


class GrantorBackend(BaseBackend):
    """Authenticate from verified ID-token claims.

    The claims handed here have already been verified against the issuer's
    JWKS by the callback view. This backend does no cryptography — it maps a
    verified identity onto a local record, and that is all.
    """

    def authenticate(  # type: ignore[override]
        self,
        request: Any,
        *,
        grantor_claims: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> Any | None:
        if not grantor_claims:
            return None

        sub = str(grantor_claims.get("sub") or "")
        if not sub:
            return None

        user = find_by_subject(sub)
        if user is None:
            user = link_by_verified_email(grantor_claims, sub)
        if user is None and conf.get("GRANTOR_CREATE_UNKNOWN_USERS"):
            user = self.create_user(grantor_claims, sub)
        if user is None:
            return None
        return user if self.user_can_authenticate(user) else None

    def create_user(self, claims: Mapping[str, Any], sub: str) -> Any:
        """Provision a person this project has never seen.

        Off by default. When a project turns it on, being able to present an
        ID token this issuer signed *is* the authorization to have an
        account — the tenant's own signup policy is what gates who can get
        such a token in the first place.

        Override this to control what a new record looks like; the default
        sets an unusable password, because a person who arrives through the
        issuer has no local credential and should never acquire one silently.
        """
        User = get_user_model()
        fields: dict[str, Any] = {}
        username_field = getattr(User, "USERNAME_FIELD", "username")
        fields[username_field] = claims.get("email") or sub
        if "email" in [f.name for f in User._meta.get_fields()] and claims.get("email"):
            fields["email"] = claims["email"]
        user = User(**fields)
        user.set_unusable_password()
        target = _set_subject(user, sub)
        user.save()
        if target is not user:
            target.save()
        logger.info("grantor: account provisioned, sub %s", sub)
        return user

    def get_user(self, user_id: Any) -> Any | None:
        return _user_queryset().filter(pk=user_id).first()

    def user_can_authenticate(self, user: Any) -> bool:
        return getattr(user, "is_active", True)
