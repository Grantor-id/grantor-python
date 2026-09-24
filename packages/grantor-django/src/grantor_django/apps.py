"""The app, and the check that refuses to boot on a broken configuration.

A missing setting discovered at the first sign-in attempt is discovered by
the wrong person: somebody trying to log in, looking at an error page, with
no way to fix it. Discovered at boot it is a deploy that does not start,
which is the right audience and the right moment.
"""

from __future__ import annotations

from typing import Any

from django.apps import AppConfig
from django.core.checks import Error, Warning, register

__all__ = ["GrantorDjangoConfig"]


class GrantorDjangoConfig(AppConfig):
    name = "grantor_django"
    verbose_name = "Grantor"

    def ready(self) -> None:
        register(_check_settings)
        register(_check_authentication_backend)
        register(_check_subject_queryset)
        register(_check_subject_manager)


def _check_settings(app_configs: Any, **kwargs: Any) -> list[Error]:
    from .conf import check_configuration

    return [
        Error(problem, id=f"grantor_django.E{index:03d}")
        for index, problem in enumerate(check_configuration(), start=1)
    ]


def _check_authentication_backend(app_configs: Any, **kwargs: Any) -> list[Warning]:
    """Warn when the sign-in views are mounted and nothing can answer them.

    ``GrantorBackend`` is not installed by adding this app. Django keeps
    whatever ``AUTHENTICATION_BACKENDS`` says, and its default says
    ``ModelBackend`` alone — which cannot answer
    ``authenticate(request, grantor_claims=...)`` at all.

    The failure that follows is the expensive kind, because it is
    *plausible*: ``authenticate`` returns ``None``, the callback turns that
    into ``account_not_found``, and the reader is told their user does not
    exist. That is the one explanation that is wrong, and it sends them to
    their database instead of their settings.

    So this fires at boot, where the audience is whoever configured the
    project, rather than at a stranger's first sign-in.

    Quiet unless the project actually mounted the session views: a
    resource-server-only or admin-only install needs no backend, and a
    warning it cannot act on is one it learns to ignore.
    """
    from .conf import _session_login_is_mounted, get

    if not get("GRANTOR_ENABLED") or not _session_login_is_mounted():
        return []

    from django.conf import settings

    backends = list(getattr(settings, "AUTHENTICATION_BACKENDS", []))
    if any(name.endswith("GrantorBackend") for name in backends):
        return []
    return [
        Warning(
            "The Grantor sign-in views are mounted but GrantorBackend is not in "
            "AUTHENTICATION_BACKENDS, so authenticate() has nothing that can answer "
            "them. Every sign-in will be refused as account_not_found, which names "
            "the wrong cause: the account is fine, the backend is missing.",
            hint=(
                'Add "grantor_django.backends.GrantorBackend" to '
                "AUTHENTICATION_BACKENDS. Keep django.contrib.auth.backends."
                "ModelBackend beside it only while this project still has passwords "
                "of its own — removing it closes the password path, including "
                "break-glass."
            ),
            id="grantor_django.W003",
        )
    ]


def _check_subject_queryset(app_configs: Any, **kwargs: Any) -> list[Warning]:
    """Warn when an explicit queryset replaces the safe default.

    When ``sub`` lives on a related model, lookups go through **that
    model's** default manager, so a project with soft-deleted rows is
    correct without configuring anything. Setting
    ``GRANTOR_USER_QUERYSET`` replaces that route entirely — which is the
    point of the setting, and also the one way left to reintroduce the
    defect it was added to close.

    Quiet unless both are true: the subject is behind a relation, and that
    relation's manager excludes rows. A project with a stock manager hears
    nothing, so this does not become noise people learn to ignore.
    """
    from django.db.models import Manager

    from .backends import _subject_relation
    from .conf import get

    path = get("GRANTOR_USER_QUERYSET")
    if not path:
        return []
    rel = _subject_relation()
    if rel is None:
        return []
    model = rel.related_model
    manager = model._default_manager
    if type(manager) is Manager and type(manager) is type(model._base_manager):
        return []
    return [
        Warning(
            f"GRANTOR_USER_QUERYSET ({path}) replaces the default lookup, which would "
            f"otherwise go through {model.__name__}.{manager.__class__.__name__} and honour "
            f"its exclusions. Make sure your queryset excludes the same rows — a queryset "
            f"that joins across the relation reads that table directly and skips the manager.",
            hint=(
                "Remove GRANTOR_USER_QUERYSET to use the default route, which honours "
                f"{model.__name__}'s manager, unless your project needs something else."
            ),
            id="grantor_django.W001",
        )
    ]


def _check_subject_manager(app_configs: Any, **kwargs: Any) -> list[Warning]:
    """Warn when the subject model's filtered manager is not its default.

    The default route is safe **only if the default manager is the filtered
    one**, and that is decided by declaration order:
    ``Model._default_manager`` is whichever manager is declared first,
    unless ``Meta.default_manager_name`` says otherwise. A project that
    declares its unfiltered escape hatch first —

        all_objects = models.Manager()        # declared first: the default
        objects = SoftDeleteManager()

    — gets lookups that read every row, which is the behaviour this
    library shipped as a defect in ``0.1.0a0``. There is no setting to
    blame and nothing in the code to notice, which is why it is worth a
    check: whoever writes the base model is making a security decision
    without being told it is one.

    Fires only on the risky shape: the default manager is a plain
    ``Manager`` **and** some other manager on the model is not. A project
    with no custom manager anywhere has nothing to miss and hears nothing.
    """
    from django.db.models import Manager

    from .backends import _subject_relation
    from .conf import get

    if get("GRANTOR_USER_QUERYSET"):
        # The project stated its own answer; W001 already covers that case.
        return []
    rel = _subject_relation()
    if rel is None:
        return []
    model = rel.related_model
    if type(model._default_manager) is not Manager:
        return []
    custom = sorted(
        f"{m.name} ({type(m).__name__})" for m in model._meta.managers if type(m) is not Manager
    )
    if not custom:
        return []
    return [
        Warning(
            f"{model.__name__} has a custom manager ({', '.join(custom)}) but its default "
            f"manager is a plain Manager, and Grantor resolves `sub` through the default "
            f"one. If the custom manager is what excludes rows — soft deletes, an "
            f"is_active scope, a tenant scope — those rows are in scope here and a deleted "
            f"person can sign in.",
            hint=(
                "Declare the filtering manager first, or set "
                f"Meta.default_manager_name on {model.__name__}, or name an explicit "
                "queryset in GRANTOR_USER_QUERYSET. Django takes the first declared "
                "manager as the default, so the order is the decision."
            ),
            id="grantor_django.W002",
        )
    ]
