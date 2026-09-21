"""The app, and the check that refuses to boot on a broken configuration.

A missing setting discovered at the first sign-in attempt is discovered by
the wrong person: somebody trying to log in, looking at an error page, with
no way to fix it. Discovered at boot it is a deploy that does not start,
which is the right audience and the right moment.
"""

from __future__ import annotations

from typing import Any

from django.apps import AppConfig
from django.core.checks import Error, register

__all__ = ["GrantorDjangoConfig"]


class GrantorDjangoConfig(AppConfig):
    name = "grantor_django"
    verbose_name = "Grantor"

    def ready(self) -> None:
        register(_check_settings)


def _check_settings(app_configs: Any, **kwargs: Any) -> list[Error]:
    from .conf import check_configuration

    return [
        Error(problem, id=f"grantor_django.E{index:03d}")
        for index, problem in enumerate(check_configuration(), start=1)
    ]
