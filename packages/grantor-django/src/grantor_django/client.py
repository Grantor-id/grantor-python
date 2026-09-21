"""Building a :class:`grantor.GrantorClient` out of Django settings.

The one place the framework half touches the core's constructor. Everything
else in this package composes the core's public functions.
"""

from __future__ import annotations

from django.urls import reverse
from grantor import GrantorClient

from . import conf

__all__ = ["get_client", "callback_url"]


def callback_url() -> str:
    """The redirect URI, derived rather than configured.

    ``GRANTOR_CALLBACK_BASE_URL`` plus wherever ``grantor_django.urls`` was
    actually mounted. A project that moves ``include("grantor_django.urls")``
    from ``auth/`` to ``accounts/`` gets the right URI without editing a
    second setting — and a setting that can disagree with the URLconf is a
    setting that eventually does.

    It must still match a redirect URI registered with the issuer
    **exactly**, trailing slash included; the issuer refuses to bounce a
    browser off an address it could not verify, and that refusal arrives in
    the management envelope with no redirect.
    """
    return conf.callback_base_url() + reverse("grantor_django:callback")


def get_client() -> GrantorClient:
    return GrantorClient(
        conf.issuer(),
        http=conf.http_client(),
        client_id=conf.client_id(),
        client_secret=conf.client_secret(),
        redirect_uri=callback_url(),
        scope=conf.scope(),
        auth_method=conf.get("GRANTOR_AUTH_METHOD"),
        timeout=conf.get("GRANTOR_TIMEOUT"),
    )
