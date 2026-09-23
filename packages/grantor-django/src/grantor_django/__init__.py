"""Sign in with Grantor, from Django.

    INSTALLED_APPS = [..., "grantor_django"]

    GRANTOR_ISSUER = "https://acme.api.grantor.id"
    GRANTOR_CLIENT_ID = env("GRANTOR_CLIENT_ID")
    GRANTOR_CLIENT_SECRET = env("GRANTOR_CLIENT_SECRET")
    GRANTOR_CALLBACK_BASE_URL = "https://app.example.com"

    urlpatterns = [path("auth/", include("grantor_django.urls"))]

That is the whole configuration. Every endpoint — authorization, token,
JWKS, end-session — comes from the issuer's discovery document.

The dividing rule between this package and ``grantor``, sharp enough for
review: anything that touches ``settings``, ``request``, ``session``, the
``User`` model, or returns an ``HttpResponse`` belongs here. Everything else
belongs in the core, where a framework this package has never heard of can
compose it.
"""

from __future__ import annotations

__all__ = ["__version__", "default_app_config"]

__version__ = "0.1.2"

# Django ≥3.2 discovers AppConfig automatically; named here for readers.
default_app_config = "grantor_django.apps.GrantorDjangoConfig"
