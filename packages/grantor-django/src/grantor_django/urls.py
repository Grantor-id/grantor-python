"""The URLs, mounted wherever the project likes.

    urlpatterns = [path("auth/", include("grantor_django.urls"))]

That publishes **three** routes — `sso/start`, `sso/callback` and
`sso/logout`. A project with a sign-out of its own usually wants only the
first two, and there is a supported way to say so:

    from grantor_django.urls import sign_in_urls

    urlpatterns = [path("auth/", include(sign_in_urls))]

**Why an export rather than a note in the documentation.** The namespace is
load-bearing: the redirect URI, the transaction cookie's path and the system
check are all derived from ``reverse("grantor_django:callback")``. A
consumer who assembles their own subset and forgets the namespace gets a
*silently wrong* redirect URI, which the issuer then refuses with
`invalid_redirect_uri` — at the issuer, for a reason nothing on their side
explains. Advice that produces that in the hands of somebody following it
correctly is worse than no advice, so the subset carries its own
``app_name`` and there is nothing to get wrong.

The redirect URI is derived from wherever this lands, so moving the mount
point does not require editing a setting that would otherwise silently
disagree with it.
"""

from __future__ import annotations

from django.urls import path

from . import views

app_name = "grantor_django"

#: `start` and `callback` only — for a project whose sign-out is its own.
#: Dropping `logout` costs nothing else: no code in this package reverses it.
SIGN_IN_PATTERNS = [
    path("sso/start", views.start, name="start"),
    path("sso/callback", views.callback, name="callback"),
]

#: Ready to hand straight to `include()`, namespace included.
sign_in_urls = (SIGN_IN_PATTERNS, app_name)

urlpatterns = [
    *SIGN_IN_PATTERNS,
    path("sso/logout", views.sign_out, name="logout"),
]
