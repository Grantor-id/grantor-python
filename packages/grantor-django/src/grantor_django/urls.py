"""The URLs, mounted wherever the project likes.

    urlpatterns = [path("auth/", include("grantor_django.urls"))]

The redirect URI is derived from wherever this lands, so moving the mount
point does not require editing a setting that would otherwise silently
disagree with it.
"""

from __future__ import annotations

from django.urls import path

from . import views

app_name = "grantor_django"

urlpatterns = [
    path("sso/start", views.start, name="start"),
    path("sso/callback", views.callback, name="callback"),
    path("sso/logout", views.sign_out, name="logout"),
]
