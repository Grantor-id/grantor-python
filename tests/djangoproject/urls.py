"""The mount point, at a path that is not the default, on purpose.

If the redirect URI were assembled from a hardcoded ``/auth/``, this URLconf
would still pass. It is mounted at ``identity/`` so that a test can prove the
URI is derived from the URLconf instead.
"""

from django.http import HttpResponse
from django.urls import include, path

urlpatterns = [
    path("identity/", include("grantor_django.urls")),
    path("", lambda request: HttpResponse("home"), name="home"),
    path("login", lambda request: HttpResponse("login"), name="login"),
]
