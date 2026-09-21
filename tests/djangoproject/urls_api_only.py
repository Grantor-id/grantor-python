"""The URLconf of a consumer that is only a resource server.

No `grantor_django.urls`, because it has no sign-in of its own — every
request arrives with a token somebody else minted. It exists so the system
check can be proven not to demand a callback URL from a project that has no
callback, which is the shape of a real consumer.
"""

from django.urls import path

from djangoproject import api

urlpatterns = [
    path("api/whoami", api.WhoAmI.as_view(), name="whoami"),
]
