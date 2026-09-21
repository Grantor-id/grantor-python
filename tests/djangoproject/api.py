"""A small DRF API, of the three shapes an adopter actually writes.

One that only needs a valid token, one gated on a scope, one gated on a
role. They exist so the resource-server half is exercised through a real
request cycle rather than by calling the authentication class directly —
DRF's own handling of 401 versus 403, and of `authenticate_header`, is part
of what this library has to get right.
"""

from grantor_django.drf import HasGrantorRole, HasGrantorScope, roles_of
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView


class WhoAmI(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Roles come off `request.auth` — the verified claims — not off
        # `request.user`, which may be a local model this library has never
        # heard of. The same idiom works whichever principal is in use.
        return Response({"sub": str(request.user), "roles": list(roles_of(request.auth))})


class Things(APIView):
    permission_classes = [IsAuthenticated, HasGrantorScope("things:write")]

    def post(self, request):
        return Response({"written": True})


class AdminOnly(APIView):
    permission_classes = [IsAuthenticated, HasGrantorRole("admin")]

    def get(self, request):
        return Response({"ok": True})
