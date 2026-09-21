"""A host project's own models, of the shape a real adopter has.

``sub`` lives on a ``Profile`` the project owns, reached through a setting —
not on a model this library ships. A library that demanded its own user
table would be a library nobody could adopt incrementally, and this test
project exists partly to keep that honest.
"""

from django.conf import settings
from django.db import models


class Profile(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="profile"
    )
    # Blank, not null, so "not linked" is one value rather than two, and a
    # unique constraint can be conditional on it.
    grantor_sub = models.CharField(max_length=255, blank=True, default="")

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["grantor_sub"],
                condition=~models.Q(grantor_sub=""),
                name="unique_linked_grantor_sub",
            )
        ]
