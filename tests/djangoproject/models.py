"""A host project's own models, of the shape a real adopter has.

``sub`` lives on a ``Profile`` the project owns, reached through a setting —
not on a model this library ships. A library that demanded its own user
table would be a library nobody could adopt incrementally, and this test
project exists partly to keep that honest.
"""

from django.conf import settings
from django.db import models


class LiveProfileManager(models.Manager):
    """A consumer-shaped manager: soft-deleted rows are not rows.

    This is not a toy. It is the shape the second consumer's `Profile` has,
    and it is what exposed the join bug — a related-field lookup reads this
    table directly and never runs this manager.
    """

    def get_queryset(self):
        return super().get_queryset().filter(deleted_at__isnull=True)


class Profile(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="profile"
    )
    # Blank, not null, so "not linked" is one value rather than two, and a
    # unique constraint can be conditional on it.
    grantor_sub = models.CharField(max_length=255, blank=True, default="")
    deleted_at = models.DateTimeField(null=True, blank=True)
    # `auto_now`, so the linking timestamp is only correct if the library
    # saves the row rather than naming columns with `update_fields`.
    updated_at = models.DateTimeField(auto_now=True)

    objects = LiveProfileManager()
    all_objects = models.Manager()

    class Meta:
        constraints = [
            # Conditional on **live** rows, like the consumer's. A deleted
            # row keeps its `sub`, so the same subject can be linked again
            # — which is precisely the two-accounts-one-subject state the
            # join bug made reachable.
            models.UniqueConstraint(
                fields=["grantor_sub"],
                condition=models.Q(deleted_at__isnull=True) & ~models.Q(grantor_sub=""),
                name="unique_live_linked_grantor_sub",
            )
        ]
