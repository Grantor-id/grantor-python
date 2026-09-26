"""What this project considers a real person.

Pointed at by `GRANTOR_USER_QUERYSET` in the tests that need it. A project
with soft-deleted profiles has to say so once, here, rather than hoping
every lookup in the library happens to go through a manager.
"""

from django.contrib.auth import get_user_model


def live_users():
    return get_user_model()._default_manager.filter(profile__deleted_at__isnull=True)


def every_user():
    """A stated answer that is simply everybody, to force the join route."""
    return get_user_model()._default_manager.all()
