"""The admin, behind Grantor.

Three lines, which is the claim the library makes and therefore the claim
that has to be true in a project that runs.
"""

from grantor_django.admin import GrantorAdminSite

site = GrantorAdminSite(name="admin")
