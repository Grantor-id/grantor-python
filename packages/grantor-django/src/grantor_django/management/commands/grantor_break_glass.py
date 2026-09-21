"""The way back in when the issuer cannot let you in.

This product has an incident on record in which enforcing a second factor
locked out the only enrolled account. An auth library that ships no way back
is arranging for that to happen again — so there is a way back, it is
deliberate, it is loud, and it is not a secret.

    manage.py grantor_break_glass ada@example.com --i-understand

**It grants two things, and both are needed.** A usable local password,
which nothing else in this library ever does — and `is_staff`, because
Django's own `AdminAuthenticationForm` refuses a non-staff user *before* it
looks at the password. An admin installed as designed has no staff rows at
all: privilege arrives from a Grantor role at sign-in, so a deployment whose
issuer is refusing everybody has nobody who can reach the form. Handing out
a password without `is_staff` opens nothing, which is what this command did
until somebody tried it in that exact state.

It does **not** grant `is_superuser`, and does not touch the Grantor role.
Staff is enough to reach the form and is the smaller credential to have
created under duress.

The password only works once ``GRANTOR_ADMIN_BREAK_GLASS = True`` is also
set — two deliberate acts, so neither one alone opens the door.

    manage.py grantor_break_glass ada@example.com --close

undoes **both** grants: the password becomes unusable again and `is_staff`
goes back off. Run it. It is the step people forget, because by the time
they could run it the thing they were panicking about is working — and a
`--close` that left a staff row behind would leave a standing admin account
on a surface whose whole security argument is that no such account exists.

Revoking `is_staff` is safe to do bluntly: this admin re-derives it from the
Grantor role on **every** sign-in, so the next normal sign-in restores it.
"""

from __future__ import annotations

from typing import Any

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.utils.crypto import get_random_string

from grantor_django.admin import BREAK_GLASS_SETTING


class Command(BaseCommand):
    help = "Open or close a temporary local way into the admin."

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument("identifier", help="username or email of the account")
        parser.add_argument(
            "--i-understand",
            action="store_true",
            help=(
                "required: acknowledges that this creates a local credential on a "
                "surface that is designed not to have one"
            ),
        )
        parser.add_argument(
            "--create",
            action="store_true",
            help=(
                "also create the account if no row matches. Only useful when the "
                "admin has never been signed into, so there is nobody to unlock"
            ),
        )
        parser.add_argument(
            "--close",
            action="store_true",
            help="undo it — remove the password and revoke is_staff",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        User = get_user_model()
        identifier = options["identifier"]
        username_field = getattr(User, "USERNAME_FIELD", "username")

        user = (
            User._default_manager.filter(**{username_field: identifier}).first()
            or User._default_manager.filter(email__iexact=identifier).first()
        )

        if options["close"]:
            if user is None:
                raise CommandError(f"no account matches {identifier!r}")
            self._close(user, identifier)
            return

        if not options["i_understand"]:
            raise CommandError(
                "refusing without --i-understand. This creates a local password on a "
                "surface designed to have none, and it is the thing an attacker most "
                "wants you to have left enabled."
            )

        if user is None:
            if not options["create"]:
                # Erroring is right; erroring uselessly is not. An admin that
                # has never been signed into has no rows at all, and that is
                # precisely a state somebody might be locked out in.
                raise CommandError(
                    f"no account matches {identifier!r}. If the admin has never been "
                    f"signed into there is nobody to unlock — pass --create to make "
                    f"one. Creating an admin account is not something this command "
                    f"will do unless you ask for it."
                )
            user = User(**{username_field: identifier})
            if hasattr(user, "email") and "@" in identifier:
                user.email = identifier

        self._open(user, identifier)

    def _open(self, user: Any, identifier: str) -> None:
        from django.conf import settings

        password = get_random_string(24)
        user.set_password(password)
        # Both of these, and this is the whole fix: Django's admin login form
        # rejects a non-staff or inactive user before the password is read.
        user.is_staff = True
        user.is_active = True
        user.save()

        self.stdout.write(self.style.WARNING("BREAK GLASS"))
        self.stdout.write("")
        self.stdout.write(f"  account:  {identifier}")
        self.stdout.write(f"  password: {password}")
        self.stdout.write("")
        self.stdout.write("Granted: a usable password, and is_staff so the form will")
        self.stdout.write("accept it. NOT is_superuser.")
        self.stdout.write("")
        self.stdout.write("This BYPASSES the Grantor role check. Nothing about signing in")
        self.stdout.write("this way consults the issuer — which is the point, because the")
        self.stdout.write("issuer is what is broken when you need this, and also exactly")
        self.stdout.write("why the window has to be closed rather than left open once it")
        self.stdout.write("is working.")
        self.stdout.write("")

        backends = list(getattr(settings, "AUTHENTICATION_BACKENDS", []))
        if not any("ModelBackend" in b for b in backends):
            # A project following this admin's doctrine to the letter omits
            # ModelBackend — and then no password authenticates at all.
            self.stdout.write(self.style.ERROR("ModelBackend is NOT installed."))
            self.stdout.write("Without it no password can authenticate, so the above will")
            self.stdout.write("not let anybody in. Add it, temporarily, alongside:")
            self.stdout.write('  "django.contrib.auth.backends.ModelBackend"')
            self.stdout.write("in AUTHENTICATION_BACKENDS, and remove it when you close.")
            self.stdout.write("")
        self.stdout.write("It does not work yet. Also set, and redeploy:")
        self.stdout.write(f"  {BREAK_GLASS_SETTING} = True")
        self.stdout.write("")
        self.stdout.write("That is a Django setting, not an environment variable. If you")
        self.stdout.write("keep configuration in env, the project has to read it across —")
        self.stdout.write(
            f'  {BREAK_GLASS_SETTING} = env.bool("{BREAK_GLASS_SETTING}", default=False)'
        )
        self.stdout.write("Setting the variable alone changes nothing this library can see.")
        self.stdout.write("")
        self.stdout.write("When you are back in, in this order:")
        self.stdout.write(f"  1. manage.py grantor_break_glass {identifier} --close")
        self.stdout.write(f"  2. {BREAK_GLASS_SETTING} = False, and redeploy")
        self.stdout.write("  3. In the issuer's audit trail, read the whole window.")
        self.stdout.write(
            "     A break-glass sign-in does NOT appear there — so anything that does "
            "was somebody signing in normally, and"
        )
        self.stdout.write(
            "     anything that happened with no sign-in behind it was this password."
        )

    def _close(self, user: Any, identifier: str) -> None:
        user.set_unusable_password()
        # Both grants, undone. Blunt on purpose: this admin re-derives
        # `is_staff` from the Grantor role on every sign-in, so a person who
        # should have it gets it back the next time they sign in normally.
        user.is_staff = False
        user.save()

        self.stdout.write(
            self.style.SUCCESS(
                f"{identifier}: local password removed and is_staff revoked. "
                f"Set {BREAK_GLASS_SETTING} = False and redeploy."
            )
        )
        self.stdout.write(
            "is_staff comes back on this person's next normal sign-in, from their Grantor role."
        )
