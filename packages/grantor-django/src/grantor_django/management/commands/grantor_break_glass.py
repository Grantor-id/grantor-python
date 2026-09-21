"""The way back in when the issuer cannot let you in.

This product has an incident on record in which enforcing a second factor
locked out the only enrolled account. An auth library that ships no way back
is arranging for that to happen again — so there is a way back, it is
deliberate, it is loud, and it is not a secret.

    manage.py grantor_break_glass ada@example.com --i-understand

What it does is the whole of it: it gives one account a usable local
password, which nothing else in this library ever does. It does not grant
the role, it does not bypass the role check, and it does not touch the
issuer. The password only works once ``GRANTOR_ADMIN_BREAK_GLASS = True`` is
also set — two deliberate acts, so neither one alone opens the door.

    manage.py grantor_break_glass ada@example.com --close

undoes it: the password becomes unusable again. Run it. It is the step
people forget, because by the time they could run it, the thing they were
panicking about is working.
"""

from __future__ import annotations

from typing import Any

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.utils.crypto import get_random_string

from grantor_django.admin import BREAK_GLASS_SETTING


class Command(BaseCommand):
    help = "Give one admin account a temporary local password, or take it away again."

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
            "--close",
            action="store_true",
            help="undo it — make the password unusable again",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        User = get_user_model()
        identifier = options["identifier"]
        username_field = getattr(User, "USERNAME_FIELD", "username")

        user = (
            User._default_manager.filter(**{username_field: identifier}).first()
            or User._default_manager.filter(email__iexact=identifier).first()
        )
        if user is None:
            raise CommandError(f"no account matches {identifier!r}")

        if options["close"]:
            user.set_unusable_password()
            user.save(update_fields=["password"])
            self.stdout.write(
                self.style.SUCCESS(
                    f"{identifier}: local password removed. "
                    f"Set {BREAK_GLASS_SETTING} = False and redeploy."
                )
            )
            return

        if not options["i_understand"]:
            raise CommandError(
                "refusing without --i-understand. This creates a local password on a "
                "surface designed to have none, and it is the thing an attacker most "
                "wants you to have left enabled."
            )

        password = get_random_string(24)
        user.set_password(password)
        user.save(update_fields=["password"])

        self.stdout.write(self.style.WARNING("BREAK GLASS"))
        self.stdout.write("")
        self.stdout.write(f"  account:  {identifier}")
        self.stdout.write(f"  password: {password}")
        self.stdout.write("")
        self.stdout.write("It does not work yet. Also set, and redeploy:")
        self.stdout.write(f"  {BREAK_GLASS_SETTING} = True")
        self.stdout.write("")
        self.stdout.write("The role check still applies: this gets you to the form, not past it.")
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
