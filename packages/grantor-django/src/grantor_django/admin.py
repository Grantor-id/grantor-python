"""A Django admin with no local password at all.

The third integration shape, and the one with the sharpest security
argument. The admin is a privileged surface on a public host, so it has no
local password path: ``ModelBackend`` need not be installed, admin users are
created with an unusable password, and the only way in is the authorization
code flow. There is nothing to brute-force and no credential to leak,
because none exists on this side.

Django's login form is **replaced**, not hidden. A hidden form is a form
somebody finds.

    from grantor_django.admin import GrantorAdminSite

    site = GrantorAdminSite(name="admin")

    GRANTOR_ADMIN_CLIENT_ID = env("GRANTOR_ADMIN_CLIENT_ID")
    GRANTOR_ADMIN_CLIENT_SECRET = env("GRANTOR_ADMIN_CLIENT_SECRET")
    GRANTOR_ADMIN_ROLE = "superadmin"

Privilege comes from a Grantor role and is **re-read on every sign-in,
including off**. Revoking the role at the issuer takes effect the next time
the person authenticates, rather than whenever somebody remembers to untick
a box in a database.
"""

from __future__ import annotations

import logging
import secrets
from dataclasses import asdict
from typing import Any

from django.conf import settings
from django.contrib.admin import AdminSite
from django.contrib.auth import get_user_model
from django.contrib.auth import login as django_login
from django.contrib.auth import logout as django_logout
from django.core import signing
from django.core.exceptions import ImproperlyConfigured, PermissionDenied
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.urls import path, reverse
from grantor import GrantorClient, GrantorError, ProtocolError, TokenError, parse_redirect_error

from . import conf, transaction
from .views import relative_path_only

__all__ = ["GrantorAdminSite", "user_for_claims", "admin_client", "BREAK_GLASS_SETTING"]

logger = logging.getLogger("grantor_django.admin")

BREAK_GLASS_SETTING = "GRANTOR_ADMIN_BREAK_GLASS"

# Its own cookie, so an admin sign-in and an application sign-in in the same
# browser cannot overwrite each other's transaction.
_TXN_COOKIE = "grantor_admin_txn"


def _required(name: str) -> str:
    value = getattr(settings, name, None)
    if not value or not isinstance(value, str):
        raise ImproperlyConfigured(
            f"{name} must be set to use the Grantor admin. The admin is a separate "
            "OAuth client from the application's: it asks for the `roles` scope and "
            "its own redirect URI, and sharing one client between the two would mean "
            "a token for the application is a token for the admin."
        )
    return value


def admin_client() -> GrantorClient:
    """The admin's own client — deliberately not the application's."""
    return GrantorClient(
        conf.issuer(),
        http=conf.http_client(),
        client_id=_required("GRANTOR_ADMIN_CLIENT_ID"),
        client_secret=_required("GRANTOR_ADMIN_CLIENT_SECRET"),
        # `roles` is the whole point: it is what says whether this person may
        # be here at all.
        scope="openid profile email roles",
        auth_method=conf.get("GRANTOR_AUTH_METHOD"),
        timeout=conf.get("GRANTOR_TIMEOUT"),
    )


def user_for_claims(claims: dict[str, Any]) -> Any:
    """Map a Grantor identity onto an admin user, or refuse.

    Both flags are set from the role on **every** sign-in, including to
    ``False``. A person whose role was revoked at the issuer loses the admin
    the next time they authenticate — and the record here says so, rather
    than keeping a stale ``is_superuser`` that some other surface might one
    day believe.
    """
    required_role = getattr(settings, "GRANTOR_ADMIN_ROLE", "superadmin")
    roles = claims.get("roles") or []
    holds_it = isinstance(roles, (list, tuple)) and required_role in roles

    User = get_user_model()
    username_field = getattr(User, "USERNAME_FIELD", "username")
    user = User._default_manager.filter(**{username_field: claims["sub"]}).first()

    if user is None:
        # A person being refused leaves no record behind. Creating one would
        # let anybody who can reach the issuer populate this table, and a row
        # in a table called `user` on an admin surface reads like an account
        # whether or not its flags say otherwise.
        if not holds_it:
            _refuse(claims, required_role)
        user = User(**{username_field: claims["sub"], "email": claims.get("email", "")})
        # No password path exists on this side, so there is nothing to guess.
        user.set_unusable_password()

    if claims.get("email"):
        user.email = claims["email"]
    user.is_active = True
    user.is_staff = holds_it
    user.is_superuser = holds_it
    user.save()

    if not holds_it:
        # An account that already exists is told the truth even as it is
        # turned away: never creating and never updating are different
        # rules, and only the first one is right.
        _refuse(claims, required_role)
    return user


def _refuse(claims: dict[str, Any], required_role: str) -> None:
    logger.warning(
        "grantor admin: refused sub %s — the %s role is required",
        claims.get("sub"),
        required_role,
    )
    raise PermissionDenied(f"the {required_role} role is required to use this admin")


class GrantorAdminSite(AdminSite):
    """An admin whose login view is a redirect to the issuer."""

    def get_urls(self) -> list[Any]:
        return [
            path("grantor/callback", self.grantor_callback, name="grantor_callback"),
            *super().get_urls(),
        ]

    def _redirect_uri(self, request: HttpRequest) -> str:
        return request.build_absolute_uri(reverse(f"{self.name}:grantor_callback"))

    def login(self, request: HttpRequest, extra_context: Any = None) -> HttpResponse:
        """No password form. Straight to the issuer.

        Unless break-glass is on — see :meth:`_break_glass_login`, and read
        its docstring before turning it on.
        """
        if getattr(settings, BREAK_GLASS_SETTING, False):
            return self._break_glass_login(request, extra_context)

        # Same guard the session views use. Unvalidated, this sends the
        # browser off-site **after a successful sign-in** — the moment a
        # person is most likely to trust what they are looking at, on the
        # most privileged surface the product has. The library already had
        # `relative_path_only`; this path simply was not using it.
        next_url = relative_path_only(request.GET.get("next"), reverse(f"{self.name}:index"))
        try:
            authorization = admin_client().start_authorization(
                redirect_uri=self._redirect_uri(request)
            )
        except GrantorError as exc:
            raise PermissionDenied("the issuer is unreachable") from exc

        response = HttpResponseRedirect(authorization.url)
        _issue_txn(
            response,
            transaction.Transaction(
                state=authorization.state,
                code_verifier=authorization.code_verifier,
                nonce=authorization.nonce,
                next_url=next_url,
            ),
        )
        return response

    def _break_glass_login(self, request: HttpRequest, extra_context: Any = None) -> HttpResponse:
        """Django's password form, back, on purpose. **This is dangerous.**

        It exists because this product has an incident on record where
        enforcing a second factor locked out the only enrolled account, and
        an auth library that ships no way back is repeating it. It is still
        the thing an attacker most wants you to have left on.

        Turning it on requires two deliberate acts, not one: setting
        ``GRANTOR_ADMIN_BREAK_GLASS = True`` **and** giving somebody a usable
        password *and* ``is_staff``, which no normal path in this library
        ever does (``manage.py grantor_break_glass`` is the supported way,
        and it says the same things this docstring does).

        ``GRANTOR_ADMIN_BREAK_GLASS`` is a **Django setting, not an
        environment variable**. A project that keeps configuration in the
        environment has to read it across itself::

            GRANTOR_ADMIN_BREAK_GLASS = env.bool(
                "GRANTOR_ADMIN_BREAK_GLASS", default=False
            )

        Setting the variable alone changes nothing this library can see. A
        consumer set it, force-deployed, and the admin went on redirecting
        to the issuer — which reads as the break-glass being broken rather
        than as never having been switched on.

        And it needs ``ModelBackend`` in ``AUTHENTICATION_BACKENDS``. A
        project following this module's own advice does not install it, and
        then no password authenticates at all.

        Afterwards, in the audit trail at the issuer, check:

        * every admin sign-in during the window — break-glass sign-ins do
          **not** appear there, so anything that does was a normal sign-in
          and anything that happened without one was not;
        * the local ``last_login`` of the account you gave a password to;
        * that the password was removed **and ``is_staff`` revoked** and the
          setting turned back off — the step people forget, because by then
          it is working again. A close that leaves a staff row behind leaves
          a standing admin account on a surface whose whole argument is that
          none exists.

        Note what this path does **not** do: it does not consult the issuer
        at all, so the Grantor role check is bypassed rather than merely
        deferred. That is the point — the role check is what is broken when
        you need this — and it is the reason the window is closed rather
        than left open because it is working.
        """
        logger.error(
            "grantor admin: BREAK GLASS is enabled — the admin is accepting local "
            "passwords. Turn %s off once you are back in.",
            BREAK_GLASS_SETTING,
        )
        return super().login(request, extra_context)

    def logout(self, request: HttpRequest, extra_context: Any = None) -> HttpResponse:
        """End the local session, then the issuer's.

        In that order. Somebody who signs out of an admin and is silently
        signed back in by a session they were never shown has been told
        something untrue — and on this surface, that is a privileged session
        they believe is closed.
        """
        id_token = request.COOKIES.get(conf.get("GRANTOR_ID_TOKEN_COOKIE_NAME"), "")
        django_logout(request)

        destination = reverse(f"{self.name}:index")
        if id_token:
            try:
                destination = admin_client().end_session_url(
                    id_token,
                    post_logout_redirect_uri=conf.get("GRANTOR_POST_LOGOUT_REDIRECT_URI"),
                )
            except GrantorError:
                logger.warning(
                    "grantor admin: could not build the end-session URL; signed out locally"
                )

        response = HttpResponseRedirect(destination)
        response.delete_cookie(conf.get("GRANTOR_ID_TOKEN_COOKIE_NAME"), path="/")
        return response

    def grantor_callback(self, request: HttpRequest) -> HttpResponse:
        refusal = parse_redirect_error(request.GET)
        if refusal:
            # Surfaced rather than retried. A retry loop against a refusal is
            # how somebody ends up watching a redirect that never settles.
            raise PermissionDenied(f"the issuer refused the sign-in: {refusal}")

        try:
            txn = _read_txn(request)
        except transaction.InvalidTransaction as exc:
            raise PermissionDenied("this sign-in expired; start again") from exc

        if not secrets.compare_digest(request.GET.get("state", ""), txn.state):
            raise PermissionDenied("state mismatch")

        client = admin_client()
        try:
            tokens = client.exchange_code(
                request.GET.get("code", ""),
                redirect_uri=self._redirect_uri(request),
                code_verifier=txn.code_verifier,
            )
        except ProtocolError as exc:
            # Logged as well as raised. Django renders PermissionDenied as a
            # bare 403 page with no detail — correct for a browser, useless
            # for whoever has to work out why the admin stopped letting
            # people in. The code is safe to log and is the whole diagnosis.
            logger.warning("grantor admin: token exchange refused: %s", exc.code)
            raise PermissionDenied(
                f"the issuer refused the authorization code: {exc.code}"
            ) from exc
        except GrantorError as exc:
            raise PermissionDenied("the issuer is unreachable") from exc

        if not tokens.id_token:
            raise PermissionDenied("the issuer returned no ID token")
        try:
            claims = client.verify_id_token(tokens.id_token, nonce=txn.nonce)
        except TokenError as exc:
            logger.warning("grantor admin: id token rejected: %s", exc.reason)
            raise PermissionDenied(f"the ID token was rejected: {exc.reason}") from exc

        user = user_for_claims(claims)
        django_login(request, user, backend="django.contrib.auth.backends.ModelBackend")

        response = HttpResponseRedirect(txn.next_url or reverse(f"{self.name}:index"))
        _clear_txn(response)
        response.set_cookie(
            conf.get("GRANTOR_ID_TOKEN_COOKIE_NAME"),
            tokens.id_token,
            httponly=True,
            secure=conf.cookie_secure(),
            samesite=conf.cookie_samesite(),
            path="/",
        )
        return response


def _issue_txn(response: HttpResponse, txn: transaction.Transaction) -> None:
    response.set_cookie(
        _TXN_COOKIE,
        signing.dumps(asdict(txn), salt=transaction.SALT),
        max_age=conf.get("GRANTOR_TXN_MAX_AGE"),
        httponly=True,
        secure=conf.cookie_secure(),
        samesite=conf.cookie_samesite(),
        path="/",
    )


def _read_txn(request: HttpRequest) -> transaction.Transaction:
    raw = request.COOKIES.get(_TXN_COOKIE, "")
    if not raw:
        raise transaction.InvalidTransaction("no transaction cookie")
    try:
        payload = signing.loads(raw, salt=transaction.SALT, max_age=conf.get("GRANTOR_TXN_MAX_AGE"))
    except signing.BadSignature as exc:
        raise transaction.InvalidTransaction("bad or expired transaction") from exc
    return transaction.Transaction(**payload)


def _clear_txn(response: HttpResponse) -> None:
    response.delete_cookie(_TXN_COOKIE, path="/")
