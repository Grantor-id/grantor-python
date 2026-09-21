"""The three views: start, callback, sign out.

Not DRF views and not part of any API contract — the caller is a browser
navigating, and the answer is a redirect. They are deliberately boring: the
protocol lives in :mod:`grantor`, and what is left here is Django.

Every failure ends the same way: the transaction cookie is deleted, and the
browser is redirected with ``?grantor_error=<code>`` from a small vocabulary.
No claim, no token and no part of either ever travels with it.
"""

from __future__ import annotations

import logging
import secrets
from typing import Any

from django.contrib.auth import authenticate, login, logout
from django.http import Http404, HttpRequest, HttpResponse, HttpResponseRedirect
from django.urls import NoReverseMatch, reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.utils.module_loading import import_string
from django.views.decorators.http import require_GET, require_POST
from grantor import (
    DiscoveryError,
    GrantorError,
    ProtocolError,
    TokenError,
    parse_redirect_error,
)

from . import conf, transaction
from .client import get_client

__all__ = [
    "start",
    "callback",
    "sign_out",
    "safe_next",
    "relative_path_only",
    "establish_session",
]

logger = logging.getLogger("grantor_django")

# The vocabulary a caller may render. Every value is safe to show a person
# and says nothing an attacker did not already know.
ERROR_DENIED = "denied"
ERROR_EXPIRED = "expired"
ERROR_ISSUER = "issuer_error"
ERROR_NO_ACCOUNT = "account_not_found"
ERROR_EXCHANGE = "exchange_failed"


def relative_path_only(raw: str | None, fallback: str) -> str:
    """A path on some site, and nothing that could name a different one.

    Must start with ``/``, must not start with ``//`` (that is
    scheme-relative and goes wherever it likes), and must contain no
    backslash — browsers normalize ``\\`` to ``/``, so a check that only
    looks for ``//`` misses ``/\\evil.example.com``.
    """
    if not raw or not raw.startswith("/") or raw.startswith("//") or "\\" in raw:
        return fallback
    return raw


def _require_enabled() -> None:
    """404 while the integration is switched off.

    Not 500 and not a redirect: a route that has not been enabled does not
    exist yet, and saying so is both the truthful answer and the one that
    tells a scanner nothing.
    """
    if not conf.get("GRANTOR_ENABLED"):
        raise Http404("the Grantor integration is not enabled")


def safe_next(request: HttpRequest, raw: str | None, fallback: str) -> str:
    """Where this person may be sent after signing in.

    An unchecked ``?next=`` is an open redirect, and an open redirect on a
    login endpoint is a phishing page hosted on your own domain — the URL
    the person checks is genuinely yours right up to the moment it is not.

    Two shapes. Without ``GRANTOR_FRONTEND_BASE_URL`` the destination must
    be on this host. With it, the browser application is somewhere else on
    purpose, so the destination is a **path** resolved against that one base
    — which is a narrower promise than "same host", not a looser one: no
    value of ``next`` can name a host at all.
    """
    base = conf.get("GRANTOR_FRONTEND_BASE_URL")
    if base:
        return base.rstrip("/") + relative_path_only(raw, fallback)
    if raw and url_has_allowed_host_and_scheme(
        raw, allowed_hosts={request.get_host()}, require_https=request.is_secure()
    ):
        return raw
    return fallback


def _error_redirect(code: str) -> HttpResponse:
    target = conf.get("GRANTOR_ERROR_REDIRECT_URL") or conf.get("GRANTOR_LOGIN_REDIRECT_URL")
    base = conf.get("GRANTOR_FRONTEND_BASE_URL")
    if base:
        target = base.rstrip("/") + relative_path_only(target, "/")
    separator = "&" if "?" in target else "?"
    param = conf.get("GRANTOR_ERROR_PARAM")
    response = HttpResponseRedirect(f"{target}{separator}{param}={code}")
    transaction.clear(response)
    return response


def establish_session(request: HttpRequest, response: HttpResponse, user: Any, tokens: Any) -> None:
    """Remember that this person is signed in.

    Django's session by default. ``GRANTOR_ESTABLISH_SESSION`` replaces it
    for a project with its own scheme — a JWT cookie pair for an SPA, say.
    It receives the response as well as the request, so a replacement can
    set cookies on the way out, and the issuer's tokens, so it can keep
    whichever of them it needs.
    """
    path = conf.get("GRANTOR_ESTABLISH_SESSION")
    if path:
        import_string(path)(request, response, user, tokens)
        return
    login(request, user)


@require_GET
def start(request: HttpRequest) -> HttpResponse:
    """Send the browser to the issuer, remembering what must come back."""
    _require_enabled()
    next_url = safe_next(
        request,
        request.GET.get(conf.get("GRANTOR_NEXT_PARAM")),
        conf.get("GRANTOR_LOGIN_REDIRECT_URL"),
    )
    try:
        authorization = get_client().start_authorization()
    except (DiscoveryError, ProtocolError):
        # The issuer being unreachable is not the person's fault and there
        # is nothing for them to do about it, so they get one word.
        logger.warning("grantor: could not start a sign-in; the issuer is unreachable")
        return _error_redirect(ERROR_ISSUER)

    response = HttpResponseRedirect(authorization.url)
    transaction.issue(
        response,
        transaction.Transaction(
            state=authorization.state,
            code_verifier=authorization.code_verifier,
            nonce=authorization.nonce,
            next_url=next_url,
        ),
    )
    return response


@require_GET
def callback(request: HttpRequest) -> HttpResponse:  # noqa: PLR0911 - one return per refusal
    """Where the issuer's redirect lands."""
    _require_enabled()
    redirect_error = parse_redirect_error(request.GET)
    if redirect_error:
        return _error_redirect(ERROR_DENIED if redirect_error == "access_denied" else ERROR_ISSUER)

    try:
        txn = transaction.read(request)
    except transaction.InvalidTransaction:
        return _error_redirect(ERROR_EXPIRED)

    # Constant-time, and compared against the cookie rather than a session
    # key: `state` is the issuer's correlation value, not our storage key.
    if not secrets.compare_digest(request.GET.get("state", ""), txn.state):
        return _error_redirect(ERROR_EXPIRED)

    client = get_client()
    try:
        tokens = client.exchange_code(request.GET.get("code", ""), code_verifier=txn.code_verifier)
    except ProtocolError as exc:
        # The issuer's specific code goes to the log, not the query string.
        # What lands in the URL is read by a front end that has to render
        # copy for it, and an unbounded vocabulary cannot be rendered — so
        # the browser gets one stable word and the operator gets the detail.
        logger.warning("grantor: token exchange refused: %s", exc.code)
        return _error_redirect(ERROR_EXCHANGE)
    except GrantorError:
        return _error_redirect(ERROR_ISSUER)

    if not tokens.id_token:
        return _error_redirect(ERROR_ISSUER)

    try:
        claims: dict[str, Any] = client.verify_id_token(tokens.id_token, nonce=txn.nonce)
    except TokenError as exc:
        logger.warning("grantor: id token rejected: %s", exc.reason)
        return _error_redirect(ERROR_ISSUER)
    except GrantorError:
        return _error_redirect(ERROR_ISSUER)

    if not claims.get("email"):
        # The scope may not have granted `email`, or the issuer may not hold
        # one. Userinfo is the fresh-claims path; the verified ID token
        # still wins wherever the two overlap.
        try:
            claims = {**client.fetch_userinfo(tokens.access_token), **claims}
        except GrantorError:
            pass

    user = authenticate(request, grantor_claims=claims)
    if user is None:
        logger.info("grantor: no local account for sub %s", claims.get("sub"))
        return _error_redirect(ERROR_NO_ACCOUNT)

    response = HttpResponseRedirect(txn.next_url)
    transaction.clear(response)
    _keep_id_token(response, tokens.id_token)
    establish_session(request, response, user, tokens)
    return response


@require_POST
def sign_out(request: HttpRequest) -> HttpResponse:
    """End the local session first, then the issuer's.

    In that order, always. A failure at the issuer then still leaves the
    person signed out here, which is the half this application is
    responsible for. The reverse order has a failure mode where somebody
    clicks "sign out", something goes wrong, and they remain signed in —
    having been told otherwise.

    And it really does go to the issuer. Somebody who signs out and is
    silently signed back in by a shared session they were never shown has
    been told something untrue.
    """
    id_token = request.COOKIES.get(conf.get("GRANTOR_ID_TOKEN_COOKIE_NAME"), "")
    logout(request)

    destination = conf.get("GRANTOR_LOGOUT_REDIRECT_URL")
    if id_token:
        try:
            destination = get_client().end_session_url(
                id_token,
                post_logout_redirect_uri=conf.get("GRANTOR_POST_LOGOUT_REDIRECT_URI"),
            )
        except GrantorError:
            # Local sign-out must never fail because of the issuer.
            logger.warning("grantor: could not build the end-session URL; signing out locally")

    response = HttpResponseRedirect(destination)
    response.delete_cookie(conf.get("GRANTOR_ID_TOKEN_COOKIE_NAME"), path="/")
    return response


def _keep_id_token(response: HttpResponse, id_token: str) -> None:
    """Hold the last ID token, for one purpose only: the sign-out hint.

    It is what proves which application is asking to end a session, and
    therefore what the post-logout redirect is validated against. Without it
    the browser is not redirected at all. ``httponly`` because nothing in
    the page has any business reading it.
    """
    response.set_cookie(
        conf.get("GRANTOR_ID_TOKEN_COOKIE_NAME"),
        id_token,
        httponly=True,
        secure=conf.cookie_secure(),
        samesite="Lax",
        path="/",
    )


def _reverse(name: str) -> str:
    try:
        return reverse(f"grantor_django:{name}")
    except NoReverseMatch:  # pragma: no cover - only when urls are not included
        return "/"
