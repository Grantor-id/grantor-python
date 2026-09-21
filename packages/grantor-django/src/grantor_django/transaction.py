"""The round trip's memory, carried by the browser.

**The secrets travel in a signed, short-TTL cookie, not the session.** This
is deliberate and it was learned the hard way: a person who starts a sign-in
on one node must be able to finish it on another, and ``state`` is not a
session key. A signed cookie is stateless, horizontally safe, and has its
TTL enforced cryptographically rather than by a sweep.

It also avoids the alternative's real cost: a server-side row per anonymous
visitor who merely *starts* a sign-in is a table anybody can fill.

``SameSite`` is ``Lax`` and must stay that way. The callback arrives as a
top-level cross-site redirect from the issuer; ``Strict`` would strip the
cookie and fail every single sign-in, in a way that looks like an expired
transaction rather than a configuration mistake.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from django.core import signing
from django.http import HttpRequest, HttpResponse

from . import conf

__all__ = [
    "Transaction",
    "InvalidTransaction",
    "issue",
    "read",
    "clear",
    "cookie_path",
    "SALT",
]

SALT = "grantor_django.sso.txn"


def cookie_path() -> str:
    """Scope the cookie to where these views are actually mounted.

    Derived rather than configured, and derived rather than left at ``/``:
    this cookie carries a PKCE verifier for ten minutes, and there is no
    reason for it to ride on every request to the rest of the site. A
    project that mounts the library at ``oauth/`` gets ``/oauth/sso``
    without being asked.
    """
    from django.urls import reverse

    try:
        callback = reverse("grantor_django:callback")
    except Exception:
        return "/"
    parent = callback.rsplit("/", 1)[0]
    return parent or "/"


class InvalidTransaction(Exception):
    """Missing, tampered with, or expired.

    All three are the same answer to the person: start again. Telling them
    apart would tell an attacker which of their guesses was closer.
    """


@dataclass(frozen=True)
class Transaction:
    """What must survive the trip to the issuer and back."""

    state: str
    code_verifier: str
    nonce: str
    next_url: str = "/"


def issue(response: HttpResponse, txn: Transaction) -> None:
    """Attach the transaction to a response as a signed cookie."""
    response.set_cookie(
        conf.get("GRANTOR_TXN_COOKIE_NAME"),
        signing.dumps(asdict(txn), salt=SALT),
        max_age=conf.get("GRANTOR_TXN_MAX_AGE"),
        httponly=True,
        secure=conf.cookie_secure(),
        samesite="Lax",
        path=cookie_path(),
    )


def read(request: HttpRequest) -> Transaction:
    """Recover the transaction, or refuse."""
    raw = request.COOKIES.get(conf.get("GRANTOR_TXN_COOKIE_NAME"), "")
    if not raw:
        raise InvalidTransaction("no transaction cookie")
    try:
        payload: Any = signing.loads(raw, salt=SALT, max_age=conf.get("GRANTOR_TXN_MAX_AGE"))
    except signing.BadSignature as exc:  # SignatureExpired subclasses this
        raise InvalidTransaction("bad or expired transaction") from exc
    if not isinstance(payload, dict):
        raise InvalidTransaction("transaction is not a mapping")
    try:
        return Transaction(**payload)
    except TypeError as exc:
        raise InvalidTransaction("transaction is missing a field") from exc


def clear(response: HttpResponse) -> None:
    """Delete the cookie. A transaction is single-use, including on failure."""
    response.delete_cookie(conf.get("GRANTOR_TXN_COOKIE_NAME"), path=cookie_path())
