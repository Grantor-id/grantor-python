"""Failures, and the two shapes the issuer expresses them in.

The error normalization here is the single most valuable thing this package
carries. Of the two hand-rolled implementations it was extracted from, one
understood both shapes and one understood only the RFC shape — and the two
cases the second one could not parse are exactly the two a new integration
hits first.

Nothing in this module ever carries token material. An exception message is
a code and, at most, a reason naming which check failed; codes and
post-verification ``sub`` are the only things any part of this library is
allowed to surface.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol

__all__ = [
    "GrantorError",
    "DiscoveryError",
    "ProtocolError",
    "TokenError",
    "normalize_error",
    "parse_error",
    "parse_redirect_error",
]


class _JsonResponse(Protocol):
    """The part of an HTTP response this module reads.

    A Protocol rather than ``httpx.Response`` so that ``parse_error`` can be
    unit-tested against a plain object, and so an adapter holding some other
    library's response can still use it.
    """

    status_code: int

    def json(self) -> Any: ...


class GrantorError(Exception):
    """Base of everything this library raises."""


class DiscoveryError(GrantorError):
    """The issuer's discovery document could not be fetched or is unusable.

    Includes the case that matters most: a document whose ``issuer`` claim
    does not equal the issuer that was configured. That is the wrong server
    or an attack, never a configuration nit, so it raises rather than warns.
    """


class ProtocolError(GrantorError):
    """The issuer refused. ``code`` is the normalized bare error code.

    ``code`` comes from whichever of the two envelopes the issuer used, so
    callers match on one vocabulary regardless of which endpoint refused
    them — ``invalid_grant``, ``invalid_scope``, ``invalid_target`` and the
    rest of the RFC set, or the management envelope's code.
    """

    def __init__(self, code: str, *, status: int | None = None) -> None:
        self.code = code
        self.status = status
        super().__init__(code)


class TokenError(GrantorError):
    """A token failed verification.

    ``reason`` names the check that failed — a signature, an audience, an
    expiry, a nonce. It never contains the token, any part of it, or any
    claim out of it, because a rejected token is exactly the one whose
    contents must not be trusted enough to log.
    """

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def normalize_error(payload: Any, *, status: int | None = None) -> str:
    """Reduce either error envelope to a bare code. The pure step.

    Two shapes, both meaning the issuer refused:

    * the **RFC shape**, ``{"error": "...", "error_description": "..."}``,
      returned by the token, revocation and userinfo endpoints and carried
      on redirects — the vast majority of what any client parses;
    * the **management envelope**, ``{"error": {"code": "...", "message":
      "..."}}``, returned by ``/oauth/authorize`` and ``/oauth/logout`` when
      they refuse *directly*, without a redirect, because the request named
      a destination the issuer could not verify.

    Both mean an address failed exact-match validation. A client that
    understands only the first fails on precisely the two refusals a new
    integration meets on its first afternoon.

    Anything unrecognizable degrades to ``http_<status>`` rather than
    raising: a parser for error bodies that can itself fail is a parser that
    replaces the issuer's diagnosis with its own.
    """
    fallback = f"http_{status}" if status is not None else "unknown_error"
    if not isinstance(payload, Mapping):
        return fallback
    error = payload.get("error")
    if isinstance(error, Mapping):
        code = error.get("code")
        return code if isinstance(code, str) and code else fallback
    if isinstance(error, str) and error:
        return error
    return fallback


def parse_error(response: _JsonResponse) -> str:
    """Normalize an error response to a bare code.

    A body that is not JSON at all — an HTML error page from something in
    front of the issuer, say — yields ``http_<status>``. That case is worth
    naming: a provider's edge is not the provider, and an intermediary's
    refusal has been mistaken for the issuer's before.
    """
    try:
        payload = response.json()
    except Exception:  # noqa: BLE001 - any decode failure means "not JSON"
        return f"http_{response.status_code}"
    return normalize_error(payload, status=response.status_code)


def parse_redirect_error(params: Mapping[str, str]) -> str | None:
    """The third place an error appears: query parameters on the callback.

    Returns the code, or ``None`` when the redirect carries no error — so a
    callback view can ask this question first and take the failure path
    without having to decide what an absent ``error`` means.
    """
    error = params.get("error")
    return error if isinstance(error, str) and error else None
