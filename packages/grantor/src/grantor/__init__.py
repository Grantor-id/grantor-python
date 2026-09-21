"""The protocol core of the Grantor client — no framework, no Django.

Every pure step of the flow is public API here, not a private helper. That
is the condition that makes the split between this package and
``grantor-django`` worth having: an adapter for another framework composes
these functions instead of copying them.

The rule the whole library is held to:

    The library may never require anything of the issuer that a stock OIDC
    library could not do.

One string is configured — the issuer. Every endpoint is read from its
discovery document.
"""

__all__ = ["__version__"]

__version__ = "0.1.0a0"
