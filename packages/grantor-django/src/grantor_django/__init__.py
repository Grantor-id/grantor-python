"""Sign in with Grantor, from Django.

The Django half of the client. The dividing rule, sharp enough for review:
anything that touches ``settings``, ``request``, ``session``, the ``User``
model, or returns an ``HttpResponse`` belongs here; everything else belongs
in ``grantor``.
"""

__all__ = ["__version__"]

__version__ = "0.1.0a0"
