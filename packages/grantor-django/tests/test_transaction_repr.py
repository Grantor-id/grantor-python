"""The round-trip transaction does not print its PKCE verifier.

The verifier is the one value in the transaction that never travels in a
URL, so it is the one a debug page or an error reporter must not show.
"""

from __future__ import annotations

from grantor_django.transaction import Transaction

VERIFIER = "pkce-verifier-0c4d6e"


def test_a_transaction_repr_does_not_print_the_verifier():
    txn = Transaction(state="st4te", code_verifier=VERIFIER, nonce="n0nce", next_url="/after")
    shown = repr(txn)
    assert VERIFIER not in shown
    assert "/after" in shown
