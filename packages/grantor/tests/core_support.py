"""Names shared by the core's tests.

In its own module rather than in ``conftest.py``: pytest puts every test
directory on ``sys.path``, so two ``conftest`` modules in one run resolve by
plain name and the second one silently shadows the first. That failure only
appears when the whole suite runs together, which is the worst moment to
meet it.
"""

from __future__ import annotations

import json
from typing import Any

from jwt.algorithms import RSAAlgorithm

ISSUER = "https://acme.api.grantor.id"
CLIENT_ID = "acme-web"
API_AUDIENCE = "https://api.example.com"
KID = "test-key-1"
ROTATED_KID = "test-key-2"


def jwk_for(public_key: Any, kid: str) -> dict[str, Any]:
    jwk = json.loads(RSAAlgorithm.to_jwk(public_key))
    jwk.update({"kid": kid, "use": "sig", "alg": "RS256"})
    return jwk
