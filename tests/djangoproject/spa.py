"""This project's own way of remembering a signed-in person.

Stands in for the real thing a consumer does here — issuing its own JWT
cookie pair for a browser application on another origin — without pulling
SimpleJWT into this repository's test dependencies. What is under test is
the seam, not somebody else's token library.
"""


def establish(request, response, user, tokens):
    response.set_cookie(
        "djangoproject_access",
        f"access-for-{user.pk}",
        httponly=True,
        samesite="Lax",
        path="/",
    )
    # The hook is handed the issuer's tokens as well, so a project can keep
    # whichever of them it needs — the ID token, for the sign-out hint.
    response.set_cookie("djangoproject_saw_id_token", "yes" if tokens.id_token else "no", path="/")
