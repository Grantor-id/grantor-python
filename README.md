# `grantor` · `grantor-django`

The official Python clients for [Grantor](https://grantor.id), an OAuth 2.1
/ OpenID Connect provider.

```sh
pip install grantor-django
```

> **Status: pre-release.** The packages are claimed and the API is still
> moving. Pin exactly until `1.0.0`.

## The rule

**The library may never require anything of the issuer that a stock OIDC
library could not do.** If a feature needs a change on the issuer side to
work, that change must be an RFC, or the feature is wrong.

Grantor promises every relying party that there is no proprietary SDK and
no bespoke endpoint — you can integrate with any conforming OIDC library,
configured from the issuer URL alone. These packages are sugar over that
standard flow, written because the same 800 lines had been hand-rolled
twice and had diverged exactly where the problem is hard. They are a
convenience, never a requirement, and there is a test on the server side
that keeps it that way.

## The two packages

| Package | What it is |
|---|---|
| **`grantor`** | The protocol core. Discovery, PKCE, code exchange, JWKS verification, userinfo, RP-initiated logout, error normalization. Sync and async. **No framework, no Django.** |
| **`grantor-django`** | The Django half — sign-in views, an authentication backend that links on `sub`, a DRF authentication class, and an admin with no local password. |

Install only what you use:

```sh
pip install grantor-django          # session sign-in
pip install grantor-django[drf]     # + resource server
pip install grantor-django[admin]   # + the Django admin behind Grantor
```

Writing an adapter for another framework? Depend on `grantor` alone. Every
pure step — building the authorization URL, verifying a token, parsing an
error — is public API, not a private helper, precisely so you can compose
them instead of copying them.

## One string is configured

```python
GRANTOR_ISSUER = "https://acme.api.grantor.id"
```

Everything else — authorization, token, JWKS and end-session endpoints —
is read from the issuer's discovery document. Do not transcribe endpoints
into your configuration; that is how a configuration goes stale while
still looking correct.

## Documentation

- [docs.grantor.id](https://docs.grantor.id) — quickstarts and guides
- [Security policy](SECURITY.md)

## Licence

MIT. © Allure Labs.
