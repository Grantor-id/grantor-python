# Changelog

Written before the tag, never after. A changelog assembled from commits
after a release is a list of commits.

Both packages move in lockstep through `0.x` and share one entry per
release; they decouple at `1.0.0`.

## Unreleased

### `grantor-django`

Sign in with Grantor, link on `sub`, sign out properly.

- `grantor_django.urls` — `/sso/start`, `/sso/callback`, `/sso/logout`,
  mounted wherever the project likes. **The redirect URI is derived from the
  URLconf**, so moving the mount point cannot leave a setting disagreeing
  with it.
- `GrantorBackend` — links on `sub`; the email fallback is used **exactly
  once**, **only when `email_verified is True`**, and **only on an account
  that is not already linked**. Provisioning unknown people is off unless
  `GRANTOR_CREATE_UNKNOWN_USERS` asks for it.
- `sub` lives on a model the host project owns, found through
  `GRANTOR_SUBJECT_FIELD` (`"profile.grantor_sub"` reaches through a
  relation). The library ships no migration for a table it does not own.
- **The round-trip secrets ride in a signed, short-TTL cookie, not the
  session**, so a sign-in begun on one node finishes on another. `SameSite`
  is `Lax` because the callback is a top-level cross-site redirect.
- Sign-out drops the local session **first**, then redirects to the issuer
  with the `id_token_hint`. POST only.
- A Django system check fails the boot on a missing or malformed setting,
  reporting every problem at once.

### `grantor`

The protocol core, with every pure step of the flow as public API rather
than a private helper.

- `discover` / `async_discover`, cached ~1h per issuer. **A document whose
  `issuer` claim disagrees with the configured issuer is refused**, not
  warned about.
- `generate_pkce`, `challenge_for` — S256 only. There is no way to express
  a request without PKCE, because this issuer accepts none.
- `build_authorization_url`, `exchange_code_request`, `refresh_token_request`,
  `userinfo_request`, `revocation_request`, `build_end_session_url` — pure,
  public, and composable by an adapter that is not this repository's.
- `verify_id_token`, `verify_access_token`, `decode_and_verify`,
  `check_nonce`. Signing algorithms are pinned from discovery **and
  intersected with an asymmetric allowlist**, so a published public key can
  never be used as an HMAC secret.
- `JwksCache` — an unknown `kid` refetches once, then rejects. A rotation is
  not an outage and a stream of junk tokens is not an amplifier.
- `parse_error` / `normalize_error` — **both** issuer error envelopes, the
  RFC shape and the management envelope, reduced to one vocabulary.
- `GrantorClient` and `AsyncGrantorClient`, thin shells on `httpx`.

## 0.1.0a0

The names claimed, and nothing else. Two importable packages with no
behaviour, so that the repository, the gate and the release path are proven
before there is anything to get wrong.

- `grantor` — the framework-free protocol core. Empty.
- `grantor-django` — the Django half, with `[drf]` and `[admin]` extras.
  Empty.
- Python 3.10+, Django 4.2 LTS and 5.x.
- Published by PyPI Trusted Publishing from a tag. No token exists.
