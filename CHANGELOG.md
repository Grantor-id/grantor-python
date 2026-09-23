# Changelog

Written before the tag, never after. A changelog assembled from commits
after a release is a list of commits.

Both packages move in lockstep through `0.x` and share one entry per
release; they decouple at `1.0.0`.

## 0.1.2 — 2026-09-22

### Added

- **A resource server can name the tenant and the applications it
  accepts.** An issuer is an *organization*, and an organization may run
  several tenants and many applications; `aud` says a token is for this
  API, and these say it came from where this API expects. Both are
  optional and both are recommended:

      GRANTOR_TENANT = "northwind"                 # the tenant's slug
      GRANTOR_ALLOWED_CLIENT_IDS = ["web-app-id"]  # who may call this API

  Outside Django, `verify_access_token` and `async_verify_access_token`
  take the same two as `tenant=` and `client_ids=`, and
  `check_access_token_origin` applies them to claims already verified. A
  token that names no tenant does not match a pinned one.

### Changed

- `grantor-django` requires `grantor>=0.1.2`.

## 0.1.1 — 2026-09-21

### Added

- **A check for the one thing the safe default cannot enforce
  (`W002`).** `0.1.0` resolves `sub` through the subject model's
  **default** manager, and Django takes whichever manager is declared
  first. A project that declares its unfiltered escape hatch first —

      all_objects = models.Manager()      # declared first: the default
      objects = SoftDeleteManager()

  — gets lookups that read every row, which is the `0.1.0a0` behaviour
  with no setting to blame and nothing in the code to notice. Whoever
  writes the base model is making a security decision without being told
  it is one. The check fires only on that shape: the default manager is
  plain and some other manager on the model is not.

  Found by the second consumer reading `0.1.0`'s fix rather than trusting
  it, which is the same way the fix it completes was found.

## 0.1.0 — 2026-09-22

### Fixed

- **The soft-delete fix from `0.1.0a0` was opt-in, so by default it fixed
  nothing.** `GRANTOR_USER_QUERYSET` defaulted to
  `User._default_manager.all()` — exactly what the join already read. A
  project that installed the release, read "fixed", and configured nothing
  was still exposed, with a green suite, because no test ran without the
  setting. Found by probing the published wheel rather than reading this
  file.

  **The safe route is now the default.** When `GRANTOR_SUBJECT_FIELD` names
  a related field, lookups go through **that model's own default manager**,
  which is what every hand-rolled implementation did before this library
  existed. A project with soft-deleted rows is correct without configuring
  anything. `GRANTOR_USER_QUERYSET` still overrides, for a project whose
  answer is something else — and a new system check (`W001`) says so at
  boot when it does, because overriding is now the one way left to
  reintroduce the defect.

  The email bootstrap took the same route and had the same hole: a deleted
  profile has no `sub`, so it read as unlinked and was claimable by anybody
  who could prove the address.

  **On urgency, measured rather than assumed:** the only consumer with a
  soft-deleting `Profile` had **zero** soft-deleted rows carrying a `sub`.
  Nobody was ever exposed. The severity was real; the urgency was lower,
  and the fix is for the next project rather than the last one.

## 0.1.0a0 — 2026-09-21

First release. Claims the names and proves the release path.

### Fixed — what two real consumers found

Every one of these was invisible from inside the library and obvious from
inside a project using it.

- **A soft-deleted account could sign in.** `find_by_subject` filters across
  a relation, and a related-field join reads the related table directly —
  the related model's manager never runs. A `Profile` manager excluding
  soft-deleted rows was bypassed, so a deleted profile authenticated, and
  with a conditional unique index on live rows the same `sub` could be
  linked to a second live account while the deleted one went on signing in.
  Two accounts, one subject. `GRANTOR_USER_QUERYSET` names the queryset a
  project considers real.
- **A withdrawn signing key never stopped being accepted.** The JWKS cache
  had no expiry at all: rotation *in* was handled, rotation *out* was not,
  so revoking a compromised key meant restarting every consumer. Worse,
  `GRANTOR_JWKS_CACHE_SECONDS` had survived into bounding only the
  discovery document — a setting quietly no longer meaning what its name
  said. It now bounds the key set, which is what it always claimed.
- **An open redirect on the admin sign-in.** `?next=` went unvalidated into
  the transaction and was followed *after* a successful sign-in — the
  moment somebody is most likely to trust what they see, on the most
  privileged surface there is. The session views' own guard now covers it.
- **`/sso/logout` ignored `GRANTOR_ENABLED`.** A dark deploy published a
  live sign-out that reached the real issuer. All three routes answer 404
  now, and the test asserts the issuer is never contacted rather than that
  a guard is called.
- **`last_login` stopped moving** for any project supplying
  `GRANTOR_ESTABLISH_SESSION`, because `login()` is what fires
  `user_logged_in`.
- **Account linking left no timestamp.** `update_fields` makes Django skip
  `auto_now` columns, so the row that had just acquired an identity was the
  one row with no record of when.
- **The ID-token cookie was written even when the project manages its own.**
  Both writes used one name and disagreed about lifetime, so ordering
  decided which won. Ordering is not a contract.

### Added

- `GRANTOR_COOKIE_SAMESITE`. `Lax` remains the default and is what the
  callback needs, but this library supports a front end on another origin,
  and that is the shape that needs `None; Secure`.
- `grantor_django.urls.sign_in_urls` — `start` and `callback` only, for a
  project whose sign-out is its own, **carrying its own `app_name`**. The
  namespace is load-bearing and a consumer assembling their own subset gets
  a silently wrong redirect URI; an export nobody can get wrong beats a
  warning in the documentation.

### `grantor-django[admin]`

A Django admin with no local password at all.

- `GrantorAdminSite` — the login view **redirects to the issuer**; Django's
  password form is replaced, not hidden, because a hidden form is a form
  somebody finds.
- `is_staff` / `is_superuser` are set from `GRANTOR_ADMIN_ROLE` on every
  sign-in, **including to `False`**. A role revoked at the issuer takes
  effect at the next sign-in, and the local record says so rather than
  keeping a stale flag.
- Admin users are created with an unusable password, and **a refused person
  leaves no record at all** — only an account that already exists has its
  flags corrected on the way out.
- Signing out of the admin **ends the issuer session too**.
- A documented break-glass path, `manage.py grantor_break_glass`, behind
  two deliberate acts: the command hands out a password **and `is_staff`**,
  and `GRANTOR_ADMIN_BREAK_GLASS = True` decides whether any form will take
  one. Both grants are needed — Django's admin form rejects a non-staff
  user before it reads the password, and an admin installed as designed has
  no staff rows at all. `--close` undoes both. `--create` provisions an
  account when there is nobody left to unlock, and only when asked.
  It prints how to close it, that the setting is a **Django setting and not
  an environment variable**, whether `ModelBackend` is even installed, and
  what to read in the audit trail afterwards.

### `grantor-django[drf]`

A DRF API that answers to a Grantor access token.

- `GrantorJWTAuthentication` — verified by signature against JWKS, with
  **the audience being this API**, from `GRANTOR_AUDIENCE`. There is no
  fallback to `GRANTOR_CLIENT_ID`: a fallback would be silently accepted by
  everyone who forgot to set it and would undo the one check this module
  exists for.
- `HasGrantorScope("things:write")` and `HasGrantorRole("admin")`.
- `roles` read as a flat array at the top level. `permissions` is not read
  from a token — it lives on userinfo only.
- A caller needs no local record: the default principal is a `GrantorUser`
  built from the claims. `GRANTOR_DRF_USER_RESOLVER` maps onto a local row
  instead, and `grantor_django.drf.resolve_local_user` is a ready-made one.
- A token that is not shaped like a JWT is **declined locally, before any
  network call** — another authenticator's opaque credential must not
  become a 503 about the identity provider.
  `GRANTOR_DRF_IGNORE_TOKEN_PREFIXES` declines by prefix as well.
- An unreachable issuer answers **503, not 401** — it is not the caller's
  fault and re-authenticating will not help.
- `GRANTOR_HTTP_CLIENT_FACTORY` supplies a configured `httpx.Client` — a
  proxy, a private CA, a client certificate — for every request this
  package makes, so the sign-in half and the resource server cannot end up
  configured differently.

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
- Serves the **other** Django shape too: a browser application on its own
  origin, with a session that is not Django's.
  `GRANTOR_FRONTEND_BASE_URL` makes `next` a path resolved against it — a
  narrower promise than "same host", since no value can name a host at all.
  `GRANTOR_ESTABLISH_SESSION` replaces `login()` with a project's own
  scheme, receiving the response and the issuer's tokens so it can set its
  own cookies. `GRANTOR_ERROR_PARAM` keeps the query-parameter name a
  project's front end already reads.
- A Django system check fails the boot on a missing or malformed setting,
  reporting every problem at once — and asks only for what this project
  actually uses, so a resource server is never made to name a callback.
- `GRANTOR_ENABLED = False` supports a dark deploy: nothing is required of
  a configuration nobody is using yet, and **all three** routes answer 404
  rather than 500 — sign-out included, since it is the one that could
  otherwise end a real session at the issuer while the feature is off.
  Anything that *is* set is still checked.

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
  **Two environments, `pypi-grantor` and `pypi-grantor-django`** — PyPI keys
  a pending publisher on (owner, repository, workflow, environment) and the
  project name is not part of that key, so one environment for both is a
  duplicate registration and the second is refused.
