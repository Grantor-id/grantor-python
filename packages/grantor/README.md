# `grantor`

The protocol core of the Python client for [Grantor](https://grantor.id), an
OAuth 2.1 / OpenID Connect provider. Discovery, PKCE, code exchange, JWKS
verification, userinfo, RP-initiated logout and error normalization — sync
and async, on `httpx`.

**No framework, no Django.** If you are writing a Django application you
want [`grantor-django`](https://pypi.org/project/grantor-django/) instead;
it depends on this package. If you are writing an adapter for another
framework, depend on this one alone: every pure step is public API, not a
private helper, precisely so you can compose them.

```sh
pip install grantor
```

Documentation: [docs.grantor.id](https://docs.grantor.id).
Source and security policy: [Grantor-id/grantor-python](https://github.com/Grantor-id/grantor-python).

MIT. © Allure Labs.
