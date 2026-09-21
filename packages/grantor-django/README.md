# `grantor-django`

Sign in with [Grantor](https://grantor.id) from Django — an OAuth 2.1 /
OpenID Connect provider.

```sh
pip install grantor-django          # session sign-in
pip install grantor-django[drf]     # + a DRF API that answers to an access token
pip install grantor-django[admin]   # + a Django admin with no local password
```

```python
INSTALLED_APPS = [..., "grantor_django"]

GRANTOR_ISSUER = "https://acme.api.grantor.id"
GRANTOR_CLIENT_ID = env("GRANTOR_CLIENT_ID")
GRANTOR_CLIENT_SECRET = env("GRANTOR_CLIENT_SECRET")
GRANTOR_CALLBACK_BASE_URL = "https://app.example.com"
```

```python
urlpatterns = [path("auth/", include("grantor_django.urls"))]
```

Every endpoint — authorization, token, JWKS, end-session — is read from the
issuer's discovery document. The issuer is the only string you configure.

Documentation: [docs.grantor.id](https://docs.grantor.id).
Source and security policy: [Grantor-id/grantor-python](https://github.com/Grantor-id/grantor-python).

MIT. © Allure Labs.
