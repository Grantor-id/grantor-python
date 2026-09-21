"""The settings a real adopter writes, and nothing more.

Everything under the `GRANTOR_` prefix here is copied verbatim into the
published quickstart. If the quickstart and this file ever disagree, the
quickstart is wrong — which is the point of extracting snippets from a
project that runs in CI rather than retyping them into a page.
"""

SECRET_KEY = "test-only-not-a-secret"  # noqa: S105
DEBUG = False
ALLOWED_HOSTS = ["*"]
USE_TZ = True

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "grantor_django",
    "djangoproject",
]

MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
]

ROOT_URLCONF = "djangoproject.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ]
        },
    }
]

DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

AUTHENTICATION_BACKENDS = [
    "grantor_django.backends.GrantorBackend",
    "django.contrib.auth.backends.ModelBackend",
]

# --- the whole Grantor configuration ---------------------------------------
GRANTOR_ISSUER = "https://acme.api.grantor.id"
GRANTOR_CLIENT_ID = "acme-web"
GRANTOR_CLIENT_SECRET = "test-client-secret"  # noqa: S105
GRANTOR_CALLBACK_BASE_URL = "https://app.example.com"
# ---------------------------------------------------------------------------

# `sub` lives on a model this project owns, not on one the library ships.
GRANTOR_SUBJECT_FIELD = "profile.grantor_sub"
GRANTOR_LOGIN_REDIRECT_URL = "/"
GRANTOR_ERROR_REDIRECT_URL = "/login"
GRANTOR_POST_LOGOUT_REDIRECT_URI = "https://app.example.com/goodbye"
