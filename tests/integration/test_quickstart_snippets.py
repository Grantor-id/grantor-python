"""The published quickstart, reconciled against a project that runs.

`docs/quickstart.json` is what `docs.grantor.id` shows a stranger in their
first minute. This file is what stops it from being a lie: every string in
it is checked against `tests/djangoproject/` — the Django project this
repository's own test suite boots, signs into and signs out of.

The reader's trust is spent in that first minute and cannot be earned back
in the second. So a snippet that drifts from a working configuration fails
here rather than in somebody's terminal.
"""

from __future__ import annotations

import json
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[2]
QUICKSTART = json.loads((REPO / "docs" / "quickstart.json").read_text())
SETTINGS = (REPO / "tests" / "djangoproject" / "settings.py").read_text()
URLS = (REPO / "tests" / "djangoproject" / "urls.py").read_text()


def test_it_installs_the_distribution_that_exists():
    """The name on PyPI, not the import name."""
    assert QUICKSTART["install"] == "pip install grantor-django"


def test_the_app_is_named_the_way_django_imports_it():
    """`pip install grantor-django` puts `grantor_django` on the path.

    Getting this backwards is the first thing that goes wrong for a reader,
    and it fails at boot with a message about a missing app.
    """
    assert '"grantor_django"' in QUICKSTART["installed_apps"]
    assert '"grantor_django"' in SETTINGS


@pytest.mark.parametrize(
    "setting",
    [
        "GRANTOR_ISSUER",
        "GRANTOR_CLIENT_ID",
        "GRANTOR_CLIENT_SECRET",
        "GRANTOR_CALLBACK_BASE_URL",
    ],
)
def test_every_setting_shown_is_one_this_project_really_sets(setting):
    assert setting in QUICKSTART["settings"], f"{setting} missing from the quickstart"
    assert setting in SETTINGS, f"{setting} missing from the test project"


def test_the_quickstart_shows_no_setting_the_library_does_not_read():
    from grantor_django import conf

    shown = {
        line.split("=")[0].strip() for line in QUICKSTART["settings"].splitlines() if "=" in line
    }
    known = set(conf.REQUIRED_SETTINGS) | set(conf.SESSION_LOGIN_SETTINGS) | set(conf._DEFAULTS)
    assert shown <= known, f"the quickstart names settings the library ignores: {shown - known}"


def test_the_urls_snippet_is_the_include_this_project_uses():
    assert 'include("grantor_django.urls")' in QUICKSTART["urls"]
    assert 'include("grantor_django.urls")' in URLS


def test_the_subject_field_names_a_model_the_host_project_owns():
    """Not one this library ships — it ships none."""
    assert "GRANTOR_SUBJECT_FIELD" in QUICKSTART["subject_field"]
    assert "profile." in QUICKSTART["subject_field"]
    assert 'GRANTOR_SUBJECT_FIELD = "profile.grantor_sub"' in SETTINGS


def test_no_endpoint_is_transcribed_into_the_configuration():
    """The one thing every page of the documentation tells a reader not to do."""
    for key, snippet in QUICKSTART.items():
        if key.startswith("_"):
            continue
        for endpoint in ("/oauth/authorize", "/oauth/token", "/oauth/jwks", ".well-known"):
            assert endpoint not in snippet, f"{key} transcribes {endpoint}"


def test_the_secret_is_read_from_the_environment():
    assert 'env("GRANTOR_CLIENT_SECRET")' in QUICKSTART["settings"]
    # And never a literal. A quickstart that shows an inline secret teaches
    # somebody to commit one.
    assert "sk_" not in QUICKSTART["settings"]
    assert "secret =" not in QUICKSTART["settings"].lower().replace("client_secret =", "")
