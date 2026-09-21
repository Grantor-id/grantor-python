# Command surface of grantor-python. `just verify` is THE gate — CI runs
# exactly the same recipe, so a green local run means a green pipeline.

default:
    @just --list

# Resolve both packages against one lockfile and one interpreter.
install:
    uv sync --all-extras

lint:
    uv run ruff check .

format:
    uv run ruff format .

typecheck:
    uv run mypy

# The live smoke test is deselected by default (see `addopts` in
# pyproject.toml); `just test-live` is the opt-in.
test *args:
    uv run pytest {{args}}

# Talks to the real issuer. Proves discovery and JWKS are reachable and
# shaped as expected — nothing a unit test can prove for you.
test-live:
    uv run pytest -m live

# Build both distributions into dist/. The release workflow builds them the
# same way; this recipe exists so a bad build is found before a tag is cut.
build:
    rm -rf dist
    uv build --package grantor --out-dir dist
    uv build --package grantor-django --out-dir dist

# The gate: lint + format-check + types + tests.
verify:
    uv run ruff check .
    uv run ruff format --check .
    uv run mypy
    uv run pytest
