"""The two packages, exercised together.

This file is the reason the two packages share a repository: one CI run
proves the pair, so nobody can publish a core that breaks the adapter
without seeing it go red.
"""

import subprocess
import sys

import grantor
import grantor_django


def test_both_packages_import():
    assert grantor.__version__
    assert grantor_django.__version__


def test_versions_move_in_lockstep():
    """Through 0.x the two are cut from one commit.

    `grantor-django` depends on `grantor~=0.1`, so a drift here is a
    release that resolves to a core it was never tested against.
    """
    assert grantor.__version__ == grantor_django.__version__


def test_the_core_pulls_in_no_django():
    """`import grantor` must not drag Django in.

    Asserted in a subprocess rather than with `sys.modules`, because the
    rest of this test session has Django imported for the adapter's sake
    and would make the check pass for the wrong reason.
    """
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", "import grantor, sys; print('django' in sys.modules)"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.strip() == "False"


def test_the_adapter_can_actually_resolve_the_core_it_ships_with():
    """`grantor-django`'s pin must admit the `grantor` cut beside it.

    This looks pedantic and is not. A `~=0.1` specifier excludes
    pre-releases, so a `grantor-django 0.1.0a0` pinned that way cannot
    install the `grantor 0.1.0a0` it was built against — the failure only
    appears in a clean venv, after the versions are on PyPI and immutable.
    """
    from importlib.metadata import requires

    from packaging.requirements import Requirement

    pins = [
        Requirement(raw)
        for raw in requires("grantor-django") or []
        if Requirement(raw).name == "grantor"
    ]
    assert pins, "grantor-django must depend on grantor"
    specifier = pins[0].specifier
    specifier.prereleases = True
    assert grantor.__version__ in specifier, (
        f"grantor-django pins grantor{specifier}, which cannot resolve "
        f"grantor {grantor.__version__}"
    )
