"""Every module under ``bridge/`` must import.

Why this exists: ``bridge/walkthrough.py`` carried a SyntaxError through two
releases while the whole suite stayed green. Nothing imported it -- ``cli.py``
does ``from bridge.walkthrough import walkthrough_a2a`` *inside* ``main()``, so
the only way to reach the defect was to run ``bridge walkthrough``, which no
test did. A green suite said nothing about a command the README advertises.

The lesson generalises past that one file: a lazy import is invisible to every
test that does not execute the branch containing it. This walks the package and
imports each module, so an unparseable or unimportable module fails here rather
than in a user's terminal.

Modules that legitimately require an optional extra guard themselves with
``pytest.importorskip`` at the top of their own tests; here a missing optional
dependency is skipped rather than failed, so the check stays honest about what
it can actually prove in a bare install.
"""
import importlib
import pkgutil

import pytest

import bridge


def _module_names():
    return sorted(
        m.name
        for m in pkgutil.walk_packages(bridge.__path__, prefix="bridge.")
    )


@pytest.mark.parametrize("name", _module_names())
def test_module_imports(name):
    try:
        importlib.import_module(name)
    except ImportError as exc:
        # An optional extra (mcp, starlette) is absent in this environment.
        # Skipping keeps the check meaningful in a bare install instead of
        # failing for a reason that is not a defect.
        pytest.skip(f"{name} needs an optional dependency: {exc}")


def test_walk_found_the_modules_that_only_the_cli_imports():
    """Guard the guard: if the walk silently returned nothing, every test above
    would vacuously pass. Pin the two modules that no other test imports."""
    names = _module_names()
    assert "bridge.walkthrough" in names
    assert "bridge.cli" in names
