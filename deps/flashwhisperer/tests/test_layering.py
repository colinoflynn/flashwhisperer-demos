"""The two structural rules, enforced rather than asserted in prose.

docs/PACKAGING.md stated both of these and said the import graph held
"because nothing has broken it yet, which is not the same thing". This is the
something. Writing it immediately found that `flasharb/probe.py` imported
`serial` at module level - the rule had been documented and violated at the
same time, and the only test that existed (`test_flashmap.py`) covered one
package's independence and nothing else.

WHAT THIS DOES NOT COVER:

  * Imports reached by `importlib`, `__import__` with a computed name, or
    inside a string passed to `exec`. The graph test reads source with a
    regular expression; it sees `import x` and `from x import y` and nothing
    cleverer.
  * Imports in subpackages. Every package here is flat (`pkg/*.py`), and the
    glob says so; a nested one would be missed silently.
  * Third-party dependencies other than `serial`. `numpy` is a hard
    dependency of the distribution and is deliberately not restricted.
  * Whether a lazily imported `serial` is reachable at all. A function that
    imports it and is never called still satisfies this.
"""
from __future__ import annotations

import builtins
import pathlib
import re

import pytest

# Left to right, no back edges. The two on the right import no sibling at all.
CHAIN = ["flashsim", "flashattack", "flashleak"]
STANDALONE = ["flashmap", "flasharb"]
PACKAGES = CHAIN + STANDALONE

_ROOT = pathlib.Path(__file__).resolve().parents[1]
_RANK = {name: i for i, name in enumerate(CHAIN)}
_IMPORT = re.compile(r"^\s*(?:from|import)\s+(flash\w+)", re.M)


def _sources(pkg: str):
    return sorted((_ROOT / pkg).glob("*.py"))


@pytest.mark.parametrize("pkg", PACKAGES)
def test_package_has_sources(pkg):
    """Guard against the glob silently matching nothing, which would make
    every other test in this file pass by checking an empty set."""
    assert _sources(pkg), f"no sources found for {pkg} - is the layout flat?"


@pytest.mark.parametrize("pkg", PACKAGES)
def test_no_module_level_serial_import(pkg):
    """A package must install and import without a bench attached, so pyserial
    is an optional extra and every use of it is imported inside the function
    that needs it."""
    offenders = []
    for path in _sources(pkg):
        for n, line in enumerate(path.read_text().splitlines(), 1):
            if re.match(r"^(import serial|from serial)\b", line):
                offenders.append(f"{path.name}:{n}: {line.strip()}")
    assert not offenders, (
        f"{pkg} imports serial at module level; move it into the function:\n  "
        + "\n  ".join(offenders))


@pytest.mark.parametrize("pkg", CHAIN)
def test_chain_has_no_back_edges(pkg):
    offenders = []
    for path in _sources(pkg):
        for dep in _IMPORT.findall(path.read_text()):
            if dep not in PACKAGES or dep == pkg:
                continue
            if dep in STANDALONE or _RANK[dep] >= _RANK[pkg]:
                offenders.append(f"{path.name}: {pkg} -> {dep}")
    assert not offenders, "back edge in the import graph:\n  " + "\n  ".join(offenders)


@pytest.mark.parametrize("pkg", STANDALONE)
def test_standalone_imports_no_sibling(pkg):
    offenders = []
    for path in _sources(pkg):
        for dep in _IMPORT.findall(path.read_text()):
            if dep in PACKAGES and dep != pkg:
                offenders.append(f"{path.name}: {pkg} -> {dep}")
    assert not offenders, (
        f"{pkg} is an instrument that happens to share a repository with a "
        "crypto toolkit; it must import none of it:\n  " + "\n  ".join(offenders))


def test_every_package_imports_without_pyserial():
    """The rule above is about source text. This is about behaviour: block
    pyserial outright and import all five, which also catches a transitive
    module-level import the regular expression would not see."""
    import sys

    real = builtins.__import__

    def guard(name, *args, **kwargs):
        if name == "serial" or name.startswith("serial."):
            raise ImportError("pyserial deliberately blocked for this test")
        return real(name, *args, **kwargs)

    # Drop anything already imported, or the guard never runs.
    saved = {k: v for k, v in sys.modules.items()
             if k.split(".")[0] in PACKAGES or k.split(".")[0] == "serial"}
    for k in saved:
        del sys.modules[k]
    builtins.__import__ = guard
    try:
        for pkg in PACKAGES:
            __import__(pkg)
    finally:
        builtins.__import__ = real
        for k in list(sys.modules):
            if k.split(".")[0] in PACKAGES:
                del sys.modules[k]
        sys.modules.update(saved)
