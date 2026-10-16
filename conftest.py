"""Two-tier tests: quick (default) vs long (--runslow).

Quick : `pytest`            -> fast unit tests only (FIPS vectors, schedule
                               inversion, mode mapping). Seconds, no hardware.
Long  : `pytest --runslow`  -> also the synthetic engine scans and the replay
                               of captured trace vectors in tests/vectors/.

In the repository this was extracted from, this file sat at the root because
`demo/oscore/` needed the same `--runslow` option and registering it in two
conftests is an error. Here there is only one test tree, so this copy is the
only one - which is what docs/PACKAGING.md said a standalone package would
need.

Nothing is inserted on sys.path: the five packages sit at the repository root,
so an editable install (`pip install -e .`) or simply running pytest from the
root finds them.
"""
import pytest


def pytest_addoption(parser):
    parser.addoption("--runslow", action="store_true", default=False,
                     help="run slow tests (engine scans + vector replays)")


def pytest_configure(config):
    config.addinivalue_line("markers", "slow: slow test (engine scan / vector replay)")


def pytest_collection_modifyitems(config, items):
    if config.getoption("--runslow"):
        return
    skip = pytest.mark.skip(reason="need --runslow")
    for item in items:
        if "slow" in item.keywords:
            item.add_marker(skip)
