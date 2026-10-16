"""`engine.select_offsets` against real measured peak maps.

`leaking_offsets` decides which byte-offset families carry the collision
channel, and `recover(pair_offsets=)` then throws away every pair that is not in
that set. So a false positive is not a missed optimisation, it is a failed
attack: on the SNMPv3 capture an earlier rule picked offset 1 out of a smooth
ramp, the vote fell 15/16 -> 8/16, and at 130 k traces all five draws failed
identically. More traces made it worse, because the spurious peak grew too.

Every map below is measured - the {offset: mean peak} that `leaking_offsets`
returned on the named capture. Producing one costs a ~50 s 120-pair scan, which
is why the decision is tested apart from the scan that feeds it.
"""

import os as _os, sys as _sys
# The five packages live under flashwhisperer/ (REORG_PLAN D2).  Walk up to the
# .git marker rather than assume a depth: importers of these packages sit at the
# repository root, in hardware/, results/<campaign>/, demo/<stack>/ and
# research/<area>/ - four different depths.  `.git` is a FILE in a worktree, so
# test existence, not isdir.
_fw = _os.path.dirname(_os.path.abspath(__file__))
while _fw != _os.path.dirname(_fw) and not _os.path.exists(_os.path.join(_fw, ".git")):
    _fw = _os.path.dirname(_fw)
_sys.path.insert(0, _os.path.join(_fw, "flashwhisperer"))
import numpy as np
import pytest

from flashattack import engine

# TinyCrypt reaches the last-round S-box such that only (i, i+3) mod 16 pairs
# can share a flash line: one family spikes, the rest sit at the ~4.2-4.4 floor
# that a max over 65536 cells produces from pure noise.
F429_TINYCRYPT_600K = {1: 4.31, 2: 4.23, 3: 6.40, 4: 4.38,
                       5: 4.37, 6: 4.36, 7: 4.27, 8: 4.21}
F746_TINYCRYPT_1M5 = {1: 4.25, 2: 4.22, 3: 5.31, 4: 4.30,
                      5: 4.33, 6: 4.31, 7: 4.18, 8: 4.23}
F746_TINYCRYPT_4M = {1: 4.43, 2: 4.30, 3: 8.28, 4: 4.23,
                     5: 4.30, 6: 4.23, 7: 4.33, 8: 4.22}

# mbedTLS leaks through all 120 pairs, so peaks form a gently decreasing ramp
# with no isolated spike. Nothing should be selected: there is no idle subset to
# discard, and discarding 105 of 120 good pairs is what breaks the attack.
SNMPV3_MBEDTLS_200K = {1: 6.58, 2: 6.01, 3: 5.71, 4: 5.11,
                       5: 4.26, 6: 4.59, 7: 4.35, 8: 4.26}
SNMPV3_MBEDTLS_130K = {1: 5.98, 2: 5.51, 3: 5.25, 4: 4.95,
                       5: 4.35, 6: 4.56, 7: 4.21, 8: 4.38}
SNMPV3_MISFIRE_DRAW = {1: 5.75, 2: 5.39, 3: 5.09, 4: 4.78,
                       5: 4.36, 6: 4.44, 7: 4.31, 8: 4.34}
TLS_MBEDTLS_250K = {1: 5.05, 2: 4.86, 3: 4.84, 4: 4.68,
                    5: 4.18, 6: 4.46, 7: 4.21, 8: 4.15}

# Mitigated victims: no channel at all, every offset at the floor.
F429_RAMTABLES_300K = {1: 4.33, 2: 4.35, 3: 4.22, 4: 4.27,
                       5: 4.31, 6: 4.21, 7: 4.32, 8: 4.30}
SNMPV3_RAM_CONTROL = {1: 4.25, 2: 4.19, 3: 4.25, 4: 4.26,
                      5: 4.23, 6: 4.34, 7: 4.16, 8: 4.32}

SPIKES = [("f429_tinycrypt_600k", F429_TINYCRYPT_600K),
          ("f746_tinycrypt_1m5", F746_TINYCRYPT_1M5),
          ("f746_tinycrypt_4m", F746_TINYCRYPT_4M)]
FLAT = [("snmpv3_200k", SNMPV3_MBEDTLS_200K),
        ("snmpv3_130k", SNMPV3_MBEDTLS_130K),
        ("snmpv3_misfire_draw", SNMPV3_MISFIRE_DRAW),
        ("tls_250k", TLS_MBEDTLS_250K),
        ("f429_ramtables", F429_RAMTABLES_300K),
        ("snmpv3_ram_control", SNMPV3_RAM_CONTROL)]


def _excess_ratio(peaks):
    """How far the top offset stands above the floor, relative to the next."""
    vals = sorted(peaks.values(), reverse=True)
    base = float(np.median(list(peaks.values())))
    return (vals[0] - base) / max(vals[1] - base, 1e-9)


@pytest.mark.parametrize("name,peaks", SPIKES)
def test_single_family_leak_is_found(name, peaks):
    assert engine.select_offsets(peaks) == [3], name


@pytest.mark.parametrize("name,peaks", FLAT)
def test_uniform_or_absent_leak_selects_nothing(name, peaks):
    assert engine.select_offsets(peaks) == [], name


def test_the_two_populations_are_far_apart():
    """The rule is not a tuned threshold. On this statistic a real single-family
    leak and a uniform one differ by more than an order of magnitude, so any cut
    well inside that gap gives the same answers on every capture here."""
    real = min(_excess_ratio(p) for _, p in SPIKES)
    uniform = max(_excess_ratio(p) for _, p in FLAT)
    assert uniform < 3.0 < real
    assert real > 5 * uniform


def test_ramp_top_alone_is_not_enough():
    """The exact regression. The old rule was `peak > median + margin`, which
    the top of a smooth ramp can clear by a hair while meaning nothing."""
    ramp = SNMPV3_MISFIRE_DRAW
    median = float(np.median(list(ramp.values())))
    assert ramp[1] > median + 1.0             # old rule fired here, by 0.14
    assert engine.select_offsets(ramp) == []  # new rule does not


def test_a_genuine_spike_survives_a_raised_floor():
    """Selection depends on isolation, not absolute height: the same spike over
    a noisier floor is still a spike."""
    raised = {d: v + 1.5 for d, v in F429_TINYCRYPT_600K.items()}
    assert engine.select_offsets(raised) == [3]


def test_margin_still_gates():
    """A map with no peak above median+margin selects nothing regardless of how
    isolated its maximum is in relative terms."""
    flat = {d: 4.30 for d in range(1, 9)}
    flat[3] = 4.60
    assert engine.select_offsets(flat) == []
