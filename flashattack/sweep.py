"""Sweeping the things an attack has to guess, and the control that gates it.

`run_attack` answers "does this capture give up the key under THESE
assumptions". It takes the pair model and the table geometry as given,
because they are properties of the captured image rather than of the
attack. In practice nobody knows them, and **guessing wrong returns a
clean null rather than a degraded answer** - which reads exactly like a
target that does not leak.

So this module sweeps them, ladders the trace count, and reports the
cheapest assumption set that worked.

    from flashattack import Capture
    from flashattack.sweep import ladder, default_geometries, controls_clean

    lad = ladder(cap, n_values=[2500, 5000, 10000],
                 geometries=default_geometries(line_shifts=[3, 1]),
                 verify=(pt0, ct0), key_for_truth=KEY)
    print(lad.summary_line())

A ladder rather than one big n, because a partial recovery has two causes
that look identical from a single run and want opposite responses:

  * the PAIR MODEL cannot express the pairs carrying the signal, in which
    case more traces never help;
  * the TRACE COUNT is short, in which case the model is fine.

A partial that does not move as n grows is the first; one that climbs is
the second. There is also a test that needs no further captures: a real
margin is in cycles and holds its absolute size as n grows, while a noise
margin falls as 1/sqrt(n).

Both pair models run by default, and NEITHER of them is better. The
120-pair vote reaches targets whose consecutive round-10 reads cross a
column boundary, which the 24-pair intra-column model can't express at
all and reports as absent. But on a plain byte-S-box cipher the narrow
model has been measured reaching the exact key from HALF the traces the
wide one needs. Running one of them is choosing which half of your
targets to miss.

The controls live in this module because a 120-pair vote has five times
the freedom of a 24-pair one, and a geometry sweep multiplies that again.
Both can manufacture a recovery. `controls_clean` scores captures that
are known to have nothing in them - a constant-time build, a
tables-in-RAM twin - through the IDENTICAL call, and a control that
scores invalidates the run rather than the build.

WHAT THIS DOES NOT DO:
  * It does not choose `n_values` or `line_shifts` for you. The flash
    read width is a per-part property that nothing on the chip reports.
  * It does not sweep `mode`, `keysize` or direction.
  * `stop_on_exact` stops at the first n that yields the key, so the
    trials are not a complete grid when it fires - `exact_at` is an
    upper bound on the cheapest n, to the ladder's resolution.
  * It says nothing about whether a null is structural. It gives you the
    evidence to decide; `margin_ratio` below is the arithmetic.
"""
from __future__ import annotations

import dataclasses
import time
from dataclasses import dataclass, field
from typing import Iterable, Optional, Sequence

from .attack import attack as run_attack
from .capture import Capture

__all__ = ["Geometry", "Trial", "Ladder", "default_geometries", "ladder",
           "controls_clean", "margin_ratio"]


@dataclass(frozen=True)
class Geometry:
    """One set of assumptions an attack cannot derive from the data.

    line_shift   log2 of (flash read width in bytes / table entry size).
                 On an 8-byte read that is 3 for a 1-byte S-box and 1 for
                 a 4-byte word table - and WHICH of those a target's last
                 round reads is a property of its implementation.
    line_off     the table's offset within its flash row. Worth 2x to 10x
                 in traces on a table that did not land row-aligned.
    pairs        "all" (120) or "intra-column" (24).
    ct_adjacent  only meaningful with a non-"all" pairs: whether the last
                 round emits reads in state order or ciphertext order.
    """
    line_shift: int
    line_off: int = 0
    pairs: str = "all"
    ct_adjacent: bool = False

    @property
    def label(self) -> str:
        n = "120" if self.pairs == "all" else "24"
        adj = "" if self.pairs == "all" else ("/ct" if self.ct_adjacent
                                              else "/state")
        return "ls=%d off=%d %s%s" % (self.line_shift, self.line_off, n, adj)


@dataclass
class Trial:
    n: int
    geometry: Geometry
    bytes_correct: int
    exact: bool
    verified: bool
    master_hex: Optional[str]
    brute_forced: list
    seconds: float

    @property
    def rank(self):
        """An exact key beats anything; then more correct bytes; then the
        SMALLEST n that got there."""
        return (self.exact, self.bytes_correct, -self.n)


@dataclass
class Ladder:
    label: str
    trials: list = field(default_factory=list)

    @property
    def best(self) -> Optional[Trial]:
        return max(self.trials, key=lambda t: t.rank) if self.trials else None

    @property
    def exact_at(self) -> Optional[int]:
        hits = [t.n for t in self.trials if t.exact]
        return min(hits) if hits else None

    @property
    def scored(self) -> int:
        """Best byte count anywhere in the ladder. Used by the control
        gate, which must not be fooled by a single lucky geometry."""
        return max((t.bytes_correct for t in self.trials), default=0)

    def at(self, n: int) -> list:
        return [t for t in self.trials if t.n == n]

    def summary_line(self) -> str:
        b = self.best
        if b is None:
            return "%s: nothing scored" % self.label
        if b.exact:
            return "%s: EXACT MASTER KEY at n=%d (%s)" % (
                self.label, b.n, b.geometry.label)
        return "%s: %d/16 best, at n=%d (%s)" % (
            self.label, b.bytes_correct, b.n, b.geometry.label)


def default_geometries(line_shifts: Sequence[int],
                       line_offs: Optional[Sequence[int]] = None,
                       models: Sequence[str] = ("all", "intra-column"),
                       ) -> list:
    """The usual grid: each line_shift, each offset, both pair models, and
    for the narrow model both adjacencies - because which one a target
    emits is not predictable and guessing returns a clean null.

    `line_offs=None` means offset 0 only, which is right for a table the
    linker aligned and wrong for one that landed wherever it landed.
    """
    out = []
    for ls in line_shifts:
        for off in (line_offs if line_offs is not None else [0]):
            if off >= (1 << ls):
                continue
            for m in models:
                if m == "all":
                    out.append(Geometry(ls, off, "all", False))
                else:
                    out.append(Geometry(ls, off, m, False))
                    out.append(Geometry(ls, off, m, True))
    return out


def ladder(capture: Capture,
           *,
           n_values: Sequence[int],
           geometries: Sequence[Geometry],
           verify=None,
           key_for_truth=None,
           stop_on_exact: bool = True,
           label: str = "",
           log=None) -> Ladder:
    """Run `run_attack` over the grid, cheapest n first.

    The capture's own geometry fields are REPLACED per trial rather than
    read, so one Capture can be swept without the caller rebuilding it.
    """
    lad = Ladder(label=label or capture.label or "capture")
    total = len(capture.timing)

    for n in sorted(n_values):
        if n > total:
            break
        for g in geometries:
            cap = dataclasses.replace(
                capture,
                timing=capture.timing[:n],
                plaintext=(None if capture.plaintext is None
                           else capture.plaintext[:n]),
                ciphertext=(None if capture.ciphertext is None
                            else capture.ciphertext[:n]),
                line_shift_last=g.line_shift,
                line_off_last=g.line_off,
            )
            t0 = time.time()
            rep = run_attack(cap, verify=verify, key_for_truth=key_for_truth,
                             pairs=g.pairs, ct_adjacent=g.ct_adjacent)
            got = _bytes_correct(rep)
            exact = bool(rep.master_hex) and (
                key_for_truth is None
                or rep.master_hex == bytes(key_for_truth).hex())
            tr = Trial(n=n, geometry=g, bytes_correct=got, exact=exact,
                       verified=bool(rep.verified),
                       master_hex=rep.master_hex,
                       brute_forced=list(rep.brute_forced or []),
                       seconds=time.time() - t0)
            lad.trials.append(tr)
            if log:
                log("    n=%-7d %-18s %2d/16 %s (%.0fs)"
                    % (n, g.label, got,
                       "EXACT MASTER KEY" if exact else "-", tr.seconds))
        if stop_on_exact and any(t.exact for t in lad.at(n)):
            break
    return lad


def _bytes_correct(rep) -> int:
    """How many round-key BYTES matched the truth.

    `RoundKeyInfo.correct` is already a byte count and is None unless
    `key_for_truth` was passed, so this returns the best over the round
    keys the report carries - 0 when truth was not supplied, which is
    correct rather than unknown: without truth there is nothing to count.
    """
    vals = []
    for rk in (rep.round_keys or []):
        # AttackReport carries these as plain dicts after serialisation
        # and as RoundKeyInfo before it; accept either rather than
        # depending on which side of that boundary the caller is on.
        c = rk.get("correct") if isinstance(rk, dict) else getattr(rk, "correct", None)
        if c is None or isinstance(c, bool):
            continue
        # NOT `isinstance(c, int)`: the engine returns numpy integers, and
        # np.int64 is not a Python int. That check silently discarded
        # every real count and reported 0/16 for a recovery that had in
        # fact got 14 - a null manufactured by a type test, which is the
        # worst direction for this number to be wrong in.
        try:
            vals.append(int(c))
        except (TypeError, ValueError):
            continue
    return max(vals, default=0)


def controls_clean(ladders: dict, control_labels: Iterable[str],
                   byte_threshold: int = 4):
    """Did anything score on a capture that has nothing in it?

    Returns (ok, offenders). A control that recovers the key, or more than
    `byte_threshold` bytes, means the sweep is manufacturing and NO row of
    the run may be quoted - not that the control build is broken.
    """
    controls = set(control_labels)
    bad = []
    for k, lad in ladders.items():
        if k not in controls:
            continue
        if lad.exact_at is not None or lad.scored > byte_threshold:
            bad.append((k, lad.scored, lad.exact_at))
    return (not bad), bad


def margin_ratio(small: float, large: float, factor: float) -> float:
    """How a margin scaled against how NOISE would have scaled.

    A real effect's margin is in cycles and holds its absolute size as n
    grows; a noise margin falls as 1/sqrt(n). So for n scaled by `factor`,
    noise predicts small/large == sqrt(factor). Returns the observed ratio
    divided by that prediction: ~1.0 means the margin behaved like noise,
    and ~1/sqrt(factor) means it did not move at all and is real.
    """
    if large <= 0:
        return float("inf")
    return (small / large) / (factor ** 0.5)
