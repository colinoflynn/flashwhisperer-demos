"""
Turn AES table-access traces into per-encryption cycle measurements.

Two effects beyond the bare flash model are modelled here because they are what
usually decides whether the side channel is exploitable on a real part:

1. Instruction-fetch contention ("shared bus").
   On a part whose accelerator has *no separate data cache*, every instruction
   fetch between two table lookups goes through the same line buffer / cache and
   evicts the data line. That destroys the temporal locality the attack feeds
   on. We model this by interleaving deterministic "code" line fetches (a fixed
   loop body in a disjoint address range) between the data lookups and running
   the *combined* stream through the flash model. Set contention=None to model a
   dedicated data cache that instruction fetches never disturb (the attacker's
   best case).

2. Measurement noise.
   Real timing has jitter (interrupts, DVFS, comms, sampling). Additive Gaussian
   noise in cycles lets us characterize how many traces an attack needs.
"""

from __future__ import annotations

from dataclasses import dataclass
import numpy as np

from .flash import FlashModel
from . import aes


@dataclass
class Contention:
    """Instruction-fetch contention on the flash *data* path between two table
    lookups.

    This models the case where instruction fetches reach the same flash
    structure the table data uses - i.e. a single shared flash latch, or a
    UNIFIED cache holding both code and data. It does NOT apply when instructions
    are served separately (a dedicated instruction cache / prefetch buffer, split
    I/D caches, or code executed from RAM): in those cases pass contention=None,
    or set code_in_ram=True here for self-documenting intent.

    code_lines_per_lookup is the key "instruction pressure" knob: how many
    distinct code rows are fetched from the shared path between two consecutive
    table lookups. 0 (or code_in_ram) = instructions never touch the data path.
    """
    code_lines_per_lookup: int = 3    # instruction pressure: code rows per lookup
    code_footprint: int = 32          # distinct code rows the loop cycles through
    code_base: int = 100_000          # code address range, disjoint from tables
    code_in_ram: bool = False         # True -> code off the flash data path entirely


def build_stream(lines: np.ndarray, contention: Contention | None):
    """
    Interleave code fetches with data lookups.

    Returns
    -------
    stream   : (N, L') int32   combined ordered line numbers
    is_data  : (L',) bool       True at columns that are data lookups
    """
    N, L = lines.shape
    if contention is None or contention.code_in_ram \
            or contention.code_lines_per_lookup <= 0:
        # instructions never touch the flash data path (RAM code / separate I$)
        return lines, np.ones(L, dtype=bool)

    cpl = contention.code_lines_per_lookup
    fp = contention.code_footprint
    base = contention.code_base

    block = cpl + 1                         # code fetches then one data lookup
    Lp = L * block
    stream = np.empty((N, Lp), dtype=np.int32)
    is_data = np.zeros(Lp, dtype=bool)

    for k in range(L):
        off = k * block
        for t in range(cpl):
            code_line = base + ((k * cpl + t) % fp)
            stream[:, off + t] = code_line     # same for every trace (constant code)
        stream[:, off + cpl] = lines[:, k]
        is_data[off + cpl] = True
    return stream, is_data


def simulate(
    lines: np.ndarray,
    flash: FlashModel,
    contention: Contention | None = None,
    noise_sigma: float = 0.0,
    rng: np.random.Generator | None = None,
):
    """
    lines : (N,L) data-lookup flash-line numbers (from aes.line_sequence).

    Returns per-trace cycle measurements (float64, length N). Includes code
    fetch cycles when contention is set (a near-constant offset plus the
    data-dependent part), plus optional Gaussian measurement noise.
    """
    stream, _ = build_stream(lines, contention)
    _, cycles = flash.run(stream)
    cycles = cycles.astype(np.float64)
    if noise_sigma > 0:
        if rng is None:
            rng = np.random.default_rng()
        cycles = cycles + rng.normal(0.0, noise_sigma, size=cycles.shape)
    return cycles


def per_access_cycles(lines, flash, contention: Contention | None = None):
    """
    Per-DATA-ACCESS cycle cost, shape (N, L_data) with L_data = number of table
    lookups (160 for AES-128). This is the *observation model* knob:

      * summing all columns  -> end-to-end whole-AES time (what `simulate`
        returns; the attacker sees only one scalar per encryption).
      * summing a subset of columns (e.g. round 1 = columns 0:16 for the S-box
        layout) -> a side channel that can time-resolve part of the execution
        (a power/EM trace windowed to a round, a trigger bracketing some cycles).

    Returns the noise-free per-access costs; add measurement noise to the summed
    window at the call site so the noise attaches to the *observation*.
    """
    stream, is_data = build_stream(lines, contention)
    hits, _ = flash.run(stream)
    cyc = np.where(hits, flash.hit_cycles, flash.miss_cycles)   # (N, L')
    return cyc[:, is_data]                                       # (N, L_data)


def encrypt_and_time(
    plaintexts: np.ndarray,
    round_keys: np.ndarray,
    layout: str,
    flash: FlashModel,
    line_bytes: int | None = None,
    contention: Contention | None = None,
    noise_sigma: float = 0.0,
    rng: np.random.Generator | None = None,
):
    """Convenience: AES -> access trace -> flash timing, in one call.

    The flash ROW width is a property of the flash: by default it is taken from
    `flash.line_bytes`. Pass `line_bytes` only to override it explicitly.
    """
    if line_bytes is None:
        line_bytes = flash.line_bytes
    _, sub_in = aes.encrypt_trace(plaintexts, round_keys)
    lines, meta = aes.line_sequence(sub_in, layout, line_bytes=line_bytes)
    cycles = simulate(lines, flash, contention, noise_sigma, rng)
    return cycles, meta
