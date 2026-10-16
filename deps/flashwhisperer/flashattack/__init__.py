"""flashattack - flash-accelerator AES timing side-channel toolkit.

Target-agnostic key-recovery engine plus transports, mode mapping, feasibility
estimation and a CLI. The exploitation engine is independent of any particular
board or firmware (those live under hardware/ and may move to another project).

Quick use:
    from flashattack import engine, modes
    known, direction = modes.known_output("ctr", material, key)
    res = engine.recover(known, timing, direction=direction, verify=(pt, ct))
    print(res.summary())

Two modules carry the parts that used to live outside the package, in
`hardware/`, where the packaged tests could not reach them and two copies of
one scoring rule drifted apart:

    lastround   the scoring rule itself - surface, fast path, equality
                selftest, and which byte pairs to cover
    geometry    where the table sits inside the flash row, which the scorer
                needs and which no number here is quotable without
    oracle      conditioning a NETWORK round-trip time into a usable oracle:
                fit the transport's own discrete artefact, subtract it per
                mode, then cut outliers on a robust scale
    round2      the round-2 collision primitives ROUND2.md documents: the
                state the second round indexes, in both directions, and its
                dip statistics
    search      partial recovery -> key: ranked candidates from a surface and
                a best-first walk, so a recovery is quotable as
                (traces, candidate keys)
"""
from . import (aesref, attack, capture, engine, geometry, lastround, modes,  # noqa: F401
               oracle, round2, search, sm4, sources, stats, tvla, vectors)
from .capture import Capture                 # noqa: F401
from .attack import attack as run_attack     # noqa: F401
from . import sweep                          # noqa: F401

__all__ = ["aesref", "engine", "lastround", "geometry", "modes", "capture",
           "attack", "sources", "stats", "oracle", "round2", "search",
           "tvla", "vectors", "sm4", "Capture", "run_attack", "sweep"]
__version__ = "0.2.0"
