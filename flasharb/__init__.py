"""Target-independent host side of the flash-arbitration probe.

Pairs with `rigs/fw_arb_common` (shared kernels + command protocol) and one board file
per part. A new target needs no changes here: describe it with a `Target` and the sweeps,
differencing and reporting all work unmodified. See `hardware/ARB_PORTING.md`.

What this measures, in one line: at zero wait states, how many cycles a table load saves by
COLLIDING with the previous load in the flash read word - as a function of where the code
sits modulo the read word and how far apart the two loads are in the instruction stream.

    from flasharb import TARGETS, ArbDevice, align_spacing_map
    dev = ArbDevice(TARGETS["g474"])
    dev.set_accel(0x000)
    grid = align_spacing_map(dev)
"""
from .target import Target, TARGETS
from .probe import ArbDevice, align_spacing_map, working_set_sweep, encoding_sweep, \
                   attribution, format_map

__all__ = ["Target", "TARGETS", "ArbDevice", "align_spacing_map", "working_set_sweep",
           "encoding_sweep", "attribution", "format_map"]
