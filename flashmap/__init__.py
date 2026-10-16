"""flashmap - reverse-engineer a microcontroller's memory system.

Measures *structure*, not secrets: flash read width, read latches, data and
instruction caches, and the configuration knobs that move them.  One firmware
shim per part (`rigs/fw_map_*`), one host tool; all inference happens here,
so adding a part means writing a shim, not an analysis.

This package is deliberately standalone.  It must not import `flashsim`,
`flashattack` or `flashleak` - it is an instrument that happens to live in the
same repository as a crypto toolkit.  `tests/test_flashmap.py` asserts that.

    python -m flashmap selftest --port COM9
    python -m flashmap map      --port COM9 --out f429.json
    python -m flashmap compare  f429.json g474.json

Layout
------
device.py       the `memmap/1` protocol driver (see flashmap/PROTOCOL.md)
experiments.py  the probe primitives, the SRAM-twin rule, repeat statistics
infer.py        raw (config, mode, args, cycles) tuples -> a structure
report.py       a "measured datasheet" with the evidence attached
"""
from __future__ import annotations

__version__ = "0.1.0"
PROTOCOL = "memmap/1"

from .device import (  # noqa: F401
    Device,
    DeviceError,
    DeviceReset,
    Ident,
    Knob,
    ProtocolError,
    Region,
    Unsupported,
    open_device,
)
from .experiments import (  # noqa: F401
    Bench,
    MeasurementSet,
    Obs,
    Sample,
    default_plan,
)
from .infer import (  # noqa: F401
    Claim,
    Structure,
    UNKNOWN,
    infer_all,
)

__all__ = [
    "Bench", "Claim", "Device", "DeviceError", "DeviceReset", "Ident", "Knob",
    "MeasurementSet", "Obs", "ProtocolError", "Region", "Sample",
    "Structure", "UNKNOWN", "Unsupported", "default_plan", "infer_all",
    "open_device", "PROTOCOL", "__version__",
]
