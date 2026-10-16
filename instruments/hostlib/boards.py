"""Find the serial port a board is on, by its probe serial. Nothing else.

    from hostlib import boards
    port = boards.port("instrument")          # an alias from BOARDS.local.json
    port = boards.port("066EFF393250")        # or a probe serial directly

A COM number is not a handle: Windows reassigns them, and two boards of the
same model have the same USB volume label and the same `DBGMCU_IDCODE`. The
probe serial is the only thing that tells them apart, so that is the only thing
this resolves on, and it refuses to guess when a serial matches nothing or
matches more than one port.

WHAT THIS IS NOT. It is not a bench registry. There is no table of which boards
exist, no drive letters, no reset quirks per part, and no claim system saying
who is using what - that belongs to whoever's bench it is. Put your aliases in
`BOARDS.local.json` at the top of the repository (gitignored):

    {
      "instrument": "0670FF535654725187073723",
      "victim":     "066EFF393250"
    }

WHAT IT DOES NOT COVER
  * It does not flash anything. Every victim and instrument here is flashed by
    its own vendor tooling, and wrapping that badly is worse than not wrapping
    it.
  * It does not reset a board. On some USB CDC stacks the right order is reset
    first, then open the port, and that is a property of the board rather than
    of this file.
  * It does not know whether the port it hands back is the board you meant. If
    two probes are plugged in and `BOARDS.local.json` names neither, you get an
    error rather than a coin flip.
"""
from __future__ import annotations

import io
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOCAL = os.path.join(ROOT, "BOARDS.local.json")


class NoSuchBoard(RuntimeError):
    pass


def aliases():
    """{alias: probe serial} from BOARDS.local.json, or {}."""
    if not os.path.exists(LOCAL):
        return {}
    return json.load(io.open(LOCAL, encoding="utf-8"))


def ports():
    """[(device, serial_number, description)] for every serial port seen."""
    try:
        from serial.tools import list_ports
    except ImportError:                        # pragma: no cover
        raise NoSuchBoard("pyserial is not installed: pip install pyserial")
    return [(p.device, p.serial_number or "", p.description or "")
            for p in list_ports.comports()]


def port(which):
    """The device name for an alias or a probe serial.

    Matching is a case-insensitive prefix, because the same probe reports a
    padded serial over CDC and an unpadded one to the debugger - a real
    nRF52840 here answers `001050219420` on one and `1050219420` on the other,
    and the padded form fed to the wrong tool hangs rather than erroring.
    """
    serial = aliases().get(which, which).lower()
    hits = []
    for dev, sn, desc in ports():
        s = sn.lower()
        if not s:
            continue
        if s.endswith(serial) or serial.endswith(s):
            hits.append((dev, sn, desc))
    if not hits:
        seen = ", ".join("%s(%s)" % (d, s or "no serial") for d, s, _ in ports())
        raise NoSuchBoard("no port for %r. Ports seen: %s" % (which, seen or "none"))
    if len(hits) > 1:
        raise NoSuchBoard("%r matches %s - name the full probe serial"
                          % (which, ", ".join(d for d, _, _ in hits)))
    return hits[0][0]


def describe():
    """Every port, for when `port()` has just refused to guess."""
    out = []
    for dev, sn, desc in ports():
        out.append("  %-8s %-26s %s" % (dev, sn or "(no serial)", desc))
    return "\n".join(out) or "  no serial ports"


if __name__ == "__main__":
    print(describe())
