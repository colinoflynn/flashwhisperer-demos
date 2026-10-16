"""flashmap.device - the `memmap/1` protocol driver.

Speaks exactly what `flashmap/PROTOCOL.md` specifies and nothing else.  The
driver is deliberately thin and paranoid: it validates the banner, it refuses to
invent values the shim did not send, and it turns every "the shim replied
something unexpected" into a `ProtocolError` rather than a silently wrong
number.  A measurement tool whose transport fails quietly is worse than no tool.

Three things here are not decoration:

* `Device.set_knob` returns the shim's **readback**, never the requested value.
  The protocol requires the shim to read the register back; a knob that refuses
  to move (the L552's `WAYSEL` did exactly that once) must show up as a
  disagreement here, not as an assumption downstream.
* `Device.timed` returns the checksum alongside the cycle count.  A probe that
  measured nothing - loop optimised away, `.ramfunc` not copied, region
  unmapped - is then detectable rather than merely fast.
* `Transcript` records every line in both directions, so a `map` run carries its
  own raw evidence and can be replayed offline against a new `infer.py`.

Nothing in this module knows what a cache is.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

PROTOCOL = "memmap/1"

# Canonical knob names, in the order a report should show them.  Parts without a
# knob simply omit it; a shim inventing a name outside this set is not an error
# (it is passed through), but the cross-product inference only reasons about the
# canonical ones because only those mean the same thing on two different parts.
CANONICAL_KNOBS = ("waitstates", "icache", "dcache", "prefetch", "waysel", "unified")

# Region kinds.  Exactly one of these is "the thing under test"; the rest are
# candidate twins.
FLASH_KINDS = ("flash",)
TWIN_KINDS = ("sram", "itcm", "dtcm", "axisram", "ccm", "other")

MODES = ("walk", "reread", "evict", "chase", "alt", "nop")


class DeviceError(RuntimeError):
    """The shim replied `err ...`, or the transport failed."""


class ProtocolError(DeviceError):
    """The shim replied something `memmap/1` does not allow."""


class Unsupported(DeviceError):
    """The shim replied `unsupported` for an optional command."""


class DeviceReset(DeviceError):
    """The shim printed an out-of-band fault notice instead of a reply.

    `PROTOCOL.md` says nothing but replies are printed, and a shim that breaks
    that rule to report a hard fault is breaking it for a good reason - a
    wedged board costs more than the line does.  It is a hard error here rather
    than a skipped line because a faulting shim has usually reset, so every knob
    is back at its power-on value and the configuration the host believes it set
    is no longer true.
    """


# --------------------------------------------------------------------------
# value objects
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Ident:
    part: str
    core: str
    clk_hz: int
    timer: str
    timer_hz: int
    caps: Tuple[str, ...]
    raw: str = ""

    @property
    def has_counters(self) -> bool:
        return "counters" in self.caps

    @property
    def ramfunc(self) -> bool:
        return "ramfunc" in self.caps

    @property
    def timer_live(self) -> bool:
        """The shim MUST report `timer=none` if its counter does not advance."""
        return self.timer not in ("none", "", None)

    def __str__(self) -> str:
        return (f"{self.part} ({self.core}) clk={self.clk_hz/1e6:.6g}MHz "
                f"timer={self.timer}@{self.timer_hz/1e6:.6g}MHz "
                f"caps={','.join(self.caps) or '-'}")


@dataclass(frozen=True)
class Region:
    name: str
    base: int
    size: int
    kind: str

    @property
    def is_flash(self) -> bool:
        return self.kind in FLASH_KINDS

    def __str__(self) -> str:
        return f"{self.name} @0x{self.base:08x} {self.size}B {self.kind}"


@dataclass(frozen=True)
class Knob:
    name: str
    values: Tuple[int, ...]
    current: int

    @property
    def is_binary(self) -> bool:
        return set(self.values) == {0, 1}

    def __str__(self) -> str:
        vs = ",".join(str(v) for v in self.values)
        return f"{self.name} [{vs}] = {self.current}"


@dataclass
class Sample:
    """A repeated measurement of one primitive.

    `cycles` is the **median**, which is what every downstream inference uses:
    a mean is pulled by the occasional interrupt or refresh event, and these
    distributions are integer-valued with a hard floor.
    """
    cycles: float
    lo: float
    hi: float
    n: int
    raw: Tuple[float, ...] = ()
    checksum: Optional[int] = None

    @property
    def spread(self) -> float:
        return self.hi - self.lo

    @property
    def stable(self) -> bool:
        return self.hi == self.lo

    def __str__(self) -> str:
        return f"{self.cycles:g} (n={self.n}, {self.lo:g}..{self.hi:g})"


# --------------------------------------------------------------------------
# transport
# --------------------------------------------------------------------------

class Transcript:
    """Every line in both directions, with a timestamp.

    A `map` run writes this next to its results so a disputed number can be
    re-derived from the bytes the board actually sent.
    """

    def __init__(self, path: Optional[str] = None):
        self.lines: List[Tuple[float, str, str]] = []
        self.path = path
        self._fh = open(path, "w", encoding="utf-8", newline="\n") if path else None

    def log(self, direction: str, text: str) -> None:
        rec = (time.time(), direction, text)
        self.lines.append(rec)
        if self._fh:
            self._fh.write(f"{rec[0]:.6f} {direction} {text}\n")
            self._fh.flush()

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None


class SerialTransport:
    """115200 8N1 by default; the shim's banner may say otherwise."""

    def __init__(self, port: str, baud: int = 115200, timeout: float = 5.0,
                 settle: float = 0.35):
        import serial  # pyserial; imported lazily so host-only tests need no dep
        self.port = port
        self._s = serial.Serial(port, baud, timeout=timeout)
        time.sleep(settle)
        self._s.reset_input_buffer()

    def write_line(self, text: str) -> None:
        self._s.write((text + "\n").encode("ascii"))

    def read_line(self) -> str:
        raw = self._s.readline()
        if not raw:
            raise ProtocolError("timeout: no reply (wrong port? shim not flashed? "
                                "shim printing a banner mid-stream?)")
        return raw.decode("ascii", errors="replace").rstrip("\r\n")

    def reset_input(self) -> None:
        self._s.reset_input_buffer()

    def close(self) -> None:
        try:
            self._s.close()
        except Exception:
            pass


class ReplayTransport:
    """Replays a transcript.  Lets `map --replay` re-run inference offline."""

    def __init__(self, path: str):
        self._replies: List[str] = []
        self._sent: List[str] = []
        with open(path, "r", encoding="utf-8") as fh:
            for ln in fh:
                parts = ln.rstrip("\n").split(" ", 2)
                if len(parts) < 3:
                    continue
                _, direction, text = parts
                (self._sent if direction == ">" else self._replies).append(text)
        self._i = 0

    def write_line(self, text: str) -> None:
        pass

    def read_line(self) -> str:
        if self._i >= len(self._replies):
            raise ProtocolError("replay exhausted")
        self._i += 1
        return self._replies[self._i - 1]

    def reset_input(self) -> None:
        pass

    def close(self) -> None:
        pass


# --------------------------------------------------------------------------
# the driver
# --------------------------------------------------------------------------

_INT = re.compile(r"^[+-]?(0x[0-9a-fA-F]+|\d+)$")

# Lines a shim may legitimately print that are not replies.  Anything matching
# is logged and treated as a fault, never silently skipped.
_OOB = re.compile(r"^(HARD ?FAULT|BUS ?FAULT|MEM ?FAULT|USAGE ?FAULT|PANIC|RESET)",
                  re.IGNORECASE)


def _num(tok: str) -> int:
    if not _INT.match(tok):
        raise ProtocolError(f"not a number: {tok!r}")
    neg = tok.startswith("-")
    tok = tok.lstrip("+-")
    v = int(tok, 16) if tok.lower().startswith("0x") else int(tok, 10)
    return -v if neg else v


class Device:
    """A `memmap/1` shim.

    Every method maps to exactly one protocol command.  No method retries, no
    method guesses, and no method caches a value the shim could have changed --
    except `ident()` / `regions()`, which the protocol defines as static.
    """

    def __init__(self, transport, transcript: Optional[Transcript] = None):
        self._t = transport
        self.transcript = transcript or Transcript()
        self._ident: Optional[Ident] = None
        self._regions: Optional[List[Region]] = None

    # - plumbing ---------------------------------------------------------
    def _read_reply(self) -> str:
        reply = self._t.read_line()
        self.transcript.log("<", reply)
        if _OOB.match(reply):
            self._t.reset_input()
            raise DeviceReset(f"shim faulted: {reply!r}. It has probably reset, "
                              f"so every knob is back at its power-on value.")
        return reply

    def _cmd(self, line: str) -> str:
        self.transcript.log(">", line)
        self._t.write_line(line)
        reply = self._read_reply()
        if reply == "unsupported":
            raise Unsupported(f"{line!r}: unsupported")
        if reply.startswith("err "):
            raise DeviceError(f"{line!r}: {reply[4:]}")
        if reply == "err":
            raise DeviceError(f"{line!r}: err")
        return reply

    def _cmd_list(self, line: str, max_lines: int = 4096) -> List[str]:
        """A command whose reply is N lines then `END`."""
        self.transcript.log(">", line)
        self._t.write_line(line)
        out: List[str] = []
        for _ in range(max_lines):
            reply = self._read_reply()
            if reply == "unsupported":
                raise Unsupported(f"{line!r}: unsupported")
            if reply.startswith("err"):
                raise DeviceError(f"{line!r}: {reply}")
            if reply == "END":
                return out
            out.append(reply)
        raise ProtocolError(f"{line!r}: no END after {max_lines} lines")

    def close(self) -> None:
        self._t.close()
        self.transcript.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # - V ----------------------------------------------------------------
    def ident(self, refresh: bool = False) -> Ident:
        if self._ident is not None and not refresh:
            return self._ident
        reply = self._cmd("V")
        f = reply.split()
        if not f or f[0] != PROTOCOL:
            raise ProtocolError(f"banner is not {PROTOCOL}: {reply!r}")
        if len(f) < 6:
            raise ProtocolError(f"banner has {len(f)} fields, need >= 6: {reply!r}")
        caps = tuple(c for c in f[6].split(",") if c) if len(f) > 6 else ()
        self._ident = Ident(part=f[1], core=f[2], clk_hz=_num(f[3]),
                            timer=f[4], timer_hz=_num(f[5]), caps=caps, raw=reply)
        return self._ident

    # - R ----------------------------------------------------------------
    def regions(self, refresh: bool = False) -> List[Region]:
        if self._regions is not None and not refresh:
            return self._regions
        out = []
        for ln in self._cmd_list("R"):
            f = ln.split()
            if len(f) < 4:
                raise ProtocolError(f"region line has {len(f)} fields: {ln!r}")
            out.append(Region(f[0], _num(f[1]), _num(f[2]), f[3]))
        if not any(r.is_flash for r in out):
            raise ProtocolError("shim exposes no `flash` region")
        self._regions = out
        return out

    def flash_region(self) -> Region:
        return next(r for r in self.regions() if r.is_flash)

    def twin_region(self, flash: Optional[Region] = None) -> Region:
        """The SRAM twin: same size, non-flash.

        PROTOCOL.md requires one.  We require *same size* too, because the twin
        exists to be subtracted, and a twin of a different size cannot be the
        identically shaped buffer the rule demands.
        """
        flash = flash or self.flash_region()
        cands = [r for r in self.regions() if not r.is_flash]
        exact = [r for r in cands if r.size == flash.size]
        if not exact:
            raise ProtocolError(
                f"no twin region of size {flash.size} for {flash.name}; "
                f"candidates: {[str(c) for c in cands]}")
        # Prefer tightly-coupled memory when the part has it (the H7 lesson:
        # where your buffers live changes the answer completely).
        order = {"dtcm": 0, "itcm": 1, "ccm": 2, "sram": 3, "axisram": 4, "other": 5}
        exact.sort(key=lambda r: order.get(r.kind, 9))
        return exact[0]

    # - K / S ------------------------------------------------------------
    def knobs(self) -> List[Knob]:
        out = []
        for ln in self._cmd_list("K"):
            f = ln.split()
            if len(f) < 3:
                raise ProtocolError(f"knob line has {len(f)} fields: {ln!r}")
            vals = tuple(_num(v) for v in f[1].split(",") if v != "")
            out.append(Knob(f[0], vals, _num(f[2])))
        return out

    def set_knob(self, name: str, value: int) -> int:
        """Returns the shim's **readback**, which may differ from `value`."""
        reply = self._cmd(f"S {name} {value}")
        m = re.match(r"^ok\s+(\S+)=(\S+)$", reply)
        if not m:
            raise ProtocolError(f"S reply not `ok <knob>=<readback>`: {reply!r}")
        if m.group(1) != name:
            raise ProtocolError(f"S {name} answered for {m.group(1)!r}")
        return _num(m.group(2))

    # - T / A ------------------------------------------------------------
    def timed(self, region: str, mode: str, *args: int) -> Tuple[int, int]:
        """One timed primitive.  Returns `(cycles, checksum)`."""
        line = " ".join(["T", region, mode] + [str(a) for a in args])
        reply = self._cmd(line)
        f = reply.split()
        if len(f) != 2:
            raise ProtocolError(f"T reply is not `<cycles> <checksum>`: {reply!r}")
        return _num(f[0]), _num("0x" + f[1] if not f[1].lower().startswith("0x") else f[1])

    def agg(self, region: str, mode: str, *args: int) -> Tuple[int, int, float, int]:
        """`A` - the shim's own repeats.  Raises `Unsupported` if absent."""
        line = " ".join(["A", region, mode] + [str(a) for a in args])
        reply = self._cmd(line)
        f = reply.split()
        if len(f) != 4:
            raise ProtocolError(f"A reply is not `min max mean n`: {reply!r}")
        return _num(f[0]), _num(f[1]), float(f[2]), _num(f[3])

    def sample(self, region: str, mode: str, args: Sequence[int],
               reps: int = 9, prefer_agg: bool = False) -> Sample:
        """`reps` repeats of one primitive, reduced to a median.

        The host repeats `T` itself unless `prefer_agg` and the shim implements
        `A`.  Host-side repeats are the default because they also carry the
        per-repeat values and the checksum, which `A` does not.
        """
        if prefer_agg:
            try:
                lo, hi, mean, n = self.agg(region, mode, *args)
                return Sample(cycles=mean, lo=lo, hi=hi, n=n)
            except Unsupported:
                pass
        vals: List[float] = []
        csum: Optional[int] = None
        for _ in range(max(1, reps)):
            c, k = self.timed(region, mode, *args)
            vals.append(float(c))
            if csum is None:
                csum = k
            elif csum != k:
                raise ProtocolError(
                    f"checksum moved between repeats of {mode} {list(args)} on "
                    f"{region}: 0x{csum:x} then 0x{k:x} - the probe is not "
                    f"reading what it read last time")
        s = sorted(vals)
        median = s[len(s) // 2] if len(s) % 2 else 0.5 * (s[len(s) // 2 - 1] + s[len(s) // 2])
        return Sample(cycles=median, lo=s[0], hi=s[-1], n=len(s),
                      raw=tuple(vals), checksum=csum)

    # - C ----------------------------------------------------------------
    def counters(self) -> Optional[Dict[str, int]]:
        """Hardware hit/miss counters, or None where the part has none."""
        try:
            lines = self._cmd_list("C")
        except Unsupported:
            return None
        out: Dict[str, int] = {}
        for ln in lines:
            for tok in ln.split():
                if "=" not in tok:
                    raise ProtocolError(f"counter token without `=`: {tok!r}")
                k, v = tok.split("=", 1)
                out[k] = _num(v)
        return out

    # - X ----------------------------------------------------------------
    def device_selftest(self) -> Tuple[bool, str]:
        reply = self._cmd("X")
        if reply == "ok":
            return True, "ok"
        if reply.startswith("fail"):
            return False, reply[4:].strip()
        raise ProtocolError(f"X reply is neither `ok` nor `fail ...`: {reply!r}")


def open_device(port: str, baud: int = 115200, timeout: float = 5.0,
                transcript_path: Optional[str] = None) -> Device:
    tr = Transcript(transcript_path)
    return Device(SerialTransport(port, baud, timeout), tr)


def replay_device(transcript_path: str) -> Device:
    return Device(ReplayTransport(transcript_path), Transcript())
