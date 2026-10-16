"""Capture: the target-agnostic container the attack runs on.

A Capture is *observed* data - per-trace plaintext and/or ciphertext plus the
timing - and the metadata needed to interpret it (mode, key size, cache-line
granularity). It contains **no key**: `engine_input()` derives the block-cipher
output the attacker knows purely from observation, so the same object works for a
live hardware interface or a recorded file, and other agents can produce one
without touching the engine.

Getting a Capture:
  * from a live interface - implement a `TraceSource` (one method, `capture()`),
    see `sources.py`;
  * from recorded data - `Capture.from_npz` / `Capture.from_csv`, or build one
    directly with numpy arrays.

What the attacker must observe, per mode (no key needed):
  ecb-enc / cbc-enc : ciphertext           (block-cipher output = C)
  ctr / gcm         : plaintext AND ciphertext (keystream = P ^ C)
  ecb-dec           : plaintext            (InvCipher output, observed)
  cbc-dec           : plaintext AND iv     (InvCipher output = P ^ IV)
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
import numpy as np

ENC_MODES = {"ecb-enc", "cbc-enc", "ctr", "gcm", "cmac"}
DEC_MODES = {"ecb-dec", "cbc-dec"}


@dataclass
class Capture:
    timing: np.ndarray                              # (N,) per-trace timing (any oracle)
    mode: str = "ecb-enc"
    keysize: int = 128
    plaintext: Optional[np.ndarray] = None          # (N,16) uint8, observed/chosen
    ciphertext: Optional[np.ndarray] = None         # (N,16) uint8, observed
    iv: Optional[bytes] = None                      # for cbc-dec (single block)
    line_shift_last: int = 4                         # last-round table: 4=S-box, 2=4-byte T-table
    line_shift_prev: int = 2                         # round Nr-1 table (for 192/256 full recovery)
    # Where each table starts inside the flash row, in table ENTRIES.  A
    # per-IMAGE property (link-order luck), so it belongs with the capture
    # rather than with the engine: the same attack on the same part needs a
    # different value for a different build.  0 is the aligned case; a byte
    # S-box at 0x...cc is 12.  See flashattack.geometry, and
    # flashleak.row_offset_from_image to read it off the firmware.
    line_off_last: int = 0
    line_off_prev: int = 0
    label: str = ""
    meta: dict = field(default_factory=dict)

    def __post_init__(self):
        self.timing = np.asarray(self.timing, dtype=float)
        for name in ("plaintext", "ciphertext"):
            v = getattr(self, name)
            if v is not None:
                setattr(self, name, np.asarray(v, dtype=np.uint8).reshape(-1, 16))

    @property
    def n(self):
        return len(self.timing)

    @property
    def direction(self):
        return "enc" if self.mode in ENC_MODES else "dec"

    def engine_input(self):
        """Return (known_blocks (N,16) int, direction) from OBSERVED data, no key."""
        m = self.mode
        if m in ("ecb-enc", "cbc-enc", "cmac"):
            # cmac: the (untruncated) tag of a single-block message is the AES
            # output block T = AES(k, M_1 ^ K1); store it as `ciphertext`.
            _require(self.ciphertext, m, "ciphertext (the tag, for cmac)")
            return self.ciphertext.astype(int), "enc"
        if m in ("ctr", "gcm"):
            _require(self.plaintext, m, "plaintext"); _require(self.ciphertext, m, "ciphertext")
            return (self.plaintext.astype(int) ^ self.ciphertext.astype(int)), "enc"
        if m == "ecb-dec":
            _require(self.plaintext, m, "plaintext")
            return self.plaintext.astype(int), "dec"
        if m == "cbc-dec":
            _require(self.plaintext, m, "plaintext")
            if self.iv is None:
                raise ValueError("cbc-dec needs iv (InvCipher output = plaintext ^ iv)")
            iv = np.frombuffer(bytes(self.iv), np.uint8)
            return (self.plaintext.astype(int) ^ iv), "dec"
        raise ValueError(f"unknown mode {m!r}")

    # ---- persistence -----------------------------------------------------
    def save_npz(self, path):
        d = {"timing": np.asarray(self.timing), "mode": self.mode,
             "keysize": np.uint16(self.keysize), "line_shift_last": np.uint8(self.line_shift_last),
             "line_shift_prev": np.uint8(self.line_shift_prev),
             "line_off_last": np.uint8(self.line_off_last),
             "line_off_prev": np.uint8(self.line_off_prev), "label": self.label}
        if self.plaintext is not None: d["plaintext"] = self.plaintext
        if self.ciphertext is not None: d["ciphertext"] = self.ciphertext
        if self.iv is not None: d["iv"] = np.frombuffer(bytes(self.iv), np.uint8)
        np.savez_compressed(path, **d)

    @classmethod
    def from_npz(cls, path):
        d = np.load(path, allow_pickle=False)
        g = lambda k: (d[k].item() if k in d.files and d[k].ndim == 0 else (d[k] if k in d.files else None))
        iv = bytes(d["iv"]) if "iv" in d.files else None
        return cls(timing=d["timing"], mode=str(g("mode")), keysize=int(g("keysize") or 128),
                   plaintext=g("plaintext"), ciphertext=g("ciphertext"), iv=iv,
                   line_shift_last=int(g("line_shift_last") or 4),
                   line_shift_prev=int(g("line_shift_prev") or 2),
                   # `or 0` would be a no-op and `g()` returns None for an older
                   # npz that predates these fields, so spell the default out.
                   line_off_last=int(g("line_off_last") or 0),
                   line_off_prev=int(g("line_off_prev") or 0),
                   label=str(g("label") or ""))

    @classmethod
    def from_csv(cls, path, mode="ecb-enc", keysize=128, **kw):
        """CSV with a 'timing' column and optional 16-byte hex 'plaintext'/'ciphertext'
        columns (or pt0..pt15 / ct0..ct15). Header required."""
        import csv
        rows = list(csv.DictReader(open(path, newline="")))
        def col16(prefix):
            if prefix in rows[0]:
                return np.array([[int(h[i:i+2], 16) for i in range(0, 32, 2)] for h in
                                 (r[prefix] for r in rows)], np.uint8)
            keys = [f"{prefix[:2]}{i}" for i in range(16)]
            if all(k in rows[0] for k in keys):
                return np.array([[int(r[k]) for k in keys] for r in rows], np.uint8)
            return None
        timing = np.array([float(r["timing"]) for r in rows])
        return cls(timing=timing, mode=mode, keysize=keysize,
                   plaintext=col16("plaintext"), ciphertext=col16("ciphertext"), **kw)


def _require(v, mode, name):
    if v is None:
        raise ValueError(f"mode {mode!r} needs observed {name} (Capture.{name} is None)")
