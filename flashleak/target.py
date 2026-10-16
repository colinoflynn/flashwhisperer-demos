"""Driving a live target, and a simulated one to check the detector against.

A target is anything with a `measure(data) -> seconds_or_cycles` method. That is
the whole interface, deliberately: the timing can come from a serial round trip,
a scope, a network reply, or an on-chip counter, and none of this package cares.

    class MyBootloader:
        def measure(self, data: bytes) -> float | None:
            t0 = time.perf_counter()
            self.port.write(b"\\x01" + data)
            self.port.read(1)                 # the ACK, or whatever means "ready"
            return time.perf_counter() - t0
        def reset(self) -> None:              # optional
            self.port.setDTR(True); self.port.setDTR(False)

`measure` returning None means "that one failed"; such traces are dropped.

Why controlled input is worth the trouble
-----------------------------------------
Two things become possible that observation alone cannot do:

* **fixed-vs-random.** Interleave a constant block with random ones and compare
  the two timing populations. This assumes nothing about the cipher and is far
  more sensitive than any of the modelled tests, so it is the right first
  question to ask of an unknown target.
* **amplification.** If the target is deterministic and resettable, the same
  input can be measured K times and the minimum kept. That removes measurement
  jitter - not the target's own input-dependent variation, which is the signal
  - and is what makes a coarse oracle usable.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

import numpy as np

try:
    from flashattack import aesref
except ImportError:                             # pragma: no cover
    aesref = None

from .probe import SBOX, SINV


def _gtab(c):
    t = np.zeros(256, np.uint8)
    for x in range(256):
        a, b, r = x, c, 0
        while b:
            if b & 1:
                r ^= a
            a = ((a << 1) ^ 0x1b) & 0xFF if a & 0x80 else (a << 1) & 0xFF
            b >>= 1
        t[x] = r
    return t


_G = {c: _gtab(c) for c in (0x0e, 0x0b, 0x0d, 0x09)}


def _gmul(a, c):
    return _G[c][a]


# --------------------------------------------------------------------------
# simulated target - ground truth for testing the detector
# --------------------------------------------------------------------------
@dataclass
class SimulatedTarget:
    """A table-AES implementation with a flash-line collision channel.

    Faithful enough to exercise every branch of the detector, and adjustable so
    each conclusion the detector can draw has a corresponding ground truth:

    direction   "enc" or "dec" - what the device does to what you send it
    observe     "input" or "output" - which side the assessor gets to see
    layout      "single"  all 16 lookups share one table (any pair may collide)
                "four"    lookup j uses table j mod 4 (only offsets 0 mod 4)
                "family3" only (i, i+3) pairs ever meet, as TinyCrypt's order does
                "none"    constant time, the negative control
    line_shift  index bits dropped to get a line tag; 4 = 16-byte line of 1-byte
                entries, 2 = 4-byte granularity
    delta       cycles saved per colliding pair
    noise       sd of additive measurement noise
    """
    key: bytes = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    direction: str = "enc"
    observe: str = "output"
    layout: str = "single"
    round_: str = "all"        # "all" is what a real cipher does; see note below
    line_shift: int = 4
    base: float = 10000.0
    delta: float = 5.0
    noise: float = 3.0
    seed: int = 0

    def __post_init__(self):
        if aesref is None:
            raise RuntimeError("SimulatedTarget needs flashattack.aesref")
        self._rng = np.random.default_rng(self.seed)
        rk = aesref.key_expansion(self.key)
        self._rk = rk
        self._k0 = np.frombuffer(bytes(rk[0]), np.uint8).astype(np.int64)
        self._k10 = np.frombuffer(bytes(rk[-1]), np.uint8).astype(np.int64)
        self.calls = 0

    # - the cipher ---------------------------------------------------------
    def _transform(self, blocks):
        b = np.asarray(blocks, np.uint8).reshape(-1, 16)
        if self.direction == "enc":
            return np.asarray(aesref.encrypt_blocks(self.key, b), np.uint8)
        return np.asarray(aesref.decrypt_blocks(self.key, b), np.uint8)

    def _lookup_indices(self, inp, out):
        """The 16 table indices of the leaking round."""
        inp = inp.astype(np.int64); out = out.astype(np.int64)
        if self.round_ == "first":
            k = self._k0 if self.direction == "enc" else self._k10
            return inp ^ k[None, :]
        if self.direction == "enc":                 # last round: ct = SBOX[s]^k10
            return SINV[out ^ self._k10[None, :]]
        return SBOX[out ^ self._k0[None, :]]        # InvCipher last round

    def _all_round_indices(self, inp):
        """Every round's SubBytes input, which is what a real cipher leaks.

        Restricting the model to one round makes the simulator far easier to
        detect than the real thing: round 1 is a linear function of the observed
        input, so an input-side test sees it cleanly, while rounds 2..10 add
        data-dependent time that no simple model explains and that dilutes every
        statistic here. Measured on hardware captures, that dilution costs about
        an order of magnitude in the input-vs-output discriminator, so a
        simulator without it will make the tool look better than it is.
        """
        b = np.asarray(inp, np.uint8)
        st = (b ^ np.frombuffer(bytes(self._rk[0]), np.uint8)[None, :])
        idx = [st.astype(np.int64)]
        for r in range(1, 11):
            sub = np.asarray(SBOX, np.uint8)[st]
            sr = np.empty_like(sub)
            for c in range(4):
                for row in range(4):
                    sr[:, 4 * c + row] = sub[:, 4 * ((c + row) % 4) + row]
            if r < 10:
                mc = np.empty_like(sr)
                for c in range(4):
                    a = [sr[:, 4 * c + row] for row in range(4)]
                    for row in range(4):
                        x = a[row]
                        xt = ((x << 1) ^ (((x >> 7) & 1) * 0x1b)).astype(np.uint8)
                        y = a[(row + 1) % 4]
                        yt = ((y << 1) ^ (((y >> 7) & 1) * 0x1b)).astype(np.uint8)
                        mc[:, 4 * c + row] = xt ^ yt ^ y ^ a[(row + 2) % 4] ^ a[(row + 3) % 4]
                sr = mc
            st = sr ^ np.frombuffer(bytes(self._rk[r]), np.uint8)[None, :]
            if r < 10:
                idx.append(st.astype(np.int64))
        return idx

    def _all_round_indices_dec(self, ct):
        """The InvCipher's own InvSubBytes inputs, for a decryption.

        Not the same as walking the encryption from the plaintext: the InvCipher
        visits the encryption's states but looks them up through the *inverse*
        S-box, at the InvShiftRows-permuted positions. Getting this wrong makes
        the simulated decryption's first modelled round linear in the observed
        plaintext, which is exactly the signature of an INPUT-side target - so
        the detector would be graded against a target that is lying about which
        side it is.
        """
        st = np.asarray(ct, np.uint8) ^ np.frombuffer(bytes(self._rk[10]), np.uint8)[None, :]
        sinv = np.asarray(SINV, np.uint8)
        out = []
        for rnd in range(9, -1, -1):
            isr = np.empty_like(st)                       # rows rotate right by r
            for c in range(4):
                for row in range(4):
                    isr[:, 4 * c + row] = st[:, 4 * ((c - row) % 4) + row]
            out.append(isr.astype(np.int64))              # the lookup indices
            st = sinv[isr] ^ np.frombuffer(bytes(self._rk[rnd]), np.uint8)[None, :]
            if rnd == 0:
                break
            imc = np.empty_like(st)                       # InvMixColumns
            for c in range(4):
                a = [st[:, 4 * c + row] for row in range(4)]
                for row in range(4):
                    imc[:, 4 * c + row] = (_gmul(a[row], 0x0e)
                                           ^ _gmul(a[(row + 1) % 4], 0x0b)
                                           ^ _gmul(a[(row + 2) % 4], 0x0d)
                                           ^ _gmul(a[(row + 3) % 4], 0x09))
            st = imc
        return out

    def _collisions(self, idx):
        tag = idx >> self.line_shift
        n = len(idx)
        total = np.zeros(n, np.int64)
        for a in range(16):
            for b in range(a + 1, 16):
                if self.layout == "none":
                    return np.zeros(n, np.int64)
                if self.layout == "four" and (b - a) % 4:
                    continue
                if self.layout == "family3" and min((b - a) % 16, (a - b) % 16) != 3:
                    continue
                total += (tag[:, a] == tag[:, b])
        return total

    # - the interface ------------------------------------------------------
    def measure_many(self, blocks):
        """Vectorised: the same model as `measure`, for generating test data."""
        b = np.asarray(blocks, np.uint8).reshape(-1, 16)
        out = self._transform(b)
        if self.round_ == "all":
            coll = np.zeros(len(b), np.int64)
            rounds = (self._all_round_indices(b) if self.direction == "enc"
                      else self._all_round_indices_dec(b))
            for idx in rounds:
                coll = coll + self._collisions(idx)
        else:
            coll = self._collisions(self._lookup_indices(b, out))
        t = self.base - self.delta * coll
        if self.noise:
            t = t + self._rng.normal(0, self.noise, size=len(b))
        self.calls += len(b)
        return t, (b if self.observe == "input" else out)

    def measure(self, data: bytes):
        t, _ = self.measure_many(np.frombuffer(data, np.uint8).reshape(1, 16))
        return float(t[0])

    def observed(self, data: bytes) -> bytes:
        """What the assessor gets to see for this call."""
        _, seen = self.measure_many(np.frombuffer(data, np.uint8).reshape(1, 16))
        return bytes(seen[0])

    def reset(self):
        pass


# --------------------------------------------------------------------------
# collection
# --------------------------------------------------------------------------
def collect(target, n, *, repeats=1, seed=0, block_size=16, progress=None):
    """Feed random blocks and gather (blocks, timing).

    `repeats > 1` measures each block that many times and keeps the minimum,
    which suppresses measurement jitter without touching the target's own
    input-dependent variation. Only worth it if `determinism()` says the target
    actually repeats.
    """
    rng = np.random.default_rng(seed)
    blocks = rng.integers(0, 256, size=(n, block_size), dtype=np.uint8)
    t = np.full(n, np.nan)
    for i in range(n):
        best = np.inf
        for _ in range(repeats):
            v = target.measure(bytes(blocks[i]))
            if v is not None and v < best:
                best = v
        t[i] = best if np.isfinite(best) else np.nan
        if progress and (i + 1) % progress == 0:
            print(f"  {i+1}/{n}", flush=True)
    ok = np.isfinite(t)
    return blocks[ok], t[ok]


def determinism(target, trials=200, repeats=5, seed=0):
    """Does the same input give the same time? Decides whether averaging helps.

    Returns the median spread across repeats of one input, next to the spread
    across different inputs. If the within-input spread is a large fraction of
    the between-input spread, the oracle is jitter-dominated and `repeats` (or a
    better timing method) is the first thing to fix - no amount of modelling
    will make up for it.
    """
    rng = np.random.default_rng(seed)
    blocks = rng.integers(0, 256, size=(trials, 16), dtype=np.uint8)
    within, first = [], []
    for i in range(trials):
        vals = [target.measure(bytes(blocks[i])) for _ in range(repeats)]
        vals = [v for v in vals if v is not None]
        if len(vals) < 2:
            continue
        within.append(max(vals) - min(vals))
        first.append(vals[0])
    within = np.array(within, float); first = np.array(first, float)
    w = float(np.median(within)) if within.size else float("nan")
    b = float(first.std()) if first.size else float("nan")
    return {"within_input_spread": w, "between_input_sd": b,
            "ratio": (w / b) if b else float("inf"),
            "deterministic": bool(within.size and np.median(within) == 0.0)}


def fixed_vs_random(target, n=2000, fixed=None, seed=0, repeats=1):
    """Non-specific leakage test: one constant input against random ones.

    Interleaved, so slow drift in the measurement hits both groups equally --
    a real effect survives that, a warm-up or a thermal ramp does not. Welch's
    t on the two populations; |t| > 4.5 is the usual call.

    This assumes nothing about the cipher and is the most sensitive tool here.
    A target that fails this is leaking *something*; the modelled tests then say
    whether it is the collision channel and what it would cost to exploit.
    """
    rng = np.random.default_rng(seed)
    fx = np.frombuffer(fixed, np.uint8) if fixed else rng.integers(0, 256, 16, dtype=np.uint8)
    fx = bytes(np.asarray(fx, np.uint8))
    a, b = [], []
    for i in range(n):
        if i % 2:
            data = fx
        else:
            data = bytes(rng.integers(0, 256, 16, dtype=np.uint8))
        best = np.inf
        for _ in range(repeats):
            v = target.measure(data)
            if v is not None and v < best:
                best = v
        if not np.isfinite(best):
            continue
        (b if i % 2 else a).append(best)
    a = np.array(a, float); b = np.array(b, float)
    if a.size < 2 or b.size < 2:
        return {"t": float("nan"), "n_random": a.size, "n_fixed": b.size,
                "leaking": False}
    t = (a.mean() - b.mean()) / np.sqrt(a.var(ddof=1) / a.size + b.var(ddof=1) / b.size)
    return {"t": float(t), "n_random": int(a.size), "n_fixed": int(b.size),
            "mean_random": float(a.mean()), "mean_fixed": float(b.mean()),
            "leaking": bool(abs(t) > 4.5)}


class SerialTarget:
    """Worked example: a device that takes a block and answers when it is ready.

    Timed from "last byte written" to "first byte back", which is what an
    assessor watching a bootloader's ACK actually has. Adjust the framing to
    whatever the target speaks.
    """

    def __init__(self, port, baud=115200, prefix=b"", reply_len=1, timeout=1.0):
        import serial                             # optional dependency
        self.s = serial.Serial(port, baud, timeout=timeout, write_timeout=timeout)
        self.prefix = prefix
        self.reply_len = reply_len

    def measure(self, data: bytes):
        try:
            self.s.reset_input_buffer()
            self.s.write(self.prefix + data)
            self.s.flush()
            t0 = time.perf_counter_ns()
            r = self.s.read(self.reply_len)
            t1 = time.perf_counter_ns()
        except Exception:
            return None
        return float(t1 - t0) if len(r) == self.reply_len else None

    def reset(self):
        self.s.setDTR(True); time.sleep(0.01); self.s.setDTR(False); time.sleep(0.2)
