"""High-level attack on a Capture -> structured AttackReport (JSON-able).

This is the main entry point for callers/agents: give it a Capture (observed
data, no key) and optionally a known plaintext/ciphertext pair for verification;
get back the recovered key, per-byte confidence, and oracle statistics.
"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
import json
import numpy as np
from . import engine, aesref


@dataclass
class RoundKeyInfo:
    index: int
    which: str
    hex: str
    min_confidence: float
    correct: int | None = None       # bytes matching truth (validation only)


@dataclass
class AttackReport:
    mode: str
    keysize: int
    direction: str
    n_traces: int
    master_hex: str | None
    verified: bool | None
    round_keys: list
    oracle: dict                      # timing statistics
    brute_forced: list = field(default_factory=list)
    notes: str = ""

    def to_dict(self):
        d = asdict(self)
        return d

    def to_json(self, **kw):
        return json.dumps(self.to_dict(), **kw)

    def summary(self):
        s = [f"{self.mode} AES-{self.keysize} ({self.direction}), n={self.n_traces}",
             f"  oracle: mean={self.oracle['mean']:.1f} std={self.oracle['std']:.2f}"]
        for rk in self.round_keys:
            c = f" ({rk['correct']}/16 vs truth)" if rk.get('correct') is not None else ""
            s.append(f"  rk[{rk['index']}] {rk['which']}: {rk['hex']}  minconf={rk['min_confidence']:.2f}{c}")
        s.append(f"  MASTER: {self.master_hex}  verified={self.verified}"
                 + (f"  brute-forced {self.brute_forced}" if self.brute_forced else ""))
        return "\n".join(s)


def _oracle_stats(t):
    t = np.asarray(t, float)
    return {"mean": float(t.mean()), "std": float(t.std()),
            "min": float(t.min()), "max": float(t.max()), "n": int(t.size)}


def attack(capture, *, verify=None, full="auto", key_for_truth=None, log=None,
           pairs="all", ct_adjacent=False):
    """Run the attack on a Capture. `verify=(pt,ct)` (known pair) enables master
    verification and brute-force; `key_for_truth` is for validation only.

    The table GEOMETRY travels with the Capture (`line_shift_*`, `line_off_*`),
    because it is a property of the captured image rather than of the attack.
    `pairs`/`ct_adjacent` choose the pair coverage - see `engine.recover`; they
    apply to the single-round path only, since AES-192/256 full recovery runs
    the 120-pair sweep on both rounds."""
    known, direction = capture.engine_input()
    timing = capture.timing
    keysize = capture.keysize
    Nr = {128: 10, 192: 12, 256: 14}[keysize]
    do_full = keysize != 128 and direction == "enc" and full in (True, "auto")

    rk_infos, master, verified, bruteforced, notes = [], None, None, [], ""

    if do_full:
        tl = bytes(aesref.key_expansion(key_for_truth)[Nr]) if key_for_truth else None
        tp = bytes(aesref.key_expansion(key_for_truth)[Nr - 1]) if key_for_truth else None
        r = engine.recover_full(known, timing, keysize=keysize,
                                line_shift_last=capture.line_shift_last,
                                line_shift_prev=capture.line_shift_prev,
                                line_off_last=capture.line_off_last,
                                line_off_prev=capture.line_off_prev,
                                verify=verify, key_for_truth=key_for_truth, log=log)
        for res in r["round_keys"]:
            rk_infos.append(RoundKeyInfo(res.roundkey_index, res.which, res.roundkey.hex(),
                                         float(min(res.confidence)), res.truth_correct).__dict__)
        master = r["master"].hex() if r["master"] else None
        verified = r["verified"]
    else:
        truth = None
        if key_for_truth:
            truth = (aesref.key_expansion(key_for_truth)[-1] if direction == "enc"
                     else aesref.key_expansion(key_for_truth)[0])
        res = engine.recover(known, timing, direction=direction, keysize=keysize,
                             line_shift=capture.line_shift_last,
                             line_off=capture.line_off_last,
                             pairs=pairs, ct_adjacent=ct_adjacent,
                             verify=verify, truth=truth, log=log)
        rk_infos.append(RoundKeyInfo(res.roundkey_index, res.which, res.roundkey.hex(),
                                     float(min(res.confidence)), res.truth_correct).__dict__)
        master = res.master.hex() if res.master else None
        verified = res.verified
        bruteforced = res.bruteforced
        if keysize != 128 and direction == "dec":
            notes = "AES-192/256 decrypt: recovered rk[0]; full master needs the 2nd decrypt round key."

    return AttackReport(mode=capture.mode, keysize=keysize, direction=direction,
                        n_traces=capture.n, master_hex=master, verified=verified,
                        round_keys=rk_infos, oracle=_oracle_stats(timing),
                        brute_forced=list(bruteforced), notes=notes)
