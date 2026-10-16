"""Load this repository's ARCHIVED captures, and run a recovery ladder on one.

Why this exists as its own module rather than as `Capture.from_npz`: that
constructor reads the schema `Capture.save_npz` writes, and almost nothing
under `results/` was written by it. Those captures were saved by ~20 campaign
scripts over months and their key names disagree --

    ct   / cts        ciphertexts
    pt   / pts        plaintexts
    cyc  / cyc_cycles timing (and the SAM G55 also carries `cyc_dhits`, a
                      cache HIT COUNT, which is a second observable and not
                      interchangeable with a cycle count)

-- and some carry the per-image address fields a recovery is not quotable
without (the K21's `sbox`, `sbox_line_off`, `sbox_bank`). Normalising that is
not a nicety: a reproduction script that guesses `cyc` where a file holds
`cyc_cycles` reports a clean null, which is indistinguishable from a part that
does not leak.

WHAT THIS MODULE DOES NOT DO:

* It does not know which capture backs which table cell. That mapping is data,
  and it lives in `research/reference/cross_part_table.json` as each config's
  `repro` block, because the recovery parameters belong with the claim rather
  than with the loader.
* It does not choose `line_off` or `ct_adjacent` for you. Both are per-image
  properties, both silently return a null when wrong, and the whole point of
  the `repro` block is that they are recorded rather than inferred.
* It does not verify a recovered key against the capture's own `key` array
  unless you ask (`ladder(..., verify=True)`); a capture whose `key` field was
  written by the same script that chose the plaintexts is a weak check, and on
  the parts where it matters the dossier's own positive control is stronger.
"""
from __future__ import annotations

import os

import numpy as np

from . import lastround as _LR

#: capture key -> the aliases seen under `results/`, most-preferred first
ALIASES = {
    "ct": ("ct", "cts", "ciphertext", "ciphertexts"),
    "pt": ("pt", "pts", "plaintext", "plaintexts"),
    "cyc": ("cyc", "cyc_cycles", "cycles", "timing"),
    "key": ("key",),
}

#: other observables a file may carry beside the cycle count. Named so a caller
#: can ask for one deliberately; never substituted for `cyc`.
OBSERVABLES = ("cyc_dhits", "cyc_cycles", "steps")


class Archived:
    """One archived capture, with its schema normalised."""

    def __init__(self, path, ct, pt, cyc, key=None, extra=None, raw_keys=()):
        self.path = str(path)
        self.ct, self.pt, self.cyc, self.key = ct, pt, cyc, key
        self.extra = dict(extra or {})
        self.raw_keys = tuple(raw_keys)

    def __len__(self):
        return 0 if self.cyc is None else int(self.cyc.shape[0])

    def __repr__(self):
        return "<Archived %s n=%d>" % (os.path.basename(self.path), len(self))

    @property
    def distinct(self):
        """Distinct cycle counts. One means bit-exactly flat: there is nothing
        for a recovery to score, and the cell is `flat` rather than `no rec`."""
        return int(np.unique(self.cyc).size)

    @property
    def sd(self):
        return float(np.std(self.cyc))


def load(path, observable="cyc"):
    """Read an archived .npz into an `Archived`, resolving the key aliases.

    `observable` selects the timing column. The default resolves through
    `ALIASES["cyc"]`; pass an explicit name (e.g. `"cyc_dhits"`) to score a
    different observable, which is how the SAM G55's noiseless cache-hit-count
    result is reproduced.
    """
    z = np.load(path, allow_pickle=True)
    have = list(z.keys())

    def pick(which):
        for name in ALIASES[which]:
            if name in have:
                return np.asarray(z[name])
        return None

    if observable != "cyc":
        if observable not in have:
            raise KeyError("%s carries no %r; it has %s"
                           % (os.path.basename(str(path)), observable, have))
        cyc = np.asarray(z[observable])
    else:
        cyc = pick("cyc")
    if cyc is None:
        raise KeyError("%s carries no timing column; it has %s"
                       % (os.path.basename(str(path)), have))
    ct = pick("ct")
    if ct is None:
        raise KeyError("%s carries no ciphertexts; it has %s"
                       % (os.path.basename(str(path)), have))
    extra = {k: z[k] for k in have
             if k not in sum(ALIASES.values(), ()) and k not in (observable,)}
    return Archived(path, np.asarray(ct), pick("pt"),
                    np.asarray(cyc, dtype=np.float64), pick("key"),
                    extra, have)


def ladder(cap, rungs, pairsets, *, line_shift=4, line_off=0,
           ct_adjacent=False, verify=False):
    """Run `recover_k10` at each trace count, over each pair set.

    Returns a list of dicts, one per rung, each with the per-pair-set byte
    counts and margins and the rung's total `bytes` out of sixteen. The rungs
    are cumulative prefixes of one capture, which is what every archived trace
    count on this bench means - NOT independent captures at each size.

    A rung whose count exceeds the capture is skipped and reported as such, so
    a ladder quoted against a short capture cannot silently read as a null.
    """
    out = []
    n_have = len(cap)
    truth = None
    if verify and cap.key is not None:
        truth = np.asarray(cap.key).reshape(-1)[:16]
    for n in rungs:
        if n > n_have:
            out.append({"n": int(n), "skipped": "capture holds %d" % n_have})
            continue
        ct, cyc = cap.ct[:n], cap.cyc[:n]
        # Each pair set is recovered ONCE and its result kept: scoring the
        # per-pair-set byte count by re-running the recovery doubled the cost
        # of every ladder, and on a 100 000-trace capture that is minutes.
        # Pair sets OVERLAP: r1r2 and r1r3 both cover state row 1, so a plain
        # dict update lets a dead pair set overwrite a live one's correct
        # bytes. Widening from two disjoint sets to all six dropped every cell
        # to 8/16 that way, which looked like a weaker result and was a
        # bookkeeping bug. Each position now takes the guess from the pair set
        # with the largest MARGIN, the confidence proxy those margins are.
        per, each, cand = {}, {}, {}
        for ps in pairsets:
            k10, mg = _LR.recover_k10(ct, cyc, ps, line_shift=line_shift,
                                      line_off=line_off,
                                      ct_adjacent=ct_adjacent)
            per[ps] = {"margin": mg}
            each[ps] = k10
            for pos, val in k10.items():
                if pos not in cand or mg > cand[pos][1]:
                    cand[pos] = (val, mg)
        got = {pos: val for pos, (val, _) in cand.items()}
        row = {"n": int(n), "pairsets": per, "k10": got,
               "positions": len(got)}
        if truth is not None:
            # Score against the TRUE round-10 subkey, expanded from the
            # capture's master key - not against the master key, which is
            # what k10 inverts to only once all sixteen positions are in hand.
            k10_true = true_k10(bytes(truth.tolist()))
            row["bytes"] = agreement(got, k10_true)
            for ps, k_ps in each.items():
                per[ps]["bytes"] = agreement(k_ps, k10_true)
            if len(got) == 16 and row["bytes"] == 16:
                row["master"] = _LR.invert_ks(got).hex()
                row["verified"] = row["master"] == bytes(truth.tolist()).hex()
        out.append(row)
    return out


def true_k10(master):
    """The round-10 subkey for a master key, so a PARTIAL recovery can be
    scored. Comparing a partial k10 against the master key is the mistake this
    exists to stop: they are different sixteen bytes."""
    from flashsim import aes as _aes
    return _aes.key_expansion(bytes(master))[10]


def agreement(k10, reference):
    """How many of `k10`'s positions match `reference` (a 16-byte round-10
    subkey). The honest byte count for a cell: a pair set covers eight
    positions, so two disjoint pair sets are needed for sixteen."""
    ref = np.asarray(reference).reshape(-1)[:16]
    return sum(1 for i, v in k10.items() if int(v) == int(ref[i]))


ALL_PAIRSETS = ("r0r1", "r1r2", "r2r3", "r0r3", "r0r2", "r1r3")


def screen(cap, *, line_shift=4, line_offs=(0, 4, 8, 12),
           adjacencies=(False, True), pairsets=ALL_PAIRSETS, n=None):
    """Find WHICH GEOMETRY recovers, cheaply, before spending a ladder on it.

    `line_off` and `ct_adjacent` are per-image and a wrong value returns a
    clean null, so a survey has to sweep them - and sweeping them with
    `recover_k10` costs one full O(n) reduction per combination. This instead
    uses the accumulator: the traces are folded into (256, 256) tables ONCE per
    ciphertext byte pair, and every geometry is then two matmuls whose cost
    does not depend on n. For four offsets that is about a 4x saving, and it is
    what makes sweeping 294 archived captures tractable rather than overnight.

    Returns {(ct_adjacent, line_off): {"bytes": int, "per": {pairset: int}}},
    scored against the round-10 subkey expanded from the capture's own key.
    Needs that key: without it there is nothing to score against and the caller
    should run a ladder and read the margins instead.
    """
    if cap.key is None:
        raise ValueError("%s carries no key; screen() has nothing to score "
                         "against" % os.path.basename(cap.path))
    n = len(cap) if n is None else min(int(n), len(cap))
    ct = cap.ct[:n]
    y = cap.cyc[:n] - cap.cyc[:n].mean()
    k10_true = true_k10(bytes(np.asarray(cap.key).reshape(-1)[:16].tolist()))

    out = {}
    for adj in adjacencies:
        # accumulate once per (ja, jb): the 24 intra-column pairs
        tables = {}
        for ps in pairsets:
            ra, rb = _LR.ROW_PAIRINGS[ps]
            for c in range(4):
                if adj:
                    ja, jb = 4 * c + ra, 4 * c + rb
                else:
                    ja, jb = int(_LR.PINV[4 * c + ra]), int(_LR.PINV[4 * c + rb])
                if (ja, jb) not in tables:
                    tables[(ja, jb)] = _LR.accumulate(ct[:, ja], ct[:, jb], y)
        for off in line_offs:
            guess = {}
            per = {}
            for ps in pairsets:
                ra, rb = _LR.ROW_PAIRINGS[ps]
                hits = 0
                for c in range(4):
                    if adj:
                        ja, jb = 4 * c + ra, 4 * c + rb
                    else:
                        ja, jb = (int(_LR.PINV[4 * c + ra]),
                                  int(_LR.PINV[4 * c + rb]))
                    Ssum, Scnt = tables[(ja, jb)]
                    surf = _LR.score_from_tables(Ssum, Scnt, _LR.SINV,
                                                 line_shift=line_shift,
                                                 line_off=off)
                    ga, gb, mg = _LR.best(surf, margin="cycles")
                    for pos, val in ((ja, ga), (jb, gb)):
                        if pos not in guess or mg > guess[pos][1]:
                            guess[pos] = (val, mg)
                        if int(val) == int(k10_true[pos]):
                            hits += 1
                per[ps] = hits
            got = {p: v for p, (v, _) in guess.items()}
            out[(bool(adj), int(off))] = {
                "bytes": agreement(got, k10_true), "per": per, "n": n}
    return out


def verify_cipher(cap, sample=4096):
    """Did the DEVICE actually compute AES? Check its own output.

    A capture carries plaintexts, ciphertexts and the key, so it can be
    validated after the fact without an on-device self-test: re-encrypt the
    plaintexts in software and compare. This is the check that matters most on
    this bench, because the failure it catches is silent - the shared
    `aes_ttable_encrypt` once updated `s[c]` in place in its final round and so
    computed a function that is not AES. A recovery against that returns a
    clean 0/16, indistinguishable from a part that does not leak, and the
    nRF52840 rig had an on-device FIPS self-test to catch it while the G474 rig
    has none.

    Returns {"ok": bool, "checked": n, "mismatch": n, "reason": str}. A
    capture missing plaintexts or a key cannot be checked and says so - which
    is a finding about the capture, not a pass.

    WHAT THIS PROVES DEPENDS ENTIRELY ON WHERE THE CIPHERTEXT COLUMN CAME
    FROM, and the function cannot tell. If `ct` was reported BY THE DEVICE this
    detects a device that is not computing AES. If `ct` was computed on the
    HOST - `cts = aesref.encrypt_blocks(KEY, pts)`, which 29 of this
    repository's capture scripts do, including the nRF52840's and the
    LPC2124's, because their batch commands stream cycle counts alone - then
    this compares `flashattack.aesref` against `flashsim.aes` and is a
    TAUTOLOGY about the device. It still catches a corrupted or mislabelled
    file, which is worth having, but a pass is not evidence the silicon
    computed AES.

    So: record the ciphertext provenance in the capture's `meta` and say which
    check you are relying on. The device-side evidence is the rig's own
    FIPS-197 self-test run IN THE CELL'S CONFIGURATION, or a single-block
    command echoed against the capture's own plaintexts. `rigs/fw_g4`'s `E`,
    `T` and `M` return the device's ciphertext, so captures from
    `results/stm32g474/g4_cell_capture.py` are the class where this function is
    a device check; most others are not.

    WHAT THIS DOES NOT COVER: it assumes an UNMASKED AES-128 ECB encryption of
    the recorded plaintexts under the recorded key. A masked implementation
    legitimately fails it - `results/rsm_f7/` is Rotating S-box Masking and
    reports every ciphertext as a mismatch, which is correct behaviour for this
    check and says nothing about that campaign. It also cannot check a capture
    with no plaintexts, which 14 archived files are: their recoveries rest on
    the capture script's own correctness and cannot be re-validated here.
    """
    from flashsim import aes as _aes
    if cap.pt is None:
        return {"ok": None, "checked": 0, "mismatch": 0,
                "reason": "no plaintexts in the capture"}
    if cap.key is None:
        return {"ok": None, "checked": 0, "mismatch": 0,
                "reason": "no key in the capture"}
    key = bytes(np.asarray(cap.key).reshape(-1)[:16].tolist())
    n = min(int(sample), len(cap)) if sample else len(cap)
    pt = np.asarray(cap.pt)[:n]
    ct = np.asarray(cap.ct)[:n]
    if pt.shape != ct.shape:
        return {"ok": None, "checked": 0, "mismatch": 0,
                "reason": "plaintext and ciphertext shapes differ: %s vs %s"
                          % (pt.shape, ct.shape)}
    rk = _aes.key_expansion(key)
    # encrypt_trace returns (state, sub_in): the ciphertexts AND the per-round
    # S-box inputs it recorded. Only the first is the cipher output, and
    # treating the pair as an array is what the shape error was.
    want = _aes.encrypt_trace(pt.astype(np.uint8), rk)[0]
    want = np.asarray(want, np.uint8).reshape(len(pt), 16)
    bad = int(np.count_nonzero(np.any(want != ct[:, :16], axis=1)))
    return {"ok": bad == 0, "checked": n, "mismatch": bad,
            "caveat": "a pass proves the device computed AES only if this "
                      "capture's ciphertext column was reported BY THE DEVICE; "
                      "if the script computed it on the host this is a check "
                      "of two software implementations against each other",
            "reason": ("every one of %d matches AES(pt, key)" % n) if not bad
                      else ("%d of %d ciphertexts are NOT AES(pt, key) - the "
                            "device computed something else and any recovery "
                            "against this file is meaningless" % (bad, n))}
