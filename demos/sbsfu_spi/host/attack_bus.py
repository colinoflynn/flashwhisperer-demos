#!/usr/bin/env python3
"""Recover SBSFU's AES key from the bus-side timing of its verify pass.

    python demos/sbsfu_spi/host/attack_bus.py oracle.npz
    python demos/sbsfu_spi/host/attack_bus.py oracle.npz --ladder

Input is what the capture driver wrote: one timing per ciphertext block, taken
from a probe on the serial flash's chip select, plus the ciphertext the
attacker staged.  Nothing here reads the target's memory or its key; the
key in the .npz is used only to SCORE the result.

WHY THIS IS NOT THE LAST-ROUND SCORER THE OTHER DEMOS USE
---------------------------------------------------------
`flashattack.engine` attacks the last round of an AES ENCRYPTION through a
256-entry byte S-box, so its index is SINV[c ^ k].  This target decrypts:
mbedTLS's inverse cipher XORs the ciphertext with the last round key and
indexes the inverse T-table with the result directly, so the index is
c ^ k with no S-box in the way.  Passing this target's traces to that
module would test a relation the access stream does not have and return a
clean null -- the failure mode that read as "no channel" twice before
(FINDINGS_LEDGER section D).

THE THREE THINGS THAT SET THE INDEX MODEL, all measured, not assumed:

1. ONE TABLE.  ST's se_mbedtls_config.h defines MBEDTLS_AES_FEWER_TABLES,
   so RT1/RT2/RT3 are ROTL of RT0 rather than separate tables -- all 16
   lookups of every inverse round hit the same 1 KB array.  The build's
   symbol table confirms it: RT0 and RSb exist, RT1..RT3 do not.

2. WHERE IT IS.  MBEDTLS_AES_ROM_TABLES is also defined, so RT0 is const
   and lives in flash, behind the cache being measured.  Had the tables
   been generated into SRAM there would be no flash-cache channel at all,
   because the SAM D21's cache serves the NVM controller only.

3. THE LINE.  RT0 holds 4-byte entries and the cache line is 8 bytes, so
   two entries share a line, and RT0's address decides where the pairing
   falls.  At 0x168c the table starts 4 bytes into a line, so entry 0 sits
   alone and entries {1,2}, {3,4}, ... share -- line = (i + 1) >> 1, NOT
   i >> 1.  The offset is swept anyway and the data is allowed to pick it,
   because that is the check on the symbol table rather than a use of it.

WHICH PAIRS CARRY INFORMATION, and the model that was tried first and is
wrong.  mbedTLS's AES_RROUND computes four output words in order, each
from four lookups, giving the round-1 stream

    s0 s13 s10 s7   s4 s1 s14 s11   s8 s5 s2 s15   s12 s9 s6 s3

where s_j = C_j ^ K10_j.  The obvious model is that only CONSECUTIVE
lookups can hit, because nothing between them can evict, and those 15
adjacent pairs happen to form a chain over all 16 bytes.  Measured against
the known key, that model does not hold: the 15 chain pairs average z
-0.42 while 14 deliberately NON-adjacent pairs average -1.07, so
adjacency predicts nothing the other pairs do not.

What does hold is the order-free version.  Two lookups to the same 8-byte
line are one fewer distinct line to fetch, wherever they sit in the round,
because the line is either still resident or will be re-fetched once
instead of twice.  So every one of the 120 byte pairs is a usable test,
not just 15, and the attack does not depend on how the compiler scheduled
four loads inside one C expression -- which C does not specify anyway.
Each key byte is then constrained by 15 pair tests instead of two.

THAT PARAGRAPH IS TRUE ON THIS PART AND FALSE ON THE NEXT ONE, and the
difference is the cache.  "Still resident" is doing all the work in it.
The SAM D21 has a 64-byte direct-mapped cache, so a line survives a few
intervening lookups and 26 of the 120 pairs come out live.  The
NUCLEO-L152RE has no cache at all -- one 8-byte read latch -- so a line
survives exactly nothing, and only CONSECUTIVE loads can share a fetch:
there, 15 pairs carry prominence 8.2-9.4 and the other 105 sit at 3.8.
Summing all 120 there buries a 9-sigma signal under 105 noise votes and
the round-1 attack fails at three times the trace count it needs.

The chain model was rejected above for the right reason and with the
wrong chain.  It was built from mbedTLS's SOURCE order; the compiler
reorders those loads, and on the L152 the live pairs are EXACTLY the
consecutive loads of the EMITTED order read out of the binary -- 15 of
15, against only 4 of 15 shared with the source chain.  See
the L152 port's own emitted-order note.

The window is a number and it is measured: a pair is live iff the two
loads are within ONE of each other on the L152 (15/15, nothing beyond)
and within FOUR OR FIVE here (22/23 at <=4, nothing past 5), both hard
edges.  The campaign that measured this tabulated it;
read this part's restricted to the eleven covered bytes, because the
five dark ones are dead at every distance and smear the edge to 47%.

So: profile the pairs, do not assume either answer.
its pair profile reports the prominence
distribution and whether there is a cliff, using no key.

Same SET but different line is NOT a test: the cache is direct-mapped with
eight sets, and a second line landing in an occupied set evicts rather
than hits.  The distinction is measurable -- see --model.
"""
from __future__ import annotations

import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

import numpy as np                                        # noqa: E402

# The round-1 lookup order of mbedTLS's AES_RROUND, in state bytes.  Kept
# because --model chain uses it, and because it is what a reader will
# expect to see after reading the source.
ORDER = [0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3]
CHAIN = list(zip(ORDER[:-1], ORDER[1:]))
ALL_PAIRS = [(i, j) for i in range(16) for j in range(i + 1, 16)]
PAIRS = ALL_PAIRS


def expected_k10(key16):
    """The last round key, in the byte order the first inverse round sees."""
    from flashattack import aesref
    # expand() returns 11 round keys of 16 bytes, column-major like the
    # state -- the same order the inverse cipher's first AddRoundKey
    # applies them in, so round key 10 indexes straight by state byte.
    return bytes(aesref.key_expansion(bytes(key16))[10])


def deskew(gaps, hz=64e6, cut_ticks=20):
    """Make the intervals comparable: remove the two things that are not
    the cipher, and drop what cannot be removed.

    `cut_ticks` IS A MEASUREMENT OF THE SAM D21 AND NOT A CONSTANT, AND
    IT WAS CARRIED TO ANOTHER PART AS THOUGH IT WERE ONE.  The default
    of 20 is right here: the histogram below is one mode, 4 traces at
    +8, then nothing until +32, so +20 is a cut in a GAP.  On the
    NUCLEO-L152RE the same window lands INSIDE the second of four modes
    -- peaks at -4, +16, +55 and +76 ticks -- and cost about 6x in
    traces (round 1's floor 290 000 -> 50 000 raw intervals, round 10's
    60 000 -> 14 000, at cut_ticks=6) until somebody plotted it.
    Callers on a new part should pass their own value and say which in
    the write-up; attack_realistic.py exposes it as --cut-ticks.

    The diagnostic, because it is what distinguishes this from the
    percentile trimming rejected further down: narrowing the window
    should make the per-collision effect BIGGER.  If it shrinks, the
    cut is eating a tail and taking the signal with it; if it grows,
    a mode was being pooled in.  See
    research/mechanism/MEASURING_CHANNELS.md section B22.

    TWO CONTAMINANTS, BOTH DISCRETE, AND THE SECOND IS WORTH 47x.

    1. SHA-256 compresses once per 64 bytes, so at chunk 16 every fourth
       interval carries a compression: ~310 us against a ~110 us median.
       It depends on the block's POSITION, not its content, so it can
       only swamp.  Subtracting each population's median removes it.

       Classified by the gap's own size, not by index mod 4.  The modular
       version is right on one pass and wrong on a concatenation of them
       -- a pass is 2 815 traces, which is not a multiple of 4, so the
       phase walks at every join and the residual spread went from 0.29
       us to 86 us while still looking like a distribution.

    2. THE VICTIM'S OWN SysTick.  SBSFU's HAL runs a 1 ms tick, and a
       110 us interval contains one about 11 % of the time.  That is not
       a tail: it is a second mode, +46 to +61 ticks of the 15.6 ns
       timer, cleanly separated -- the histogram has 4 traces at +8 and
       then nothing at all until +32.  Pooling the two modes puts a
       0.78 us step on top of a signal measured in single nanoseconds.

       Measured on 95 710 traces: pooled, the residual sd is 292 ns and
       the round-1 collision effect is -2.28 +/- 1.38 ns, i.e. 1.6 sd and
       not established.  Dropping the interrupt branch costs 16 % of the
       traces and takes the sd to 55.7 ns and the same effect to
       -2.97 +/- 0.29 ns, 10.4 sd.  (sd/effect)^2 falls from 16 417 to
       351, so the trace count for a recovery falls by about 47x.

       This is NOT the tail-trimming that was tried and rejected earlier.
       Trimming by percentile removes the slowest traces, and the slowest
       traces are the ones that missed most -- it cut the effect along
       with the noise and made (sd/effect)^2 worse.  This removes a
       *mode*, identified by a gap in the histogram, and the effect
       survives it intact.

    Returns (y, keep).  Both, always: a caller that took only the
    intervals would silently treat a dropped trace as an average one,
    which is worse than keeping it.
    """
    g = np.asarray(gaps, dtype=np.float64)
    tick = 1e6 / hz
    split = 0.5 * (g.min() + g.max())
    heavy = g > split
    y = np.zeros_like(g)
    keep = np.zeros(len(g), dtype=bool)
    for sel in (heavy, ~heavy):
        if not sel.any():
            continue
        med = np.median(g[sel])
        ok = sel & (g < med + cut_ticks * tick)
        if ok.any():
            y[ok] = g[ok] - np.median(g[ok])
            keep |= ok
    return y, keep


class Round:
    """Which table read is being attacked, and how a key guess indexes it.

    The two ends of the inverse cipher leak through different tables, and
    the difference is not cosmetic -- it is a factor of four in traces.

    round 1 (`first`).  mbedTLS XORs the ciphertext with the last round
    key and indexes RT0 with the result: index = C_j ^ K10_j, no S-box in
    the way.  RT0 has FOUR-BYTE entries, so an 8-byte line holds two of
    them and a collision needs the two indices to agree in all but the
    bottom bit: probability 2/256.  Recovers K10; the AES key follows by
    inverting the schedule.  Needs only the ciphertext, which the attacker
    staged.

    round 10 (`last`).  The final inverse round has no MixColumns and
    falls back to the inverse S-box.  What it emits is the AES block
    output D(c), NOT the plaintext -- mbedTLS's CBC wrapper XORs the
    previous ciphertext in afterwards -- so with a_j = (p ^ c_prev)_j the
    relation is a_j = RSb[idx_j] ^ K0_j and index = FSb[a_j ^ K0_j].
    Getting that wrong by one XOR tests a relation the cipher does not
    have and returns a clean null.  The capture stores a_j directly, per
    pass, because each pass has its own IV and an .npz carries one.

    RSb has ONE-BYTE entries -- eight to an 8-byte line, so a collision
    has probability 8/256 against RT0's 2/256 -- and the guess is a byte
    of K0 itself, the AES key.  It needs the plaintext, which is the
    stronger assumption; see the image builder for when it holds.

    `line_off` is in ENTRIES and comes from the table's own address:
    RT0 at 0x168c is 4 bytes into a line, i.e. one 4-byte entry; RSb at
    0x1a8c is 4 bytes into a line, i.e. four 1-byte entries.
    """

    def __init__(self, name, entries_per_line, sub, table_attr, known):
        self.name = name
        self.entries_per_line = entries_per_line
        self.sub = sub                  # index = sub[data ^ guess]
        self.table_attr = table_attr
        self.known = known              # "ct" or "pt"

    def line_off(self, addr):
        entry_bytes = 8 // self.entries_per_line
        return (addr & 7) // entry_bytes


IDENT = np.arange(256, dtype=np.int64)
_FSB = None


def fsb():
    global _FSB
    if _FSB is None:
        from flashattack import aesref
        _FSB = np.frombuffer(bytes(aesref.SBOX), dtype=np.uint8).astype(np.int64)
    return _FSB


def rounds():
    return {
        "first": Round("first", 2, IDENT, "rt0_addr", "ct"),
        "last": Round("last", 8, fsb(), "rsb_addr", "aes_out"),
    }


def line_of(idx, line_off, entries_per_line=2):
    return (idx + line_off) // entries_per_line


def pair_scores(ct, y, ja, jb, line_off, rnd=None):
    """2^16 search on (k[ja], k[jb]) from the same-line collision.

    Scored as the mean of y over the traces where the two lookups land in
    one line.  The right guess selects the traces that really collided and
    so really saved a miss, and its mean sits below the rest.
    """
    ca = ct[:, ja].astype(np.int64)
    cb = ct[:, jb].astype(np.int64)
    Ssum = np.zeros((256, 256))
    Scnt = np.zeros((256, 256))
    np.add.at(Ssum, (ca, cb), y)
    np.add.at(Scnt, (ca, cb), 1.0)

    epl = 2 if rnd is None else rnd.entries_per_line
    sub = IDENT if rnd is None else rnd.sub
    base = np.arange(256)
    nlines = int(line_of(np.int64(255), line_off, epl)) + 1
    scores = np.full((256, 256), np.inf)
    for ga in range(256):
        na = line_of(sub[base ^ ga], line_off, epl)
        Rs = np.zeros((nlines, 256))
        Rc = np.zeros((nlines, 256))
        np.add.at(Rs, na, Ssum)
        np.add.at(Rc, na, Scnt)
        for gb in range(256):
            nb = line_of(sub[base ^ gb], line_off, epl)
            c = Rc[nb, base].sum()
            if c > 0:
                scores[ga, gb] = Rs[nb, base].sum() / c
    return scores


def known_key_control(ct, y, key_k10, line_off, rnd=None):
    """Does the effect exist at all, with the key handed to us?

    A key search that returns nothing is ambiguous: the channel may be
    absent, or present and just short of traces.  This separates the two.
    It computes, from the TRUE last round key, how many of the 15 adjacent
    lookup pairs actually land in one cache line for each block, and asks
    whether blocks with more collisions were faster.

    This is not an attack -- it uses the key.  It is the measurement that
    says whether the attack can ever work, and how many traces it needs:
    the per-collision effect and the residual spread give the trace count
    directly, instead of discovering it by running out of bench time.
    """
    epl = 2 if rnd is None else rnd.entries_per_line
    sub = IDENT if rnd is None else rnd.sub
    k = np.frombuffer(bytes(key_k10), dtype=np.uint8).astype(np.int64)
    idx = sub[ct.astype(np.int64) ^ k[None, :]]
    lines = line_of(idx, line_off, epl)
    hits = np.zeros(len(ct), dtype=np.int64)
    for (ja, jb) in PAIRS:
        hits += (lines[:, ja] == lines[:, jb])

    out = []
    for h in range(hits.max() + 1):
        s = y[hits == h]
        if len(s) >= 8:
            out.append((h, len(s), float(s.mean()),
                        float(s.std() / np.sqrt(len(s)))))
    # Slope of time against collision count: the per-collision saving.
    A = np.vstack([hits, np.ones_like(hits)]).T.astype(float)
    slope, _ = np.linalg.lstsq(A, y, rcond=None)[0]
    resid = y - A @ np.linalg.lstsq(A, y, rcond=None)[0]
    return out, float(slope), float(resid.std())


def run(ct, y, line_off, want=None, verbose=True, pairs=None,
        rnd=None):
    """Score every pair, then let each byte take evidence from all of them.

    MARGINAL EVIDENCE, NOT THE WINNING CELL.  The first version of this
    took each pair's argmin and gave one vote to each of the two bytes in
    it.  That throws away the whole score matrix except one entry: a pair
    whose best cell is wrong contributes a wrong vote at full weight, and
    a pair that ranks the true byte second contributes nothing.  Taking
    the column-wise minimum instead -- the best this pair can do for each
    candidate value of one byte, minimised over the other -- keeps the
    ranking, and a byte that eleven pairs agree on wins even when no
    single pair's top cell is right.

    On the last round it is the difference between a partial answer and
    11 of 16 key bytes exact at 5 000 traces.
    """
    pairs = ALL_PAIRS if pairs is None else pairs
    votes = np.zeros((16, 256))
    margins = []
    for (ja, jb) in pairs:
        sc = pair_scores(ct, y, ja, jb, line_off, rnd)
        fin = sc[np.isfinite(sc)]
        if not len(fin):
            continue
        med = np.median(fin)
        s = fin.std() + 1e-12
        a_marg = np.nan_to_num(sc.min(axis=1), neginf=med, posinf=med)
        b_marg = np.nan_to_num(sc.min(axis=0), neginf=med, posinf=med)
        votes[ja] += (med - a_marg) / s
        votes[jb] += (med - b_marg) / s
        ia, ib = np.unravel_index(np.argmin(sc), sc.shape)
        mg = float((med - sc[ia, ib]) / s)
        margins.append(mg)
        if verbose:
            ok = ""
            if want is not None:
                ok = (" a" + ("+" if ia == want[ja] else "-")
                      + " b" + ("+" if ib == want[jb] else "-"))
            print(f"    pair ({ja:2d},{jb:2d}): k={ia:02x},{ib:02x} "
                  f"margin {mg:5.2f} sd{ok}")
    k = [int(np.argmax(votes[j])) for j in range(16)]

    # A FLAT VOTE VECTOR IS NOT A CONFIDENT ONE, and it used to print as
    # the most confident result this function can produce.
    #
    # When the round's index is LINEAR in the key -- round 1, where the
    # table is read at C ^ K10 with no S-box between -- the pair score
    # depends only on ga ^ gb, so sc.min(axis=1) is the same number for
    # every ga and each byte's votes come out constant.  argmax then
    # returns 0 for all sixteen, and `votes[j] > votes[j][want[j]]` is
    # false everywhere, so the rank line printed "0 0 0 ... 0" beside a
    # recovered key of all zeros and a 0/16.  Rank 0 at every position
    # reads as a perfect result; it meant the opposite, and the two
    # halves of the report disagreed for as long as anyone looked at
    # only one of them.
    ties = [int(np.isclose(votes[j], votes[j].max()).sum())
            for j in range(16)]
    flat = [j for j in range(16) if ties[j] > 1]
    if flat:
        print(f"    NO INFORMATION at {len(flat)} of 16 positions: the vote "
              f"is tied {ties[flat[0]]} ways.")
        print("    This round's table index is linear in the key, so only "
              "key-byte DIFFERENCES are identifiable here, never absolute")
        print("    bytes.  The L152 port's realistic arm "
              "attack_realistic.py is the attack that uses them.")
    if want is not None:
        ranks = ["tied" if ties[j] > 1
                 else str(int((votes[j] > votes[j][want[j]]).sum()))
                 for j in range(16)]
        print("    rank of the true byte per position: " + " ".join(ranks))
    return k, float(np.mean(margins) if margins else 0.0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("npz")
    ap.add_argument("--round", choices=("first", "last", "both"),
                    default="both",
                    help="which inverse round to attack.  first: RT0, "
                         "index C ^ K10, needs only the ciphertext.  last: "
                         "RSb, index FSb[(P ^ Cprev) ^ K0], four times more "
                         "likely to collide but needs the plaintext too")
    ap.add_argument("--line-off", type=int, default=None,
                    help="entries the table sits into its first cache line; "
                         "the default comes from the table address the build "
                         "recorded, and --sweep lets the data choose instead")
    ap.add_argument("--sweep", action="store_true",
                    help="try every line offset and report which the data "
                         "prefers -- the check on the symbol table")
    ap.add_argument("--model", choices=("all", "chain"), default="all",
                    help="all: every one of the 120 byte pairs, which is "
                         "what the known-key control supports.  chain: "
                         "only the 15 pairs adjacent in mbedTLS's lookup "
                         "order, kept so the discarded model can be "
                         "re-measured rather than taken on trust")
    ap.add_argument("--ladder", action="store_true",
                    help="report recovery at 1/8, 1/4 and 1/2 of the traces "
                         "as well, so a long capture can be judged on its "
                         "trend and not only on its endpoint")
    a = ap.parse_args()

    with np.load(a.npz, allow_pickle=True) as d:
        data = {k: np.array(d[k]) for k in d.files}
    gaps = data["gaps_us"]
    key = bytes(data["key"]) if "key" in data else None
    # EVERY PER-TRACE ARRAY MUST BE THE SAME LENGTH AS THE INTERVALS.
    # Nothing downstream checks, and the failure is silent: an observable
    # that is longer than `gaps` does not match the mask, so it is left
    # unsubset, and then a `[:n]` pairs masked times with unmasked blocks
    # from there on.  It cost an hour -- a hand-built subset .npz had
    # truncated gaps_us first and then compared every other array against
    # the NEW length, so ct and aes_out stayed full size.  The scratch
    # script that sliced before masking was accidentally immune and
    # disagreed with this one, which is how it surfaced.
    _n = len(gaps)
    for _k, _v in data.items():
        if getattr(_v, "shape", ()) and _v.ndim >= 1 and _v.shape[0] not in (_n,)                 and _v.dtype != object and _v.shape[0] > 16:
            raise SystemExit(
                f"'{_k}' has {_v.shape[0]} rows against {_n} intervals; the "
                "capture is malformed and every trace after the first "
                "dropped one would be paired with the wrong block.")

    y, keep = deskew(gaps)
    # Every observable is subset by the same mask, so a dropped interval
    # takes its ciphertext with it.  Subsetting y alone would pair each
    # surviving time with the wrong block from there on.
    data = {k: (v[keep] if getattr(v, "shape", ()) and v.shape[:1] ==
                keep.shape else v) for k, v in data.items()}
    y = y[keep]
    n = len(y)

    print(f"{n} timed blocks; residual spread after deskew "
          f"sd {y.std():.4f} us, "
          f"p1..p99 {np.percentile(y, 1):.3f}..{np.percentile(y, 99):.3f}")

    pairset = ALL_PAIRS if a.model == "all" else CHAIN
    which = ("first", "last") if a.round == "both" else (a.round,)
    R = rounds()
    results = {}

    for name in which:
        rnd = R[name]
        addr = int(data.get(rnd.table_attr, 0))
        obs = data.get(rnd.known)
        print("\n" + "=" * 68)
        print(f"round {name}: table @ 0x{addr:08x}, "
              f"{rnd.entries_per_line} entries per 8-byte line, "
              f"indexed by {rnd.known.upper()}")
        if name == "last" and obs is not None and key is not None                 and obs.any():
            # CHEAP, DECISIVE, AND IT CAUGHT A REAL ERROR.  The last-round
            # model stands or falls on `aes_out` being the cipher's own
            # block output rather than the plaintext, and the two differ
            # by one XOR that no amount of trace collection reveals -- the
            # attack simply returns a clean null.  With the key in hand it
            # is one line to check.
            from flashattack import aesref
            m = min(2000, len(obs))
            good = (aesref.decrypt_blocks(key, data["ct"][:m]) == obs[:m])
            print(f"  aes_out == D(ct) on {m} blocks: {bool(good.all())}")
            if not good.all():
                print("  REFUSING to score: the recorded block output is "
                      "not what this key decrypts the ciphertext to.")
                continue
        if obs is None or not addr or not obs.any():
            print(f"  skipped: the capture carries no usable {rnd.known}. "
                  "Re-capture with an sbsfu_oracle.py that records it.")
            continue
        obs = obs[:n]

        derived = rnd.line_off(addr)
        off = a.line_off if a.line_off is not None else derived
        want = None
        if key is not None:
            want = (expected_k10(key) if name == "first" else bytes(key))
            print(f"  ground truth: {want.hex()}")

        if want is not None:
            for o in (range(rnd.entries_per_line) if a.sweep else [off]):
                rws, slope, sd = known_key_control(obs, y, want, o, rnd)
                print(f"  known-key control at line offset {o}"
                      + ("  <- from the table address" if o == derived
                         else "") + ":")
                for h, n_, m, se in rws:
                    print(f"      {h} collisions: n={n_:7d} mean {m:+.4f} "
                          f"+/- {se:.4f} us")
                print(f"      per-collision effect {slope * 1000:+.2f} ns, "
                      f"residual sd {sd:.4f} us")
                if slope:
                    p_hit = rnd.entries_per_line / 256.0
                    need = (sd / abs(slope)) ** 2 / p_hit
                    print(f"      order-of-magnitude traces per pair test: "
                          f"{need:,.0f}")

        print(f"  scoring {len(pairset)} pair tests ({a.model})")
        best = None
        for o in (range(rnd.entries_per_line) if a.sweep else [off]):
            k, mg = run(obs, y, o, want, verbose=False, pairs=pairset,
                        rnd=rnd)
            hit = sum(1 for j in range(16) if want and k[j] == want[j])
            print(f"    line offset {o}: {bytes(k).hex()}  "
                  f"margin {mg:.2f} sd" + (f"  {hit}/16" if want else ""))
            if best is None or mg > best[1]:
                best = (k, mg, o, hit)
        k, mg, o, hit = best
        results[name] = (bytes(k), hit)
        if a.ladder:
            for frac in (8, 4, 2):
                m = n // frac
                kk, mm = run(obs[:m], y[:m], o, want, verbose=False,
                             pairs=pairset, rnd=rnd)
                h = sum(1 for j in range(16) if want and kk[j] == want[j])
                print(f"    {m:8d} traces: margin {mm:5.2f} sd, {h}/16")
        if want is not None:
            print(f"  RECOVERED {hit}/16 bytes")

    print("\n" + "=" * 68)
    if key is not None:
        full = [nm for nm, (_, h) in results.items() if h == 16]
        if full:
            print("KEY RECOVERED from round " + " and ".join(full))
            if "first" in full:
                print("  round 1 gives K10; the AES key follows by "
                      "inverting the schedule (invert_ks in "
                      "the usual last-round scorer)")
            if "last" in full:
                print("  round 10 gives K0, which IS the AES key: "
                      + results["last"][0].hex())
        else:
            print("NOT RECOVERED.  A statistic is not a channel: a margin"
                  " without 16/16 is not a key")
            print("(research/mechanism/MEASURING_CHANNELS.md).  The"
                  " known-key control above says whether this is")
            print("a missing channel or a missing trace count.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
