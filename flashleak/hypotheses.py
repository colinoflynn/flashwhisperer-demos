"""Turning the statistics into statements about an unknown target.

The assessor is assumed to know only that bytes go in or out of something doing
crypto. They do not know whether they are watching plaintext or ciphertext,
encryption or decryption, ECB or CTR, or what table layout the implementation
uses. Each question below is decided by running a test whose *outcome differs*
between the answers, rather than by being told.

What the observation position actually decides
----------------------------------------------
The collision channel is visible from either side of the cipher, but it says
different things:

  observed block is the OUTPUT of a final round without MixColumns
      -> each byte is one lookup, index `tbl[B[j] ^ k[j]]`, key AFTER the
         lookup and behind an S-box. Nonlinear, so absolute key bytes. This is
         the position that leads to a whole key on its own.

  observed block is the INPUT
      -> index is `B[j] ^ k[j]`, key BEFORE the lookup and linear, so a
         collision only ever reveals `k[a] ^ k[b]` at line granularity. Still a
         strong finding, and a round-2 pass can finish it, but it is not the
         same position.

A fixed unknown XOR mask on the observed data does not hide the output side: for
a guess `g`, `tbl[B[j] ^ g]` with `B = out ^ m` is `tbl[out ^ (m ^ g)]`, so the
mask is absorbed into the recovered bytes. That is why a CTR keystream, a
ciphertext, and a ciphertext XOR some constant header all look alike here - and
why detection does not require knowing the mode.

What *does* break the output side is a mask that VARIES per block and is unknown,
which is exactly CBC decryption observed as plaintext only (`P_i = D(K,C_i) ^
C_(i-1)`). If both sides are observed, XOR them back together first; see
`combine_cbc`.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np

from . import probe

#: Mean-peak excess over the shuffled floor that a capture known to yield a key
#: showed. On the F429 OSCORE capture the per-offset peaks were
#: 4.31 4.23 6.40 4.38 4.37 4.36 4.27 4.21 - mean 4.57 against a 4.33 floor, so
#: an excess of about 0.24, and that capture recovered a key at 200 k traces.
#:
#: Careful with this number: it is calibrated for the MEAN peak over pairs, not
#: a single pair's peak. An earlier version used 2.0, which is the right scale
#: for one strong pair and roughly eight times too big for the mean - it turned
#: a 250 k capture that really is breakable into an estimate of 96 million
#: traces.
#:
#: And it estimates when THIS key-free detector would be confident, which is not
#: the same as when a key-known attack succeeds. The detector is strictly the
#: weaker instrument; treat its estimate as an upper bound on the attacker's
#: cost, never a lower one.
#:
#: STALE, AND KNOWN TO BE. The 0.24 above was measured while `probe.condition`
#: was splitting unimodal timing into spurious modes and re-centring each one,
#: which cost about 60 % of this statistic on the one capture that could be
#: rechecked. Whatever that capture's excess really was, it was larger than
#: 0.24, so this constant is too small and every estimate derived from it is
#: too optimistic. It shows: on the tinyaes vector the detector now says
#: "order 3,083 traces" where the key-known ladder needs 250 000 for the full
#: key and gets 4/16 at 50 000 - the "upper bound on the attacker's cost"
#: promise above is violated by about 80x there.
#:
#: Re-measuring it needs the F429 OSCORE capture, which is untracked and not
#: in this repository, so it is left alone rather than guessed at. Until
#: someone re-runs it with conditioning fixed, read the trace estimate as an
#: order of magnitude and nothing more.
RECOVERY_EXCESS = 0.25

#: Two thresholds, because neither statistic settles it alone.
#:
#: `concentration` (median over all 120 pairs) identifies the input side when
#: every pair can collide, and reads ~0 when the layout PARTITIONS the channel.
#: `concentration_family` (best offset family) rescues the partitioned case --
#: but partitioning raises it on EITHER side, so it needs a higher bar.
#: Measured, real captures first:
#:
#:                                             truth    pooled  family
#:   tiny-AES decrypt, observed ciphertext     input      2.78    3.39   (*)
#:   mbedTLS compact decrypt, observed ct      input      7.73    8.93   (*)
#:   mbedTLS 4-table decrypt, observed ct      input      0.56   10.05   (*)
#:   SNMPv3 CFB keystream                      output     0.38    0.53   (*)
#:   simulated single-table, observe input     input      6.17    6.74
#:   simulated 4-table,      observe input     input      0.71   16.61
#:   simulated single-table, observe output    output     0.40    0.81
#:   simulated 4-table,      observe output    output     0.48    0.79
#:
#: (*) measured before `probe.condition` stopped splitting unimodal timing
#: into spurious modes; those four captures are untracked and could not be
#: re-run here. The four simulated rows WERE re-measured after that fix and
#: are the numbers shown. All eight still classify correctly, and the narrow
#: case got wider rather than narrower: the two 4-table rows used to sit at
#: 10.05 against 2.11 on the family statistic and now sit at 16.61 against
#: 0.79, so the bar at 5.0 has more room on both sides than when it was set.
#:
#: A target is called input-side if EITHER bar is cleared; every row above is
#: then classified correctly. The narrow case is a partitioned layout seen from
#: the output side (2.11) against a partitioned input-side capture (10.05) --
#: about 5x, where unpartitioned cases separate by 20x. Treat a 4-table call as
#: the least certain thing this tool says.
#:
#: The 4-table row was a hold-out: it was not used to set either threshold, and
#: on the first version of this rule it was misclassified. Calibration uses only
#: captures with NO runtime FLASH_ACR change; the encrypt vector used earlier
#: went through a defective ACR handler and is excluded.
CONCENTRATION_FIRES = 1.0

#: Bar for the best-offset-family statistic, which only partitioned layouts clear.
CONCENTRATION_FAMILY_FIRES = 5.0

#: How far over its own shuffled floor the output-side mean peak has to sit,
#: in standard errors of that floor, before the side is called.
#:
#: The width is SELECTED by `probe.output_shift_scan` and then scored, so
#: this covers a maximum over four row widths and the null is inflated. Both
#: numbers here are measured against that, not inherited from the fixed-width
#: version: 20 draws of pure N(1000, 3), no cipher in them at all, 20 000
#: traces each, conditioned exactly as a real capture would be, scanned and
#: then scored through the identical call.
#:
#:     null, 20 draws:  mean +0.29   sd 1.66   max +3.72
#:
#: 4.0 was the fixed-width bar and a null draw reached 3.72, so it does not
#: survive selection - which an 8-draw pilot had missed at max +2.16. 6.0
#: sits 3.4 sd above the null mean. Real cases are nowhere near it: the
#: tinyaes vector reads +39.5 at its true width, the simulated four-table
#: target +56 at 20 000 traces, the single-table one +16.6 at 50 000.
OUTPUT_FIRES = 6.0

#: Below `OUTPUT_FIRES` but above this, the answer is "suggestive" rather than
#: "nothing". A target that IS exploitable but under-sampled lands here, and
#: calling that clean would be the most damaging thing this tool could do.
#:
#: This was 1.5 when the row width was fixed. Under selection that is below
#: the null's own mean plus one sd, and pure noise read "suggestive" about
#: half the time - the negative control in `selftest` is what caught it. 4.0
#: is just above the largest null draw seen in 20.
#:
#: Note what that costs. The band a fixed-width rule would have hedged now
#: reads "none detected", and this detector is already the weaker instrument
#: - `assess` says so in its own notes. Read a quiet result as "not at this
#: trace count", never as "safe".
OUTPUT_SUGGESTIVE = 4.0


@dataclass
class Finding:
    question: str
    answer: str
    confidence: str          # "strong" | "weak" | "none"
    evidence: str

    def __str__(self):
        return f"{self.question}: {self.answer}  [{self.confidence}] - {self.evidence}"


@dataclass
class Assessment:
    timing: dict
    tests: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)
    notes: list = field(default_factory=list)

    def add(self, *a):
        self.findings.append(Finding(*a))


def combine_cbc(plaintexts, ciphertexts):
    """Recover the block cipher's raw output from an observed CBC decryption.

    `P_i = D(K, C_i) ^ C_(i-1)`, so `D(K, C_i) = P_i ^ C_(i-1)`. Pass the
    plaintext blocks and the ciphertext blocks *in order*, including the IV as
    ciphertext block 0; returns the raw outputs, which are what the output-side
    test wants. Without this step CBC decryption looks like noise to that test,
    because the per-block mask varies.
    """
    p = np.asarray(plaintexts, np.uint8)
    c = np.asarray(ciphertexts, np.uint8)
    if len(c) != len(p) + 1:
        raise ValueError("need one more ciphertext block than plaintext blocks "
                         "(the IV is ciphertext block 0)")
    return p ^ c[:-1]


def granularity_sweep(blocks, timing, shifts=(1, 2, 3, 4), n_shuffle=32):
    """Which line granularity does the channel actually resolve?

    Cheap input-side test at several assumed line widths. The finest shift that
    still shows structure bounds the effective granularity, which in turn hints
    at the table's entry size - 1-byte entries in a 16-byte line give 4-byte
    resolution when there is sub-line structure, 4-byte T-table entries give the
    same from a different cause. Mostly this exists so the expensive tests can be
    run at a sensible width instead of a guessed one.
    """
    out = {}
    for s in shifts:
        r = probe.pair_input_test(blocks, timing, line_shift=s,
                                  n_shuffle=n_shuffle, seed=s)
        out[s] = r
    return out


def assess(blocks, timing, *, quick=False, seed=0) -> Assessment:
    """Full battery on observed (block, timing) pairs. No key, no mode, no role.

    `quick=True` skips the 2^16 output-side search, which is most of the runtime.
    """
    blocks = np.asarray(blocks)
    timing = np.asarray(timing, float)
    a = Assessment(timing=probe.timing_summary(timing))
    if a.timing["constant_time"]:
        pass                                 # nothing to condition
    else:
        blocks, timing, cond = probe.condition(blocks, timing)
        a.tests["conditioning"] = cond
        if cond["modes"] > 1 or cond["dropped_outliers"]:
            a.notes.append(
                f"conditioned first: dropped {cond['dropped_outliers']} outliers "
                f"and found {cond['modes']} timing mode(s), centring each on its "
                f"own median. Sigma went {cond['sigma_raw']:.1f} -> "
                f"{cond['sigma_conditioned']:.1f}. Raw multi-mode timing hides "
                "this channel completely - every statistic below is measured in "
                "units of that sigma.")

    # ---- 0. is there anything to measure? -------------------------------
    if a.timing["constant_time"]:
        a.add("data-dependent timing", "NO - constant time", "strong",
              f"{a.timing['distinct']} distinct timing values in "
              f"{a.timing['n']} measurements")
        a.notes.append("Nothing downstream can leak if the clock never moves. "
                       "Check the measurement really has the resolution you "
                       "think (timing.quantum) before concluding the target is "
                       "safe.")
        return a
    if a.timing["n"] < 2000:
        a.notes.append(f"only {a.timing['n']} traces - treat every result below "
                       "as provisional; this channel usually needs 1e4-1e6")

    # ---- 1. model-free: does the data move the clock? -------------------
    dd = probe.data_dependence(blocks, timing, n_shuffle=64 if quick else 200,
                               seed=seed)
    a.tests["data_dependence"] = dd
    a.add("byte values change the timing",
          "yes" if dd.fired else "not detectably", "strong" if dd.fired else "weak",
          f"z = {dd.z:+.1f} against a shuffled null")
    if not dd.fired:
        a.notes.append("A flat model-free result does NOT clear the target: "
                       "cache-collision leakage lives in *pairs* of bytes and is "
                       "normally invisible here. The pair tests below are the "
                       "ones that matter.")

    # ---- 2. which granularity, and is the input side live? --------------
    sweep = granularity_sweep(blocks, timing, n_shuffle=16 if quick else 32)
    a.tests["granularity"] = sweep
    # Concentration, not the dip, decides whether the INPUT-side model fits:
    # input-side leakage is a function of B[a]^B[b] alone, so one bucket stands
    # clear; anything else smears. It peaks at the true line width, which is
    # therefore also the granularity estimate.
    conc = {s: r.detail.get("concentration", 0.0) for s, r in sweep.items()}
    fam = {s: r.detail.get("concentration_family", 0.0) for s, r in sweep.items()}
    a.tests["xor_concentration"] = conc
    a.tests["xor_concentration_family"] = fam
    partitioned = (max(conc.values()) < CONCENTRATION_FIRES
                   and max(fam.values()) >= CONCENTRATION_FAMILY_FIRES)
    best_shift = max(fam, key=fam.get) if partitioned else max(conc, key=conc.get)
    input_side = (max(conc.values()) >= CONCENTRATION_FIRES) or partitioned
    shift = best_shift if input_side else 2

    if input_side:
        a.add("what the observed block is", "consistent with the cipher INPUT",
              "strong",
              f"the XOR bucketing concentrates (pooled {max(conc.values()):.2f} "
              f"vs {CONCENTRATION_FIRES:.1f}, best offset family "
              f"{max(fam.values()):.2f} vs {CONCENTRATION_FAMILY_FIRES:.1f}, at "
              f"{1 << best_shift} bytes"
              + ("; only the family bar cleared, so the layout partitions the "
                 "channel and this call is the less certain kind" if partitioned else "")
              + "); "
              "only a lookup indexed by block^key makes one bucket stand out "
              "like that")
        a.add("recoverable key material",
              "key-byte DIFFERENCES at line granularity, not absolute bytes",
              "strong",
              "the key enters before the lookup and linearly; a round-2 pass "
              "can finish it on a single-table implementation "
              "(see flashattack/ROUND2.md)")
        a.add("effective line granularity",
              f"no finer than {1 << shift} bytes", "weak",
              "the width where the XOR bucketing concentrates most: "
              + ", ".join(f"{1<<s}B:{c:.2f}" for s, c in conc.items())
              + ". This is an UPPER bound and biased coarse - wider buckets "
              "hold more traces and so dip harder. On a capture where the "
              "round-1 difference sweep resolves 4-byte granularity, this "
              "statistic still peaks at 16. For the real number, sweep "
              "line_shift against recovered differences instead "
              "(research/round2/round2_decrypt.py)")
    else:
        a.notes.append("line granularity not estimated: that reading comes from "
                       "the input-side model, which does not fit here")

    inp = sweep[shift] if shift in sweep else probe.pair_input_test(blocks, timing, shift)
    a.tests["pair_input"] = inp

    # ---- 3. the expensive output-side tests -----------------------------
    if quick:
        if input_side:
            a.add("what the observed block is", "consistent with the cipher INPUT",
                  "strong",
                  f"XOR bucketing concentrates ({conc[shift]:.1f}) at "
                  f"{1<<shift} bytes, which only the input-side model explains")
        elif inp.fired:
            a.add("cache-collision structure", "present", "strong",
                  f"pair test z = {inp.z:+.1f} against a shuffled null")
            a.add("which side of the cipher you are on", "UNDETERMINED", "none",
                  "the pair test responds to leakage from either side; only the "
                  "output-side search separates them, and --quick skipped it")
            prof = probe.offset_profile(inp.detail["per_pair"])
            a.tests["offset_profile"] = prof
            a.add("table layout", _layout(prof, invert=True), "weak",
                  "mean dip by byte offset: "
                  + ", ".join(f"{d}:{v:.2f}" for d, v in prof.items()))
        else:
            a.add("cache-collision structure", "none detected", "weak",
                  f"pair test z = {inp.z:+.1f}")
        a.notes.append("quick mode skipped the 2^16 output-side search. That is "
                       "the test that says whether a whole key is recoverable "
                       "and which side you are observing; re-run without "
                       "--quick before drawing either conclusion.")
        return a

    # The row width for the OUTPUT side is its own question. The input-side
    # sweep above answers it only when the input side is live, because that is
    # where the XOR bucketing concentrates; on an output-side capture it reads
    # flat at every width and `best_shift` is whichever noise peak won. This
    # used to fall back to a constant 2, which is a guess, and a wrong row
    # width here returns a clean null rather than a degraded one.
    if input_side:
        out_shift, scan = shift, None
    else:
        out_shift, scan = probe.output_shift_scan(blocks, timing, seed=seed)
        a.tests["output_shift_scan"] = scan
        a.tests["output_shift"] = out_shift

    sub = [(i, (i + 4) % 16) for i in range(8)] + [(i, (i + 3) % 16) for i in range(4)]
    sub = [(min(x, y), max(x, y)) for x, y in sub if x != y]
    enc = probe.pair_output_test(blocks, timing, "enc", out_shift, pairs=sub)
    dec = probe.pair_output_test(blocks, timing, "dec", out_shift, pairs=sub)
    a.tests["pair_output_enc"] = enc
    a.tests["pair_output_dec"] = dec
    a.tests["floor_check"] = probe.floor_check(blocks, timing, "enc", out_shift,
                                               seed=seed)
    if scan is not None:
        a.notes.append(
            "the output-side row width was scanned rather than assumed: "
            + ", ".join(f"{1 << s} entries:{v:+.1f}"
                        for s, v in sorted(scan.items()))
            + f" over each width's own shuffled floor, so {1 << out_shift} "
            "entries per row was scored. A wrong width here returns a clean "
            "null, not a weak reading")
    _conclude(a, inp, enc, dec, out_shift, input_side, blocks, timing)
    return a


def _conclude(a: Assessment, inp, enc, dec, shift, input_side_already=False,
              a_blocks=None, a_timing=None):
    """Assemble the role / layout / cost statements."""
    fl = a.tests.get("floor_check")
    if fl and abs(fl["mean"] - probe.OUTPUT_NOISE_FLOOR) > 0.6:
        a.notes.append(
            f"the output-side noise floor measured {fl['mean']:.2f} on shuffled "
            f"timings here, not the assumed {probe.OUTPUT_NOISE_FLOOR}; z values "
            "for those tests are read against the assumed floor and are "
            "correspondingly off")

    # Compare against the floor measured on THIS data, not the assumed one --
    # the analytic 4.2 is a property of a 65536-cell maximum under ideal noise
    # and real captures sit a few tenths either side of it.
    floor = fl["mean"] if fl else probe.OUTPUT_NOISE_FLOOR
    # z of the observed mean peak against the shuffled mean peak, both over a
    # comparable number of pairs.
    se = fl["se"] if fl and fl.get("se") else 0.1
    out_fired = []
    for r, label in ((enc, "encryption output (ciphertext / keystream)"),
                     (dec, "decryption output (plaintext)")):
        if r is not None and (r.statistic - floor) / max(se, 1e-9) > OUTPUT_FIRES:
            out_fired.append((r, label))

    # The 2^16 search is not specific either: given 65536 guesses it can find a
    # partition that partly overlaps genuine input-side leakage. So when the XOR
    # bucketing has already concentrated, the input-side reading wins.
    if (a.tests.get("xor_concentration")
            and (max(a.tests["xor_concentration"].values()) >= CONCENTRATION_FIRES
                 or max(a.tests.get("xor_concentration_family", {0: 0}).values())
                 >= CONCENTRATION_FAMILY_FIRES)):
        out_fired = []

    if input_side_already:
        prof = probe.offset_profile(inp.detail["per_pair"])
        a.tests["offset_profile"] = prof
        a.add("table layout", _layout(prof, invert=True), "weak",
              "mean dip by byte offset: "
              + ", ".join(f"{d}:{v:.2f}" for d, v in prof.items()))
        return
    if out_fired:
        out_fired.sort(key=lambda t: -t[0].statistic)
        best, label = out_fired[0]
        conf = "strong" if len(out_fired) == 1 else "weak"
        a.add("what the observed block is", f"consistent with a cipher {label}",
              conf,
              f"peak {best.statistic:.2f} vs measured floor {floor:.2f}"
              + ("; both directions fired, so the direction is not resolved"
                 if len(out_fired) > 1 else ""))
        a.add("recoverable key material", "absolute key bytes (whole key)", conf,
              "the key enters after the lookup, behind an S-box, so collisions "
              "are nonlinear in it")
        excess = best.statistic - floor
        need = a.timing["n"] * (RECOVERY_EXCESS / max(excess, 1e-6)) ** 2
        a.add("traces for this detector to be confident",
              f"order {need:,.0f}", "weak",
              f"mean-peak excess {excess:.2f} now, scaling as sqrt(n) toward "
              f"~{RECOVERY_EXCESS}. An attacker who knows the key is "
              "confirming rather than searching, and gets there sooner - "
              "read this as an upper bound on their cost, not a lower one")
        # Layout has to come from the SAME side the leak is on, over ALL 120
        # pairs. Two ways of getting this wrong were tried first: the output
        # test's 12-pair subset spans two offsets and called a single-table
        # target "four tables" because offset 4 beat offset 3; and the cheap
        # input-side profile, which is blind to an output-side leak, put a
        # TinyCrypt-style offset-3 family at offset 7. So pay for the full scan
        # on the winning direction - about 120 pair searches.
        side = "enc" if "encryption" in label else "dec"
        full = probe.pair_output_test(a_blocks, a_timing, side, shift)
        a.tests[f"pair_output_{side}_full"] = full
        prof = probe.offset_profile(full.detail["per_pair"])
        a.tests["offset_profile"] = prof
        a.add("table layout", _layout(prof), "weak",
              "mean peak by byte offset over all 120 pairs: "
              + ", ".join(f"{d}:{v:.2f}" for d, v in prof.items()))
    elif inp.fired:
        # Structure is there, but nothing identifies which side of the cipher it
        # is on. Saying "input" here would be a wrong headline dressed as a weak
        # one: the input-side test is not specific, and only the concentration
        # statistic is. Undetermined is the honest answer.
        a.add("cache-collision structure", "present", "strong",
              f"pair test z = {inp.z:+.1f} against a shuffled null")
        a.add("which side of the cipher you are on", "UNDETERMINED", "none",
              f"the XOR bucketing did not concentrate "
              f"(max {max(a.tests['xor_concentration'].values()):.2f}, needs "
              f"{CONCENTRATION_FIRES:.1f}) so the input-side model does not fit, "
              "and the output-side search did not clear its floor either. More "
              "traces is the fix: the output-side test is the one that "
              "sharpens with n")
        prof = probe.offset_profile(inp.detail["per_pair"])
        a.tests["offset_profile"] = prof
        a.add("table layout", _layout(prof, invert=True), "weak",
              "mean dip by byte offset: "
              + ", ".join(f"{d}:{v:.2f}" for d, v in prof.items()))
    else:
        # A positive-but-small excess is worth saying out loud. The key-free
        # tests here are strictly weaker than a key-known attack on the same
        # traces - this repo's SNMPv3 capture yields a key, and reads only
        # +0.7 over the floor to a detector that does not know the key. Calling
        # that "clean" would be the most damaging thing this tool could do.
        best_excess = max([(r.statistic - floor) for r in (enc, dec)
                           if r is not None], default=0.0)
        if best_excess / max(se, 1e-9) > OUTPUT_SUGGESTIVE:
            need = a.timing["n"] * (RECOVERY_EXCESS / best_excess) ** 2
            a.add("cache-collision leakage",
                  "SUGGESTIVE - above the floor but below the firing threshold",
                  "weak",
                  f"best output-side excess {best_excess:+.2f} over a measured "
                  f"floor of {floor:.2f}. Excess grows as sqrt(n), so order "
                  f"{need:,.0f} traces would settle it for this detector")
            a.notes.append("A sub-threshold excess is the expected reading for a "
                           "target that IS exploitable but under-sampled. Do not "
                           "record this as a pass.")
        else:
            a.add("cache-collision leakage", "none detected", "weak",
                  "neither the input-side nor the output-side test cleared its "
                  f"null; best output-side excess {best_excess:+.2f}")
        a.notes.append("Absence of evidence at this trace count is not evidence "
                       "of absence. Re-run with more traces, and if you can "
                       "control the input use the fixed-vs-random probe, which "
                       "is far more sensitive than anything here.")


def _layout(profile: dict, invert=False) -> str:
    """Read a table layout off the offset profile.

    Needs the profile to span most offsets: with only two or three of them a
    ranking is a coin toss, not a layout.
    """
    if len(profile) < 6:
        return "not determined (too few byte offsets measured)"
    vals = {d: (-v if invert else v) for d, v in profile.items()}
    order = sorted(vals, key=lambda d: -vals[d])
    top = order[0]
    rest = [vals[d] for d in order[1:]]
    if not rest:
        return "unknown"
    spread = max(rest) - min(rest) or 1e-9
    lead = vals[top] - max(rest)
    mod4 = [d for d in vals if d % 4 == 0]
    other = [vals[x] for x in vals if x % 4]
    if len(mod4) >= 2 and other:
        # every 0-mod-4 offset must beat every other one, and by more than the
        # spread among the others - otherwise this is just a ranking
        gap = min(vals[d] for d in mod4) - max(other)
        if gap > 0 and gap > (max(other) - min(other)):
            return ("four separate tables indexed by row (only offsets 0 mod 4 "
                    "can collide) - the channel is partitioned, not suppressed")
    if lead > 3 * spread:
        return (f"one access family dominates (offset {top} in OBSERVED byte "
                "order) - a single table reached in an order that only lets "
                "that family meet. Note ShiftRows permutes state positions "
                "before they become observable bytes, so this offset need not "
                "equal the one in the implementation's own coordinates")
    return "one shared table across all offsets - the fully exposed case"
