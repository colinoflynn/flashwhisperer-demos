"""The gated Dongle campaign: reproduce stage 1, and only then run the rest of round 4.

Why the gate. §5j measured that on the nRF52840 Dongle the fault rate depends on the USB frame
phase a probe starts at, and two back-to-back 1.5 h stages of `r4-seed-2` showed that the
consequence is not throughput but validity: gated gave `p = 0.010` with argmin 244 reproducing
in both phase halves, while UNGATED -- the configuration every capture in this campaign used --
gave `p = 0.590`, a margin sitting on the label-shuffle null's own mean, and halves disagreeing
120/132. The discriminator is that ungated, the delta classes sit at systematically different
frame phases (per-class mean `ftrem` spanning 1 330 clocks against the gated 25), so a class
difference can be manufactured with no collision involved. Gating removes that by construction.

Why stage 1 runs again before anything else. One significant stage is not a channel. `p = 0.010`
is a single stage out of thirteen, and the split-half agreement that supports it comes from
INSIDE one run, so it shares anything at the run level. The only test of reproducibility is a
second independent gated run asking whether argmin 244 comes back -- 1 of 64 classes, so chance
agreement is 1.6 %.

The criterion is encoded rather than judged afterwards, because a driver that decides at 2 a.m.
should not be deciding on a hunch. Stage 1 must, in [`stage_stats.py`](stage_stats.py):

1. return **argmin 244** again,
2. at **p < 0.05** against 800 label shuffles, and
3. with the classes **phase-balanced** -- per-class `ftrem` spread under 200 clocks, which
   separates a gate that held (~25) from one that did not (1 330) with room to spare.

Fail any of the three and the run stops with the rest of round 4 unstarted, because the twelve
remaining stages CHAIN off stage 1's answer: `r4-chain-1` pins byte 2 from it, and every stage
after that builds on the pin. Eighteen hours spent extending a wrong pin is worse than nothing,
because the output would look like a campaign.

On success it continues in the SAME state file, so stage 1 is not repeated -- the reproducibility
run IS stage 1 of the campaign.

    python demos/fido2_usb/host/dongle_gated_campaign.py
    python demos/fido2_usb/host/dongle_gated_campaign.py --stage-hours 1.5 --expect 244
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
PY = sys.executable

LOG = HERE / "dongle_gated_campaign.log"
STATE = HERE / "dongle_campaign_state.json"
LADDER_LOG = HERE / "dongle_campaign_ladder.log"
STAGE1_NPZ = HERE / "ladder_r4-seed-2.npz"
STAGE1_KEEP = HERE / "ladder_r4-seed-2_gated2.npz"

# The first gated run's result, which this campaign's stage 1 has to reproduce.
REFERENCE = {"argmin": 244, "p": 0.013, "margin": 1.35, "n": 94235,
             "class_phase_spread": 25}


def log(m: str) -> None:
    line = f"{datetime.now():%Y-%m-%d %H:%M:%S}  {m}"
    with open(LOG, "a", encoding="utf-8", newline="\n") as f:
        f.write(line + "\n")
    print(line, flush=True)


def run(cmd: list[str], tag: str, env_extra: dict | None = None) -> int:
    log(f"--> {tag}: {' '.join(str(c) for c in cmd)}")
    env = dict(os.environ)
    env.update(env_extra or {})
    t0 = time.time()
    proc = subprocess.Popen([str(c) for c in cmd], cwd=str(ROOT), env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, bufsize=1, errors="replace")
    assert proc.stdout is not None
    for line in proc.stdout:
        line = line.rstrip()
        if line:
            log(f"    [{tag}] {line}")
    rc = proc.wait()
    log(f"<-- {tag}: rc={rc} after {(time.time() - t0) / 60:.1f} min")
    return rc


def ladder(args, env, max_stages: int | None) -> int:
    cmd = [PY, "-u", "demos/fido2_usb/host/ladder_campaign.py", "--round", "4",
           # Blind by construction: there is no SWD on this board to write a known key, and the
           # ladder uses --key for a logged CHECK only. Every verdict reads NO MATCH and that is
           # expected -- what the stages produce is relations, which a search consumes.
           "--key", "00000000000000000000000000000000",
           "--extend-hours", str(args.stage_hours),
           "--stall-minutes", str(args.stall_minutes),
           "--phase-lo", str(args.phase_lo), "--phase-hi", str(args.phase_hi),
           "--seed0", str(args.seed0),
           "--state", str(STATE), "--log", str(LADDER_LOG)]
    if max_stages:
        cmd += ["--max-stages", str(max_stages)]
    return ladder_run(cmd, env, max_stages)


def ladder_run(cmd: list[str], env: dict, max_stages: int | None) -> int:
    return run(cmd, "stage1" if max_stages == 1 else "rest", env)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--stage-hours", type=float, default=1.5)
    ap.add_argument("--stall-minutes", type=float, default=10.0)
    ap.add_argument("--phase-lo", type=int, default=18000)
    ap.add_argument("--phase-hi", type=int, default=23999)
    ap.add_argument("--seed0", type=int, default=1300000,
                    help="a DIFFERENT seed from the first gated run's 1200000, so stage 1 here "
                         "is an independent measurement rather than the same probe stream "
                         "replayed. Reproducing an argmin from identical inputs would test "
                         "determinism, not the channel.")
    ap.add_argument("--expect", type=int, default=REFERENCE["argmin"])
    ap.add_argument("--alpha", type=float, default=0.05)
    ap.add_argument("--shuffles", type=int, default=800)
    ap.add_argument("--fresh", action="store_true",
                    help="discard any existing campaign state and start from stage 1")
    ap.add_argument("--skip-repro", action="store_true",
                    help="stage 1 already reproduced in a previous invocation; go straight to "
                         "the remaining stages. Refuses if stage 1 is not complete in the "
                         "state file.")
    args = ap.parse_args()

    env = {"FIDO_VICTIM": "nrf52840dongle"}
    log("=" * 78)
    log(f"gated Dongle campaign, pid {os.getpid()}; phase "
        f"[{args.phase_lo},{args.phase_hi}) seed0 {args.seed0}")
    log(f"reference to reproduce: argmin {args.expect} "
        f"(first gated run: p={REFERENCE['p']}, margin {REFERENCE['margin']:+.2f} sigma, "
        f"n/class from {REFERENCE['n']} probes)")

    if args.fresh and STATE.exists():
        log(f"--fresh: removing {STATE.name}")
        STATE.unlink()

    # ---- phase 1: reproduce stage 1 -------------------------------------------------------
    if not args.skip_repro:
        if STAGE1_NPZ.exists():
            # ladder_r4-seed-2.npz currently holds the UNGATED control; it is already preserved
            # as _ungated, but do not let this run be the thing that loses a copy.
            log(f"note: {STAGE1_NPZ.name} exists and will be overwritten by stage 1")
        rc = ladder(args, env, max_stages=1)
        if rc != 0:
            log(f"stage 1 exited {rc}; stopping rather than extending an unknown pin")
            return rc
        if not STAGE1_NPZ.exists():
            log("stage 1 wrote no npz; stopping")
            return 2
        STAGE1_KEEP.write_bytes(STAGE1_NPZ.read_bytes())
        log(f"stage 1 raw data preserved as {STAGE1_KEEP.name}")

        rc = run([PY, "-u", "demos/fido2_usb/host/stage_stats.py", str(STAGE1_KEEP),
                  "--shuffles", str(args.shuffles), "--expect-argmin", str(args.expect),
                  "--alpha", str(args.alpha)], "check")
        if rc != 0:
            log("=" * 78)
            log("STAGE 1 DID NOT REPRODUCE. The remaining twelve stages are NOT being run.")
            log("They chain off stage 1: r4-chain-1 pins byte 2 from it and everything after "
                "builds on that pin, so eighteen hours of extension would produce output that "
                "LOOKS like a campaign and rests on a pin that did not replicate.")
            log("What this means, stated carefully: the first gated run's p=0.013 was one "
                "stage out of thirteen, and a single stage clearing 0.05 is suggestive rather "
                "than established. A failure here says the gated configuration is not yet "
                "producing a reproducible measurement on this board -- not that the channel is "
                "absent, and not that gating is wrong, since the ungated arm measured nothing "
                "at all.")
            log("Next thing to try: a third gated stage to see whether either answer recurs, "
                "and re-measure the phase window, which MOVES with request length.")
            return 3
        log("stage 1 reproduced; continuing with the rest of round 4")
    else:
        st = json.loads(STATE.read_text()).get("stages", {}) if STATE.exists() else {}
        if not (st.get("r4-seed-2") or {}).get("complete"):
            log("--skip-repro given but stage 1 is not complete in the state file; refusing")
            return 4
        log("--skip-repro: stage 1 already complete, going to the remaining stages")

    # ---- phase 2: the rest of round 4 -----------------------------------------------------
    log(f"the remaining stages at {args.stage_hours} h each; round 4 holds thirteen and one "
        f"is done")
    rc = ladder(args, env, max_stages=None)
    log("=" * 78)
    if STATE.exists():
        st = json.loads(STATE.read_text()).get("stages", {})
        done = [k for k, v in st.items() if v.get("complete")]
        log(f"complete stages: {sorted(done)}")
        for k in sorted(done):
            v = st[k]
            log(f"  {k}: argmin {v.get('offset')}, dip {v.get('delta_vs_others')}, "
                f"margin {v.get('margin_sigma')}, n/class {v.get('n_per_class')}, "
                f"escalations {v.get('escalations')}")
    log("Every verdict reads NO MATCH by construction: this board has no SWD, so no known key "
        "entered any decision. The stages produce RELATIONS; whether they are right is settled "
        "by the search, and only by a key that decrypts the credential already captured in "
        "dongle_oracle.json.")
    log("Re-run stage_stats.py over every ladder_*.npz before trusting any stage: a stage with "
        "a large per-class ftrem phase spread is confounded whatever its margin says.")
    return rc


if __name__ == "__main__":
    sys.exit(main())
