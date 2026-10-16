"""flashmap CLI - `selftest`, `map`, `compare`.

    python -m flashmap selftest --port COM9
    python -m flashmap map      --port COM9 --out f429.json
    python -m flashmap map      --raw results/flashmap/f429.raw.json --out flashmap/f429.json   # offline
    python -m flashmap compare  f429.json g474.json
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from typing import Optional

from .device import DeviceError, open_device
from .experiments import (Bench, MeasurementSet, cfgname, default_plan,
                          selftest as host_selftest)
from .infer import Structure, infer_all, _is_isolated as is_isolated
from . import report as rep


def _policy_config(st, ms):
    """Which configuration the replacement-policy probes must run in.

    Not the headline one.  The headline geometry is the configuration with the
    most reuse, and on a part whose associativity is itself a knob that can be
    the DIRECT-MAPPED setting - which has no victim to choose, so every
    re-touch probe sized from it is empty (`k < ways` has no solutions at
    ways = 1).  Pick instead the isolated configuration with the largest
    measured associativity, and take the spacing from that configuration's own
    conflict period.
    """
    cache = st.get("cache")
    if cache is None or not cache.known or not cache.value.get("present"):
        return None
    per = (cache.data or {}).get("per_config", {})
    best = None
    for c in ms.configs():
        f = per.get(cfgname(c))
        if not isinstance(f, dict) or not f.get("ways") or f["ways"] < 2:
            continue
        key = (is_isolated(ms, c), f["ways"], f["period"])
        if best is None or key > best[0]:
            best = (key, c, f["ways"], f["period"] or f["line"])
    if best is None:
        return None
    return best[1], best[2], best[3]


def _reuse_config(st, ms):
    """The configuration the cache claim was measured in, for the replay pass."""
    cache = st.get("cache")
    want = (cache.value or {}).get("enabled_in") if (cache and cache.known) else None
    for c in ms.configs():
        if cfgname(c) == want:
            return c
    return ms.configs()[0]


def _structure_from_json(path: str) -> Structure:
    """Load either a raw MeasurementSet or an already-inferred Structure."""
    with open(path, "r", encoding="utf-8") as fh:
        d = json.load(fh)
    if "obs" in d:
        return infer_all(MeasurementSet.from_json(path))
    st = Structure(part=d.get("part", "?"), meta=d.get("meta", {}))
    from .infer import Claim
    for k, v in d.get("claims", {}).items():
        st.claims[k] = Claim(name=v["name"],
                             value=v["value"] if v.get("known", True) else None,
                             confidence=v.get("confidence", "none"),
                             basis=v.get("basis", ""),
                             evidence=v.get("evidence", []),
                             caveats=v.get("caveats", []),
                             data=v.get("data", {}))
    st.notes = d.get("notes", [])
    return st


def cmd_selftest(a) -> int:
    with open_device(a.port, a.baud, a.timeout,
                     transcript_path=a.transcript) as dev:
        print(f"-- flashmap selftest on {a.port}")
        ok, problems = host_selftest(dev)
    print()
    if ok:
        print("SELFTEST PASS - the shim is usable for `map`.")
        return 0
    print(f"SELFTEST FAIL ({len(problems)} problem(s)):")
    for p in problems:
        print(f"  - {p}")
    return 1


def cmd_map(a) -> int:
    if a.raw:
        ms = MeasurementSet.from_json(a.raw)
        print(f"-- re-inferring from {a.raw}: {ms!r}")
    else:
        if not a.port:
            print("map needs --port or --raw", file=sys.stderr)
            return 2
        t0 = time.time()

        def prog(i, n, el):
            rate = i / max(el, 1e-9)
            eta = (n - i) / max(rate, 1e-9)
            sys.stderr.write(f"\r  {i}/{n} steps  {el:5.0f}s elapsed  "
                             f"{eta:5.0f}s left   ")
            sys.stderr.flush()

        with open_device(a.port, a.baud, a.timeout,
                         transcript_path=a.transcript) as dev:
            ok, problems = dev.device_selftest()
            if not ok and not a.force:
                print(f"shim self-test failed: {problems}\n"
                      f"(pass --force to map anyway, but read the failure first: "
                      f"a frozen counter makes every structure look absent)",
                      file=sys.stderr)
                return 1
            bench = Bench(dev, reps=a.reps, progress=None if a.quiet else prog)
            # The reference wait state is MEASURED, not assumed: pick the
            # cheapest advertised setting that actually makes a miss resolvable
            # on this part (see Bench.calibrate_waitstates).
            ws_ref = bench.calibrate_waitstates()
            plan = default_plan(bench.knobs, bench.flash.size, depth=a.depth,
                                ws_ref=ws_ref)
            if not a.quiet:
                print(f"-- {bench.ident}")
                if getattr(bench, "ws_table", None):
                    print("-- wait-state calibration (flash penalty, "
                          "cyc/access): "
                          + " ".join("%d:%g" % t for t in bench.ws_table)
                          + f"  -> structural grid at waitstates={ws_ref}")
                print(f"-- plan: {len(plan)} steps x 2 regions x {a.reps} reps")
            ms = bench.run(plan)

            # Second phase: some experiments can only be SIZED from the first
            # phase's result. The LRU/FIFO discriminator needs the measured
            # associativity and conflict period, so it cannot live in the plan.
            first = infer_all(ms)
            pick = _policy_config(first, ms)
            if pick is None:
                if not a.quiet:
                    print("\n-- phase 2 skipped: no configuration fitted a "
                          "set-associative geometry, so there is no victim to "
                          "choose and no policy to measure")
            else:
                cfg, ways, sp = pick
                retouch = bench.supports_evict_start(sp)
                extra = bench.policy_plan(cfg, ways, sp, retouch=retouch)
                if not a.quiet:
                    print(f"\n-- phase 2: {len(extra)} steps sized from the "
                          f"measured geometry of {cfgname(cfg)} "
                          f"(ways={ways}, conflict period={sp} B)"
                          + ("" if retouch else
                             "; this shim does not honour the optional `evict` "
                             "walk start, so LRU and FIFO stay inseparable and "
                             "only the cyclic chase runs"))
                if extra:
                    bench.run(extra, into=ms)

            # Third phase, and it runs whether or not phase 2 did: the REPLAY
            # CONTROL.  Re-measure the `evict` rows nearest the measured
            # capacity, in the opposite order, so a probe whose result depends
            # on what ran before it is visible in the capture rather than
            # indistinguishable from a structure.  It is sized from the first
            # pass because where retention is marginal is not known until the
            # capacity has been measured - and on the H723, where no geometry
            # is fitted at all, this is the only control that fires.
            cv = first.value("cache")
            cap = (cv or {}).get("capacity_bytes") or (cv or {}).get("capacity_bytes_min")
            if cap:
                rcfg = _reuse_config(first, ms)
                sps = sorted({int(o.args[1]) for o in ms.rows("evict", "flash")
                              if len(o.args) == 2})
                replay = bench.replay_plan(rcfg, int(cap), sps)
                if not a.quiet:
                    print("")
                    print(f"-- phase 3: {len(replay)} replay-control steps "
                          f"around the measured {int(cap)} B capacity, in "
                          f"reverse order")
                if replay:
                    bench.run(replay, into=ms)
        if not a.quiet:
            sys.stderr.write("\n")
        print(f"-- captured {len(ms)} observations in {time.time()-t0:.0f}s")
        if ms.meta.get("warnings"):
            print("-- capture warnings:")
            for w in ms.meta["warnings"]:
                print(f"   ! {w}")
        if a.rawout:
            ms.to_json(a.rawout)
            print(f"-- raw measurements -> {a.rawout}")

    st = infer_all(ms)
    text = rep.render(st, evidence=not a.brief)
    print(text)
    if a.out:
        rep.to_json(st, a.out)
        print(f"-- structure -> {a.out}")
    if a.md:
        with open(a.md, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(rep.markdown(st))
        print(f"-- markdown -> {a.md}")
    return 0


def cmd_compare(a) -> int:
    sa = _structure_from_json(a.a)
    sb = _structure_from_json(a.b)
    print(rep.compare(sa, sb))
    return 0


def main(argv: Optional[list] = None) -> int:
    p = argparse.ArgumentParser("flashmap", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("--port", help="serial port, e.g. COM9 or /dev/ttyACM0")
        sp.add_argument("--baud", type=int, default=115200)
        sp.add_argument("--timeout", type=float, default=8.0)
        sp.add_argument("--transcript", help="write every protocol line here")

    s = sub.add_parser("selftest", help="exercise every command; fail loudly")
    common(s)
    s.set_defaults(fn=cmd_selftest)

    s = sub.add_parser("map", help="measure a part and infer its structure")
    common(s)
    s.add_argument("--out", help="inferred structure (JSON)")
    s.add_argument("--rawout", help="raw measurement set (JSON)")
    s.add_argument("--md", help="markdown datasheet")
    s.add_argument("--raw", help="re-infer from a saved measurement set instead "
                                 "of touching hardware")
    s.add_argument("--reps", type=int, default=7)
    s.add_argument("--depth", choices=("full", "quick"), default="full")
    s.add_argument("--brief", action="store_true", help="summary only, no evidence")
    s.add_argument("--quiet", action="store_true")
    s.add_argument("--force", action="store_true",
                   help="map even if the shim's own self-test fails")
    s.set_defaults(fn=cmd_map)

    s = sub.add_parser("compare", help="diff two mapped parts")
    s.add_argument("a")
    s.add_argument("b")
    s.set_defaults(fn=cmd_compare)

    a = p.parse_args(argv)
    try:
        return a.fn(a)
    except DeviceError as e:
        print(f"device error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
