"""Command line: python -m flashleak <command>

  analyse FILE         assess recorded (blocks, timing)
  probe   TARGET       drive a live target, then assess what it gave back
  selftest             run the detector against simulated targets whose answers
                       are known, including the negative controls
  fwscan  PATH         static triage of a firmware image, directory or archive:
                       XIP MCU? AES tables in flash, and in which layout?
  placement PATH       the *build* question rather than the library question:
                       will those tables be READ FROM FLASH at run time? Works
                       from a linked .elf (exact), a raw .bin (inferred from the
                       start-up copy loop and the literal pool), or an unlinked
                       .o/.a (conditional on the linker script, which it can
                       also check)

A recorded file is an .npz or .csv. For .npz the block array is found by trying
the usual names (blocks, window, ciphertext, keystream, plaintext, data, pts)
and the timing by (timing, cyc, dt_hw, t, cycles); override with --blocks-key
and --timing-key. For .csv, 16 hex-or-decimal byte columns plus a timing column,
or one hex string column plus a timing column.
"""
from __future__ import annotations

import argparse
import importlib
import sys

import numpy as np

from . import hypotheses, report, target as target_mod

BLOCK_KEYS = ("blocks", "window", "ciphertext", "keystream", "plaintext",
              "data", "pts", "inputs", "outputs")
TIME_KEYS = ("timing", "cyc", "dt_hw", "t", "cycles", "time", "dt")


def load(path, blocks_key=None, timing_key=None, block_offset=0):
    if path.endswith(".npz"):
        d = np.load(path, allow_pickle=True)
        bk = blocks_key or next((k for k in BLOCK_KEYS if k in d.files), None)
        tk = timing_key or next((k for k in TIME_KEYS if k in d.files), None)
        if bk is None or tk is None:
            raise SystemExit(f"could not find blocks/timing in {path}; "
                             f"keys are {list(d.files)}")
        b = np.asarray(d[bk])
        if b.ndim == 2 and b.shape[1] > 16:
            b = b[:, block_offset:block_offset + 16]
        print(f"  using blocks='{bk}' {b.shape}, timing='{tk}'")
        return b.astype(np.uint8), np.asarray(d[tk], float)
    rows, times = [], []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line[0] in "#bB" and not line[0].isdigit():
                if not any(c.isdigit() for c in line):
                    continue
            parts = [p for p in line.replace(",", " ").split() if p]
            if len(parts) == 2:
                rows.append(list(bytes.fromhex(parts[0])))
                times.append(float(parts[1]))
            elif len(parts) >= 17:
                rows.append([int(x, 0) for x in parts[:16]])
                times.append(float(parts[16]))
    if not rows:
        raise SystemExit(f"no usable rows in {path}")
    return np.array(rows, np.uint8), np.array(times, float)


def cmd_analyse(a):
    blocks, timing = load(a.file, a.blocks_key, a.timing_key, a.block_offset)
    if a.limit:
        blocks, timing = blocks[:a.limit], timing[:a.limit]
    res = hypotheses.assess(blocks, timing, quick=a.quick)
    print(report.render(res))
    if a.json:
        open(a.json, "w").write(report.to_json(res))
        print(f"wrote {a.json}")


def _load_target(spec):
    """'module:Factory(arg=...)' or 'sim:layout=four,direction=dec'."""
    if spec.startswith("sim:") or spec == "sim":
        kw = {}
        for kv in spec[4:].split(",") if ":" in spec else []:
            if not kv:
                continue
            k, _, v = kv.partition("=")
            kw[k] = int(v) if v.isdigit() else v
        return target_mod.SimulatedTarget(**kw)
    mod, _, rest = spec.partition(":")
    if not rest:
        raise SystemExit("target must be 'module:Factory(...)' or 'sim:...'")
    m = importlib.import_module(mod)
    return eval(rest, {"__builtins__": {}}, vars(m))       # noqa: S307


def cmd_probe(a):
    tgt = _load_target(a.target)
    print("determinism:")
    d = target_mod.determinism(tgt, trials=a.det_trials)
    for k, v in d.items():
        print(f"  {k:<22} {v}")
    if not d["deterministic"]:
        print("  -> repeated measurements differ; --repeats will help, and a "
              "better clock would help more")
    print("\nfixed-vs-random (model-free):")
    fr = target_mod.fixed_vs_random(tgt, n=a.tvla, repeats=a.repeats)
    for k, v in fr.items():
        print(f"  {k:<22} {v}")
    print("  -> " + ("LEAKING: timing depends on the data"
                     if fr["leaking"] else
                     "no data-dependent timing at this trace count"))
    if a.n:
        print(f"\ncollecting {a.n} traces...")
        blocks, timing = target_mod.collect(tgt, a.n, repeats=a.repeats,
                                            progress=max(a.n // 10, 1))
        res = hypotheses.assess(blocks, timing, quick=a.quick)
        print(report.render(res))
        if a.json:
            open(a.json, "w").write(report.to_json(res))


def cmd_selftest(a):
    """Every conclusion the tool can draw, against a target that knows the truth."""
    cases = [
        ("encrypt, observe ciphertext, single table",
         dict(direction="enc", observe="output", layout="single"),
         "encryption output"),
        ("decrypt, observe plaintext, single table",
         dict(direction="dec", observe="output", layout="single"),
         "decryption output"),
        ("encrypt, observe plaintext (input side)",
         dict(direction="enc", observe="input", layout="single"),
         "cipher INPUT"),
        ("four separate tables",
         dict(direction="enc", observe="output", layout="four"),
         "encryption output"),
        ("constant time (negative control)",
         dict(layout="none", noise=0.0), "constant time"),
        ("noise only, no channel (negative control)",
         dict(layout="none", noise=3.0), "none detected"),
    ]
    # 20 000 was the default for a long time and it is not enough: the
    # "encrypt, observe ciphertext" case reads +0.19 over its floor there and
    # +40 at 50 000, so the detector was being graded on a capture it could
    # not have called either way. The other five cases pass at 20 000; this
    # one sets the number. Pass --n to go lower if you only want a smoke test.
    n = a.n or 50000
    # --quick skips the 2^16 output-side search, which is the only thing that
    # can answer four of these six. Grading them anyway reported 2/6 and read
    # as four failures rather than as four questions nobody asked.
    if a.quick:
        cases = [c for c in cases if "output" not in c[2].lower()]
        print("--quick skips the output-side search, so only the cases that do "
              "not need it are graded.\n")
    bad = 0
    for name, kw, expect in cases:
        tgt = target_mod.SimulatedTarget(seed=1, **kw)
        rng = np.random.default_rng(0)
        blocks = rng.integers(0, 256, size=(n, 16), dtype=np.uint8)
        timing, seen = tgt.measure_many(blocks)
        res = hypotheses.assess(seen, timing, quick=a.quick)
        answers = " | ".join(f.answer for f in res.findings)
        ok = expect.lower() in answers.lower()
        bad += not ok
        print(f"[{'OK ' if ok else 'BAD'}] {name}")
        print(f"        expected '{expect}'")
        print(f"        got      {answers[:150]}")
    print(f"\n{len(cases)-bad}/{len(cases)} cases as expected")
    return 1 if bad else 0


def cmd_fwscan(a):
    from . import fwscan as fw
    return fw.run(a.image, base=a.base, decompress=a.decompress,
                  only_hits=a.only_hits)


def cmd_placement(a):
    from . import placement as pl
    argv = [a.artefact]
    if a.part:
        argv += ["--part", a.part]
    if a.base is not None:
        argv += ["--base", hex(a.base)]
    for ld in a.ld:
        argv += ["--ld", ld]
    if a.section:
        argv += ["--section", a.section]
    if a.quiet:
        argv += ["--quiet"]
    if a.list_parts:
        argv += ["--list-parts"]
    if a.json:
        argv += ["--json", a.json]
    if a.fail_on:
        argv += ["--fail-on", a.fail_on]
    return pl.main(argv)


def cmd_codescan(a):
    from . import codescan as cs
    if a.selftest:
        return cs.selftest()
    argv = [a.artefact]
    if a.part:
        argv += ["--part", a.part]
    if a.base is not None:
        argv += ["--base", hex(a.base)]
    if a.window is not None:
        argv += ["--window", str(a.window)]
    argv += ["--top", str(a.top)]
    if a.json:
        argv += ["--json", a.json]
    if a.fail_on:
        argv += ["--fail-on", a.fail_on]
    return cs.main(argv)


def main(argv=None):
    p = argparse.ArgumentParser(prog="flashleak", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    an = sub.add_parser("analyse", help="assess a recorded capture")
    an.add_argument("file")
    an.add_argument("--blocks-key"); an.add_argument("--timing-key")
    an.add_argument("--block-offset", type=int, default=0,
                    help="column offset if the block array is wider than 16")
    an.add_argument("--limit", type=int, default=0)
    an.add_argument("--quick", action="store_true", help="skip the 2^16 search")
    an.add_argument("--json")
    an.set_defaults(fn=cmd_analyse)

    pr = sub.add_parser("probe", help="drive a live target")
    pr.add_argument("target", help="'module:Factory(...)' or 'sim:layout=four'")
    pr.add_argument("--n", type=int, default=0, help="traces to collect and assess")
    pr.add_argument("--repeats", type=int, default=1, help="measurements per input, min-filtered")
    pr.add_argument("--tvla", type=int, default=2000)
    pr.add_argument("--det-trials", type=int, default=100)
    pr.add_argument("--quick", action="store_true")
    pr.add_argument("--json")
    pr.set_defaults(fn=cmd_probe)

    st = sub.add_parser("selftest", help="check the detector against known truth")
    st.add_argument("--n", type=int, default=0)
    st.add_argument("--quick", action="store_true")
    st.set_defaults(fn=cmd_selftest)

    fs = sub.add_parser("fwscan", help="triage a firmware image before touching hardware")
    fs.add_argument("image")
    fs.add_argument("--base", type=lambda s: int(s, 0), default=None,
                    help="flash base address, if the vector table is not at offset 0")
    fs.add_argument("--decompress", action="store_true",
                    help="also scan decompressible streams inside the image")
    fs.add_argument("--only-hits", action="store_true",
                    help="for archives/directories, print only members with findings")
    fs.set_defaults(fn=cmd_fwscan)

    pc = sub.add_parser("placement",
                        help="will the AES tables be in flash at run time?")
    pc.add_argument("artefact", help=".elf, .bin, .o, .a, or a directory of them")
    pc.add_argument("--part", default=None,
                    help="part family for the memory map (f4, g4, f7, h7, l5, ...); "
                         "without it the SRAM region cannot be classified")
    pc.add_argument("--base", type=lambda s: int(s, 0), default=None,
                    help="flash base for a raw .bin with no vector table")
    pc.add_argument("--ld", action="append", default=[],
                    help="linker script(s) to check for the required placement rule")
    pc.add_argument("--section", default=None,
                    help="section name to look for in --ld")
    pc.add_argument("--quiet", action="store_true", help="verdict lines only")
    pc.add_argument("--list-parts", action="store_true",
                    help="print the memory map this tool uses for each part")
    pc.add_argument("--json", metavar="FILE", help="write the findings as JSON")
    pc.add_argument("--fail-on", choices=["exposed", "unknown", "never"],
                    default=None,
                    help="exit non-zero on this verdict or worse (CI gate); "
                         "the default always exits 0")
    pc.set_defaults(fn=cmd_placement)

    cs = sub.add_parser("codescan",
                        help="find table lookups by code shape, for an algorithm "
                             "with no byte signature (PQC and anything else new)")
    cs.add_argument("artefact", help=".elf or .bin")
    cs.add_argument("--part", default=None,
                    help="part family for the memory map, as for `placement`")
    cs.add_argument("--base", type=lambda s: int(s, 0), default=None,
                    help="flash base for a raw .bin (default 0x08000000)")
    cs.add_argument("--window", type=int, default=None,
                    help="bytes to look back for the base-register setup")
    cs.add_argument("--top", type=int, default=12,
                    help="distinct base addresses to print")
    cs.add_argument("--json", metavar="FILE")
    cs.add_argument("--selftest", action="store_true",
                    help="check this finder against `placement` on the in-tree "
                         "builds whose keys were recovered on silicon")
    cs.add_argument("--fail-on", choices=["exposed"], default=None)
    cs.set_defaults(fn=cmd_codescan)

    a = p.parse_args(argv)
    return a.fn(a) or 0


if __name__ == "__main__":
    sys.exit(main())
