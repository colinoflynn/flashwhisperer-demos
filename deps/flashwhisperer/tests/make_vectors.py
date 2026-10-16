"""Capture trace vectors from the currently-flashed firmware into tests/vectors/.

Run once per firmware (flash the board first). Example:
  # with fw_f4_modes flashed (mbedtls, T-table):
  PYTHONPATH=. python tests/make_vectors.py --port COM9 --impl ttable_mbedtls \
      --acr 00000705 --spec ecb-enc/2b7e151628aed2a6abf7158809cf4f3c/120000 \
      --spec ecb-dec/2b7e151628aed2a6abf7158809cf4f3c/120000

Vectors are tiny (timing only, uint16, seed-regenerated material) - see
flashattack/vectors.py. The long test replays them (pytest --runslow).
"""

import os as _os, sys as _sys
# The five packages live under flashwhisperer/ (REORG_PLAN D2).  Walk up to the
# .git marker rather than assume a depth: importers of these packages sit at the
# repository root, in hardware/, results/<campaign>/, demo/<stack>/ and
# research/<area>/ - four different depths.  `.git` is a FILE in a worktree, so
# test existence, not isdir.
_fw = _os.path.dirname(_os.path.abspath(__file__))
while _fw != _os.path.dirname(_fw) and not _os.path.exists(_os.path.join(_fw, ".git")):
    _fw = _os.path.dirname(_fw)
_sys.path.insert(0, _os.path.join(_fw, "flashwhisperer"))
import argparse
import os
import numpy as np
from flashattack import transport, modes, vectors

OUTDIR = os.path.join(os.path.dirname(__file__), "vectors")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", required=True)
    ap.add_argument("--impl", required=True, help="label, e.g. ttable_mbedtls / sbox_tinyaes")
    ap.add_argument("--acr", default="00000705")
    ap.add_argument("--seed", default="5eed01")
    ap.add_argument("--spec", action="append", required=True,
                    help="mode/keyhex/n , repeatable")
    args = ap.parse_args()
    os.makedirs(OUTDIR, exist_ok=True)

    tgt = transport.SerialTarget(args.port)
    banner = tgt.banner()
    print("id:", banner, "| cfg:", tgt.set_acr(args.acr))
    seed = int(args.seed, 16)
    for spec in args.spec:
        mode, keyhex, n = spec.split("/"); n = int(n)
        keysize = len(keyhex) // 2 * 8
        print("key:", tgt.setkey(keyhex))
        if mode == "ecb-enc" and "-lib" in banner:
            bc = "X"
        else:
            bc = "X " + modes.MODE_CHAR[mode]
        print(f"collecting {n} : impl={args.impl} mode={mode} keysize={keysize} via '{bc}'")
        material, cyc = transport.collect_oncore(tgt, bc, seed, n)
        _, direction = modes.known_output(mode, material, bytes.fromhex(keyhex))
        path = os.path.join(OUTDIR, f"{args.impl}_{mode}_{keysize}.npz")
        vectors.save(path, seed=seed, n=n, mode=mode, direction=direction,
                     impl=args.impl, keysize=keysize, key_hex=keyhex, timing=cyc,
                     notes=f"F429 acr={args.acr} {banner}")
        print("  saved", path, f"({os.path.getsize(path)/1024:.0f} KB)")
    tgt.close()


if __name__ == "__main__":
    main()
