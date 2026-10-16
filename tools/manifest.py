"""What data should exist, and whether what is here is still it.

Two kinds of data live in this repository's world, and only one of them is in
git:

  vector  a distilled capture under demos/<demo>/vectors/. Tracked, a few MB,
          holds what the attack reads and nothing else. It must be present and
          it must hash the way it did when it was recorded.
  raw     the original capture, which stayed on the bench because it is
          hundreds of megabytes. Not in this repository at all. The row is the
          record that it exists, how big it is and what it hashes to, so a copy
          can be checked rather than assumed.

    python tools/manifest.py --write     # regenerate from what is on disk
    python tools/manifest.py             # verify the tree against it

Verify reports four things, and they are not the same:

  MISSING  a vector in the manifest and not on disk. The demo cannot replay.
  CHANGED  on disk with a different hash. Any analysis that used it is not
           reproducible from what is here now, which is worse than missing.
  ABSENT   a raw capture that is not here. Expected, and not a failure: the
           row is there to say what to ask for.
  UNLISTED a vector on disk and not in the manifest. Run --write.

`git status` answers none of this for the raw rows, and for the vectors it
answers only whether THIS clone changed them.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import os

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
MANIFEST = os.path.join(ROOT, "captures", "MANIFEST.tsv")

DATA_EXT = (".npz", ".npy", ".log", ".out", ".txt", ".csv")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def walk_vectors():
    """Every tracked vector, as demos/<demo>/vectors/<file>."""
    demos = os.path.join(ROOT, "demos")
    for demo in sorted(os.listdir(demos)) if os.path.isdir(demos) else []:
        vdir = os.path.join(demos, demo, "vectors")
        if not os.path.isdir(vdir):
            continue
        for fn in sorted(os.listdir(vdir)):
            if fn.lower().endswith(DATA_EXT):
                full = os.path.join(vdir, fn)
                yield "demos/%s/vectors/%s" % (demo, fn), full


def read_manifest():
    rows = {}
    if not os.path.exists(MANIFEST):
        return rows
    with io.open(MANIFEST, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) >= 4:
                rows[parts[0]] = (parts[1], int(parts[2]), parts[3])
    return rows


HEADER = """\
# Capture data this repository knows about.
#
#   vector  tracked, under demos/<demo>/vectors/ - must be present and match
#   raw     NOT in this repository: the original capture, on the bench. The
#           row says what exists and what it hashes to, so a copy can be
#           checked. tools/manifest.py reports it ABSENT, which is fine.
#
# Regenerate: python tools/manifest.py --write   (keeps the raw rows)
# Verify:     python tools/manifest.py
#
# path\tkind\tbytes\tsha256
"""


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--write", action="store_true",
                    help="regenerate the vector rows; raw rows are kept as they are")
    a = ap.parse_args()

    known = read_manifest()
    found = dict(walk_vectors())

    if a.write:
        rows = {p: v for p, v in known.items() if v[0] == "raw"}
        for rel, full in sorted(found.items()):
            rows[rel] = ("vector", os.path.getsize(full), sha256(full))
        os.makedirs(os.path.dirname(MANIFEST), exist_ok=True)
        with io.open(MANIFEST, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(HEADER)
            for rel in sorted(rows):
                kind, sz, h = rows[rel]
                fh.write("%s\t%s\t%d\t%s\n" % (rel, kind, sz, h))
        nv = sum(1 for v in rows.values() if v[0] == "vector")
        mb = sum(v[1] for v in rows.values() if v[0] == "vector") / 1048576.0
        print("  %d vectors, %.1f MB, and %d raw rows kept"
              % (nv, mb, len(rows) - nv))
        return 0

    if not known:
        print("  no manifest yet; run --write")
        return 1

    bad = 0
    for rel in sorted(known):
        kind, sz, h = known[rel]
        full = os.path.join(ROOT, rel.replace("/", os.sep))
        if not os.path.exists(full):
            if kind == "raw":
                print("  ABSENT   %s (%.1f MB, on the bench)" % (rel, sz / 1048576.0))
            else:
                print("  MISSING  %s" % rel)
                bad += 1
            continue
        if sha256(full) != h:
            print("  CHANGED  %s" % rel)
            bad += 1
    for rel in sorted(found):
        if rel not in known:
            print("  UNLISTED %s" % rel)
            bad += 1

    if not bad:
        print("  %d rows, nothing missing or changed" % len(known))
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
