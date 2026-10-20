"""Pack a capture into a replayable vector, and refuse to write a wrong one.

    python -m demos.riot_802154.host.make_vector captures/run_*.jsonl \
        --key <hex> --out demos/riot_802154/vectors/<name>.npz

The vector does not store the AES output blocks. Every block the attacker read
off the air is `AES_K(A_i)` for a counter block built out of fields the frame
carried in the clear, so given the key and the frame counters the whole
sequence regenerates exactly -- which is how a six-figure capture fits in a few
megabytes. **This refuses to write a vector whose blocks do not come back byte
for byte**, which is the only thing standing between a distilled capture and a
plausible-looking fiction.

What it keeps, and why each field is not optional:

  frame_counter   the nonce. Regenerates the blocks, and it is public.
  radio_us        the attacker's interval, reply END minus request END.
  ack_us          the common-mode reference. Without it the conditioning in
                  recover.py cannot be reproduced and the vector replays to a
                  worse answer than the capture gave.
  source_id       which capture file the reply came from. The conditioning
                  median-centres within (file, CSMA slot), so collapsing this
                  changes the result.
  payload_len     the frame shape, which is the group the ACK coefficient is
                  fitted within.

The key is in the `.json` beside it, under `truth`. It is there so the replay
can regenerate and check, and the recovery never reads it.
"""

import argparse
import hashlib
import sys
from pathlib import Path

import numpy as np

from flashattack import aesref

from . import frames as frames_mod


def pack(rows, key, blocks):
    """The arrays, after checking every block regenerates under `key`."""
    counters = np.array([r["frame_counter"] for r in rows], np.int64)
    sizes = np.array([r["payload_len"] for r in rows], np.int16)
    euis = {bytes(r["src_eui_le"]) for r in rows}
    levels = {r["security_level"] for r in rows}
    if len(euis) != 1 or len(levels) != 1:
        raise SystemExit("the capture mixes source addresses or security "
                         "levels; this packer assumes one victim and one level")
    eui, level = euis.pop(), levels.pop()

    bad = 0
    for b in blocks:
        pts = np.stack([np.frombuffer(
            frames_mod.counter_block(eui, c, b, level), np.uint8)
            for c in counters])
        got = aesref.encrypt_blocks(key, pts)
        for g, r in zip(got, rows):
            if bytes(g) != r["aes_output"][b]:
                bad += 1
    if bad:
        raise SystemExit(
            "%d of %d blocks do not regenerate under the given key. Either "
            "the key is wrong or the extractor's predicted plaintext missed, "
            "and a vector that does not regenerate is not a capture. Pass "
            "--drop-mismatched to keep only the rows that do."
            % (bad, len(rows) * len(blocks)))

    src = np.unique([r["source"] for r in rows], return_inverse=True)[1]
    return dict(frame_counter=counters,
                radio_us=np.array([r["radio_us"] for r in rows], float),
                ack_us=np.array([r["ack_us"] for r in rows], float),
                source_id=src.astype(np.int32),
                payload_len=sizes,
                src_eui_le=np.frombuffer(eui, np.uint8),
                security_level=np.array([level], np.uint8),
                blocks=np.array(blocks, np.int16))


def filter_regenerating(rows, key, blocks):
    """Keep the rows every requested block regenerates for.

    Vectorised over rows: `aesref.encrypt_blocks` runs one key over many
    blocks, so this is one call per CTR block index rather than one per
    (row, block), which at six figures of rows is the difference between
    seconds and an hour.
    """
    eui = bytes(rows[0]["src_eui_le"])
    level = rows[0]["security_level"]
    ok = np.ones(len(rows), bool)
    for b in blocks:
        pts = np.stack([np.frombuffer(frames_mod.counter_block(
            eui, r["frame_counter"], b, level), np.uint8) for r in rows])
        got = aesref.encrypt_blocks(key, pts)
        want = np.stack([np.frombuffer(r["aes_output"][b], np.uint8)
                         for r in rows])
        ok &= (got == want).all(axis=1)
    return [r for r, good in zip(rows, ok) if good]


def load_rows(path, key, blocks=None):
    """Rows in the shape recover.py wants, with the blocks regenerated.

    Needs the key, which `tools/replay.py` reads out of the json's `truth` and
    the adapter hands over. Regenerating is not a shortcut around the capture:
    `pack` already checked every block came back byte for byte before the
    vector was written, so these are the measured blocks.
    """
    d = np.load(path)
    want = list(blocks or [int(b) for b in d["blocks"]])
    eui = bytes(d["src_eui_le"])
    level = int(d["security_level"][0])
    counters = d["frame_counter"]
    regen = {}
    for b in want:
        pts = np.stack([np.frombuffer(
            frames_mod.counter_block(eui, int(c), b, level), np.uint8)
            for c in counters])
        regen[b] = aesref.encrypt_blocks(key, pts)
    radio = d["radio_us"]
    base = radio.min()
    slot = np.round((radio - base) / 320).astype(np.int64)
    rows = []
    for i in range(len(counters)):
        rows.append(dict(source=int(d["source_id"][i]),
                         probe=i,
                         frame_counter=int(counters[i]),
                         security_level=level,
                         src_eui_le=eui,
                         payload_len=int(d["payload_len"][i]),
                         aes_output={b: bytes(regen[b][i]) for b in want},
                         radio_us=float(radio[i]),
                         ack_us=float(d["ack_us"][i]),
                         csma_slot=int(slot[i]),
                         slot_adjusted_us=float(radio[i] - 320.0 * slot[i])))
    return rows


def main():
    # @file reads the capture list from a manifest. A six-figure run is 480
    # files, and a command line that long is refused by the shell.
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0],
                                 fromfile_prefix_chars="@")
    ap.add_argument("files", type=Path, nargs="+")
    ap.add_argument("--key", required=True, help="the victim's key, to "
                    "regenerate and check against")
    ap.add_argument("--blocks", type=int, nargs="+", default=[1, 2, 3, 4])
    ap.add_argument("--limit", type=int, default=0,
                    help="keep only the first N clean replies")
    ap.add_argument("--drop-mismatched", action="store_true",
                    help="keep only the replies that regenerate; prints how "
                         "many went and why that is expected to be a trickle")
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()

    key = bytes.fromhex(args.key)
    rows, rejected = frames_mod.extract(args.files, blocks=args.blocks)
    raw = sum(1 for p in args.files for _ in open(p))
    print("%d raw probes -> %d clean replies; rejected %s"
          % (raw, len(rows), dict(rejected)))
    if args.drop_mismatched:
        before = len(rows)
        rows = filter_regenerating(rows, key, args.blocks)
        print("regenerating replies %d of %d (%.3f%%); the rest are the "
              "extractor's predicted plaintext missing on an odd frame"
              % (len(rows), before, 100.0 * len(rows) / before))
    if args.limit:
        rows = rows[:args.limit]
    data = pack(rows, key, args.blocks)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(args.out, **data)
    h = hashlib.sha256(args.out.read_bytes()).hexdigest()
    print("wrote %s  %d replies x %d blocks  %.2f MB"
          % (args.out, len(rows), len(args.blocks),
             args.out.stat().st_size / 1e6))
    print("sha256 %s" % h)
    print("Now write the .json beside it: tools/replay.py will not run "
          "without the geometry.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
