"""Read the round T-table access order off an ARM disassembly of aes_encrypt.

Why this exists: the attack's reachable key-byte graph is decided by which INPUT
bytes end up adjacent in the EXECUTED order, and C leaves evaluation order inside
an expression unspecified. The order therefore belongs to the binary, not the
source -- so it has to be read, per build.

RIOT's rotated single-table AES (`sys/crypto/aes.c:1098`) computes

    t0 = Te0(s0 >> 24) ^ Te1((s1 >> 16) & 0xff) ^ Te2((s2 >> 8) & 0xff)
                       ^ Te3(s3 & 0xff) ^ rk[4]

with Te1/Te2/Te3 defined as Te0 rotated right by 8/16/24. So every lookup is a
load from the SAME 1 KB table, each index is one byte extracted from one state
word, and the rotation on the accumulating XOR says which term it was.

Identification therefore runs in two steps, and neither reads the prologue --
the loop body reassigns registers, which is what made a prologue-based version
of this script report a non-permutation:

 1. Find the first accumulator register that collects four rotated XORs of four
    table loads. That is `t0`, whose four terms are parts 0,1,2,3 of words
    0,1,2,3 respectively, so it maps each state REGISTER to its word.
 2. Replay the body with that map: each `ldr rX, [tab, rI, lsl #2]` (or the
    `add`+`ldr` pair GCC emits at other optimisation levels) resolves through
    rI's extraction to one plaintext byte index.

Big-endian packing, so the extraction picks the byte:

    lsr #24 -> 4w+0   ubfx #16,8 -> 4w+1   ubfx #8,8 -> 4w+2   uxtb -> 4w+3

The output is checked against being a permutation of 0..15, which is a real
control: a wrong register->word map still produces sixteen indices, but an
inconsistent one repeats and omits, which is exactly how the earlier version
announced its own failure.

What this does NOT do: it does not distinguish round 1 from a later round. For a
rolled round loop they are the same instructions; for an unrolled build the first
sixteen loads are round 1 and the count reported makes that visible.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

EXTRACTS = [
    (re.compile(r"lsrs?(?:\.w)?\s+(\w+),\s*(\w+),\s*#24$"), 0),
    (re.compile(r"mov(?:\.w)?\s+(\w+),\s*(\w+),\s*lsr\s*#24$"), 0),
    (re.compile(r"ubfx\s+(\w+),\s*(\w+),\s*#16,\s*#8$"), 1),
    (re.compile(r"ubfx\s+(\w+),\s*(\w+),\s*#8,\s*#8$"), 2),
    (re.compile(r"uxtb(?:\.w)?\s+(\w+),\s*(\w+)$"), 3),
]
LOADRS = re.compile(r"ldr(?:\.w)?\s+(\w+),\s*\[(\w+),\s*(\w+),\s*lsl\s*#2\]$")
ADDR = re.compile(r"add(?:\.w)?\s+(\w+),\s*(\w+),\s*(\w+),\s*lsl\s*#2$")
LOADI = re.compile(r"ldr(?:\.w)?\s+(\w+),\s*\[(\w+)(?:,\s*#\d+)?\]$")
EOR_ROR = re.compile(r"eor(?:\.w)?\s+(\w+),\s*(\w+),\s*(\w+),\s*ror\s*#(\d+)$")
EOR_PLAIN = re.compile(r"eors?(?:\.w)?\s+(\w+),\s*(\w+),\s*(\w+)$")
TEXT = re.compile(r"^\s*[0-9a-f]+:\s+(.*?)\s*(?:;.*)?$")


def disassemble(path: Path, func: str = "aes_encrypt") -> list[str]:
    out = subprocess.run(
        ["arm-none-eabi-objdump", "-d", "--no-show-raw-insn", str(path)],
        capture_output=True, text=True, check=True).stdout.splitlines()
    body, on = [], False
    for ln in out:
        if re.match(rf"^[0-9a-f]+\s+<{re.escape(func)}>:", ln):
            on = True
            continue
        if on:
            if re.match(r"^[0-9a-f]+\s+<", ln):
                break
            m = TEXT.match(ln)
            if m and m.group(1):
                body.append(m.group(1))
    return body


def scan(body: list[str]):
    """Walk once, yielding ('load', dest, src_reg, part) and raw eor records."""
    extracted: dict[str, tuple[str, int]] = {}     # idx reg -> (state reg, part)
    addr_of: dict[str, str] = {}                   # addr reg -> idx reg
    events = []
    for ins in body:
        done = False
        for rx, part in EXTRACTS:
            m = rx.search(ins)
            if m:
                extracted[m.group(1)] = (m.group(2), part)
                done = True
                break
        if done:
            continue
        m = LOADRS.search(ins)
        if m and m.group(3) in extracted:
            st, part = extracted[m.group(3)]
            events.append(("load", m.group(1), st, part))
            continue
        m = ADDR.search(ins)
        if m:
            addr_of[m.group(1)] = m.group(3)
            continue
        m = LOADI.search(ins)
        if m and m.group(2) in addr_of and addr_of[m.group(2)] in extracted:
            st, part = extracted[addr_of[m.group(2)]]
            events.append(("load", m.group(1), st, part))
            continue
        m = EOR_ROR.search(ins)
        if m:
            events.append(("eor", m.group(1), m.group(2), m.group(3), int(m.group(4))))
            continue
        m = EOR_PLAIN.search(ins)
        if m:
            events.append(("eor", m.group(1), m.group(2), m.group(3), 0))
    return events


def word_map(events) -> dict[str, int]:
    """Map state register -> word, from the first accumulator that takes four loads."""
    held: dict[str, tuple[str, int]] = {}          # loaded reg -> (state reg, part)
    groups: dict[str, list[tuple[str, int]]] = {}
    for ev in events:
        if ev[0] == "load":
            held[ev[1]] = (ev[2], ev[3])
            continue
        _, dst, a, b, _ror = ev
        for src in (a, b):
            if src in held:
                groups.setdefault(dst, []).append(held[src])
        for src in (a, b):                          # consumed
            held.pop(src, None)
        if len(groups.get(dst, [])) >= 4:
            four = groups[dst][:4]
            regs = {part: reg for reg, part in four}
            if len(regs) == 4 and set(regs) == {0, 1, 2, 3}:
                return {reg: part for part, reg in regs.items()}
            groups[dst] = []
    return {}


def read_order(events, words: dict[str, int]) -> list[int]:
    out = []
    for ev in events:
        if ev[0] == "load" and ev[2] in words:
            out.append(4 * words[ev[2]] + ev[3])
    return out


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    rows = []
    for arg in sys.argv[1:]:
        p = Path(arg)
        events = scan(disassemble(p))
        words = word_map(events)
        order = read_order(events, words)[:16]
        ok = sorted(order) == list(range(16))
        rows.append((p.name, order, ok))
        print(f"{p.name:22s} {'OK ' if ok else 'BAD'} {order}")
        if not ok:
            print(f"{'':22s}     words={words}  ({len(order)} indices)")
    good = [(n, o) for n, o, ok in rows if ok]
    if len(good) > 1:
        base_n, base = good[0]
        print()
        print(f"against {base_n}:")
        for n, o in good[1:]:
            same = o == base
            pb = {frozenset((base[i], base[i + 1])) for i in range(15)}
            po = {frozenset((o[i], o[i + 1])) for i in range(15)}
            print(f"  {n:22s} {'IDENTICAL' if same else 'DIFFERENT'}; "
                  f"adjacent pairs kept {len(pb & po)}/15, new {len(po - pb)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
