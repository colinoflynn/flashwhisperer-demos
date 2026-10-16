"""Find table lookups by the CODE that reads them, not by the table's contents.

`fwscan` and `placement` find a table by recognising its *bytes* - the AES
S-box, the four `Te`, the Gladman `gfm` set. That works, it is checked against
builds whose keys came out on silicon, and it is the right tool for the job it
was built for. It cannot help with a table nobody has a signature for, which is
every algorithm this bench has not already broken. Three cases in a row went
past it:

  * SQIsign keeps its precomputed data in `const` typedef'd structs,
  * QR-UOV's modular-inverse table is a non-`const` array,
  * `rigs/fw_f401_ct` reads its S-box through a pointer.

This module asks the other question. A table lookup has a *shape* in the
instruction stream regardless of what is in the table:

    LDR   r3, [pc, #N]        ; or MOVW/MOVT - materialise a base address
    ...
    LDRB  r0, [r3, r0]        ; register-offset load from that base

A **register-offset load whose base resolves into a flash region** is a table
read, and it does not matter whether the table holds an S-box, GF(16) products
or discrete-Gaussian weights. That is the whole signature, and it is
algorithm-agnostic.

    python -m flashleak codescan fw.elf --part f4
    python -m flashleak codescan fw.bin --part l1 --base 0x08000000
    python -m flashleak codescan build/ --part g4 --fail-on exposed

Addresses are classified with `placement`'s part maps, so a base landing in
CCM, DTCM or SRAM reads `SAFE` for the same reasons and with the same caveats
as there.


What this does NOT cover
------------------------
Written here per the repo convention, and the first entry is the important one:

* **It finds a table READ, not a SECRET-dependent table read.** The index
  register's provenance is not traced. An S-box lookup and a lookup indexed by
  a loop counter have the same shape, so a hit is a candidate and the question
  of whether the index carries a secret is left to the reader - or to
  `tools/secret_index_audit.py` if source is available. Expect hits on
  jump tables, `__aeabi` helpers, character classes and font data.
* **It decodes, it does not disassemble.** There is no control-flow or
  instruction-boundary recovery: the scan steps two bytes at a time over
  everything in an executable section, so data embedded in `.text` that happens
  to encode a load produces a spurious site. The base-resolution requirement
  suppresses most of it, because random bytes rarely resolve to a mapped
  address.
* **Base resolution is a short backward window, and only two idioms.**
  PC-relative literal loads and MOVW/MOVT pairs, within `--window` bytes. A base
  passed in as a function argument, loaded from a struct, or computed across a
  basic-block boundary is not resolved and the site is reported as
  `base-unresolved` rather than dropped. Most sites in a real image are
  unresolved; that is the expected state, not a failure.
* **A register value can go stale, so a base can be invented.** The resolver
  records the last literal or MOVW/MOVT write to each register and does *not*
  invalidate it when an instruction it does not model writes to that register.
  Over a long window a dead value therefore gets attributed to a later load.
  This is why bases appear that land in no region at all; they are printed as
  `?`/`unmapped` and never make the verdict `EXPOSED`. Widening `--window` past
  the default trades recall for exactly this noise - the default is the widest
  setting that stayed clean on the in-tree corpus.
* **It says nothing about timing.** A table in flash is a precondition, not a
  channel; `research/mechanism/MEASURING_CHANNELS.md` is what decides that, and
  the row width decides whether a given table can collide at all.
* **Thumb-2 only.** Cortex-M. It does not decode A32, TriCore, C28x, Power or
  MIPS, so the non-ARM parts on the roster are out of scope.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .placement import EXPOSED, SAFE, UNKNOWN, Part, is_elf, parse_elf, resolve_part

#: How far back to look for the instruction that set up the base register.
#:
#: Calibrated, not guessed. On `rigs/fw_f4_lib/fw.elf` a 64-byte window finds
#: only `sbox` and misses `gfm2_sbox` and `gfm3_sbox` entirely - two of the
#: three tables `placement` reports, in a build whose key came out on the F429.
#: 192 finds all three by symbol. 512 finds more loads per table but starts
#: attributing stale register values and inventing unmapped bases, because the
#: resolver below does not invalidate a register when an instruction it does not
#: model writes to it. 192 is the widest setting that stayed clean here.
DEFAULT_WINDOW = 192

# ---------------------------------------------------------------- decoding

#: 16-bit load register-offset: `0101 1xx mmm nnn ttt`, keyed on bits 15..9.
_T1_LOADS = {0b0101011: ("ldrsb", 1), 0b0101100: ("ldr", 4),
             0b0101101: ("ldrh", 2), 0b0101110: ("ldrb", 1),
             0b0101111: ("ldrsh", 2)}

#: 32-bit load register-offset T2: `1111 100x xxx1 nnnn` / `tttt 0000 00ii mmmm`.
_T2_LOADS = {0xF810: ("ldrb.w", 1), 0xF830: ("ldrh.w", 2), 0xF850: ("ldr.w", 4),
             0xF910: ("ldrsb.w", 1), 0xF930: ("ldrsh.w", 2)}


@dataclass
class Load:
    """A register-offset load site."""
    off: int                 # offset within the scanned buffer
    addr: int                # run-time address of the instruction
    mnem: str
    elem: int                # bytes loaded per access
    rt: int
    rn: int                  # base register
    rm: int                  # index register
    shift: int = 0


def reg_offset_loads(code: bytes, base_addr: int) -> list[Load]:
    """Every register-offset load encoding in `code`."""
    out: list[Load] = []
    n = len(code)
    for off in range(0, n - 1, 2):
        hw = code[off] | (code[off + 1] << 8)
        key = hw >> 9
        if key in _T1_LOADS:
            mnem, elem = _T1_LOADS[key]
            out.append(Load(off, base_addr + off, mnem, elem,
                            rt=hw & 7, rn=(hw >> 3) & 7, rm=(hw >> 6) & 7))
            continue
        if off + 3 >= n:
            continue
        hw2 = code[off + 2] | (code[off + 3] << 8)
        k = hw & 0xFFF0
        # The register form requires hw2[11:6] == 0; LDRB/LDRH/LDR immediate
        # T3 shares hw1 and sets hw2 bit 11.
        if k in _T2_LOADS and (hw2 & 0x0FC0) == 0:
            mnem, elem = _T2_LOADS[k]
            out.append(Load(off, base_addr + off, mnem, elem,
                            rt=(hw2 >> 12) & 0xF, rn=hw & 0xF, rm=hw2 & 0xF,
                            shift=(hw2 >> 4) & 3))
    return out


def _u32(buf: bytes, off: int) -> int | None:
    if off < 0 or off + 4 > len(buf):
        return None
    return int.from_bytes(buf[off:off + 4], "little")


def resolve_base(code: bytes, base_addr: int, site: int, rn: int,
                 read_word, window: int = DEFAULT_WINDOW) -> tuple[int | None, str]:
    """Value in `rn` at `site`, from a PC-relative literal or a MOVW/MOVT pair.

    Forward pass over the window ending at `site`, keeping the last write to
    each register. `placement.ldr_literal_sites` cannot be reused here: it maps
    *value -> sites* and discards the destination register, and this needs the
    opposite direction.
    """
    regs: dict[int, tuple[int, str]] = {}
    start = max(0, site - window)
    if start & 1:
        start += 1
    off = start
    while off < site:
        if off + 1 >= len(code):
            break
        hw = code[off] | (code[off + 1] << 8)
        pc = base_addr + off + 4
        if (hw & 0xF800) == 0x4800:                       # LDR Rt,[pc,#imm8*4]
            rt = (hw >> 8) & 7
            lit = (pc & ~3) + (hw & 0xFF) * 4
            val = read_word(lit)
            if val is not None:
                regs[rt] = (val, f"ldr r{rt},[pc] @ {base_addr + off:#x} -> {lit:#x}")
            off += 2
            continue
        if off + 3 < len(code):
            hw2 = code[off + 2] | (code[off + 3] << 8)
            if (hw & 0xFF7F) == 0xF85F:                   # LDR.W Rt,[pc,#imm12]
                rt = (hw2 >> 12) & 0xF
                imm = hw2 & 0xFFF
                lit = (pc & ~3) + (imm if (hw >> 7) & 1 else -imm)
                val = read_word(lit)
                if val is not None:
                    regs[rt] = (val, f"ldr.w r{rt},[pc] @ {base_addr + off:#x} -> {lit:#x}")
                off += 4
                continue
            if (hw & 0xFBF0) in (0xF240, 0xF2C0):         # MOVW / MOVT
                i = (hw >> 10) & 1
                imm = ((hw & 0xF) << 12) | (i << 11) | (((hw2 >> 12) & 7) << 8) | (hw2 & 0xFF)
                rd = (hw2 >> 8) & 0xF
                if (hw & 0xFBF0) == 0xF240:
                    regs[rd] = (imm, f"movw r{rd},#{imm:#x} @ {base_addr + off:#x}")
                elif rd in regs:
                    lo = regs[rd][0] & 0xFFFF
                    regs[rd] = ((imm << 16) | lo,
                                f"movw/movt r{rd} @ {base_addr + off:#x}")
                off += 4
                continue
            if (hw & 0xE000) == 0xE000 and (hw & 0x1800) != 0:
                off += 4                                   # some other 32-bit insn
                continue
        off += 2
    if rn in regs:
        return regs[rn]
    return None, "base-unresolved"


# ---------------------------------------------------------------- reporting

@dataclass
class Hit:
    insn_addr: int
    mnem: str
    elem: int
    base: int | None
    region: str
    exposure: str
    section: str = ""
    symbol: str = ""
    evidence: str = ""


@dataclass
class CodeReport:
    path: str
    kind: str
    part: str
    scanned: int = 0
    sites: int = 0
    hits: list[Hit] = field(default_factory=list)
    unresolved: int = 0
    note: str = ""

    @property
    def verdict(self) -> str:
        if any(h.exposure == EXPOSED for h in self.hits):
            return "EXPOSED"
        if self.hits:
            return "SAFE"
        if self.sites:
            return "UNDETERMINED"
        return "NO-LOOKUPS"


def _sym_for(elf, addr: int) -> str:
    """Nearest preceding symbol containing `addr`, preferring data objects.

    An earlier version kept whichever matching symbol came last in the table and
    reported ARM mapping symbols (`$d`, `$t`) as the table's name, which is
    worse than printing nothing.
    """
    best: tuple[int, int, str] | None = None     # (is_object, value, name)
    for s in elf.symbols:
        if not s.name or s.name.startswith("$"):
            continue
        if s.value > addr:
            continue
        if s.size and addr >= s.value + s.size:
            continue
        rank = (1 if (s.info & 0xF) == 1 else 0, s.value, s.name)
        if best is None or rank[:2] > best[:2]:
            best = rank
    return best[2] if best else ""


def scan_elf(data: bytes, part: Part, path: str, window: int) -> CodeReport:
    elf = parse_elf(data)
    rep = CodeReport(path, "elf", part.name)

    def read_word(addr: int) -> int | None:
        for s in elf.sections:
            if s.addr and s.addr <= addr < s.addr + s.size and s.sh_type != 8:
                return _u32(data, s.offset + (addr - s.addr))
        return None

    for sec in elf.sections:
        if not (sec.flags & 0x4) or not sec.size or sec.sh_type == 8:
            continue                                        # SHF_EXECINSTR only
        code = data[sec.offset:sec.offset + sec.size]
        rep.scanned += len(code)
        for ld in reg_offset_loads(code, sec.addr):
            rep.sites += 1
            base, ev = resolve_base(code, sec.addr, ld.off, ld.rn, read_word, window)
            if base is None:
                rep.unresolved += 1
                continue
            reg = part.classify(base)
            tsec, sym = "", ""
            for s in elf.sections:
                if s.addr and s.addr <= base < s.addr + s.size:
                    tsec = s.name
                    break
            sym = _sym_for(elf, base)
            rep.hits.append(Hit(ld.addr, ld.mnem, ld.elem, base,
                                reg.name if reg else "unmapped",
                                reg.exposure if reg else UNKNOWN,
                                tsec, sym, ev))
    return rep


def scan_bin(data: bytes, part: Part, path: str, base_addr: int,
             window: int) -> CodeReport:
    rep = CodeReport(path, "bin", part.name)
    rep.scanned = len(data)

    def read_word(addr: int) -> int | None:
        return _u32(data, addr - base_addr)

    for ld in reg_offset_loads(data, base_addr):
        rep.sites += 1
        base, ev = resolve_base(data, base_addr, ld.off, ld.rn, read_word, window)
        if base is None:
            rep.unresolved += 1
            continue
        reg = part.classify(base)
        rep.hits.append(Hit(ld.addr, ld.mnem, ld.elem, base,
                            reg.name if reg else "unmapped",
                            reg.exposure if reg else UNKNOWN, "", "", ev))
    rep.note = ("a raw image has no section table, so the whole file is decoded "
                "as if it were code; expect more spurious sites than from an ELF")
    return rep


def analyse(path: str, part: str | None = None, base: int | None = None,
            window: int = DEFAULT_WINDOW) -> CodeReport:
    p = Path(path)
    data = p.read_bytes()
    pt = resolve_part(part)
    if is_elf(data):
        return scan_elf(data, pt, str(p), window)
    return scan_bin(data, pt, str(p), base if base is not None else 0x0800_0000,
                    window)


def _group(rep: CodeReport) -> dict[int, list[Hit]]:
    out: dict[int, list[Hit]] = {}
    for h in rep.hits:
        out.setdefault(h.base or 0, []).append(h)
    return out


def render(rep: CodeReport, top: int = 12) -> str:
    out = [f"{rep.path}: {rep.kind}, part={rep.part}, "
           f"{rep.scanned} B scanned, {rep.sites} register-offset load site(s), "
           f"{rep.unresolved} with an unresolved base"]
    if rep.note:
        out.append(f"  note: {rep.note}")
    groups = sorted(_group(rep).items(), key=lambda kv: -len(kv[1]))
    if groups:
        out.append(f"  {len(groups)} distinct base address(es), most-read first:")
        for base, hits in groups[:top]:
            h = hits[0]
            mark = "!!" if h.exposure == EXPOSED else ("ok" if h.exposure == SAFE else " ?")
            where = f"{h.region}"
            if h.section:
                where += f" [{h.section}]"
            if h.symbol:
                where += f" {h.symbol}"
            out.append(f"   {mark} {base:#010x}  {len(hits):3d} load(s)  "
                       f"{h.mnem:8s} {where}")
            out.append(f"        {h.evidence}")
        if len(groups) > top:
            out.append(f"   ... {len(groups) - top} more base(s)")
    out.append(f"  => VERDICT: {rep.verdict}" + {
        "EXPOSED": "  - at least one table read resolves into flash. Whether the"
                   " INDEX carries a secret is a separate question this tool does"
                   " not answer.",
        "SAFE": "  - every resolved base is in RAM for this part.",
        "UNDETERMINED": "  - load sites found but no base resolved; try a larger"
                        " --window, or pass --base for a raw image.",
        "NO-LOOKUPS": "  - no register-offset loads at all (fully unrolled, or"
                      " not Thumb-2 code).",
    }[rep.verdict])
    return "\n".join(out)


def to_dict(rep: CodeReport) -> dict:
    return {"path": rep.path, "kind": rep.kind, "part": rep.part,
            "verdict": rep.verdict, "scanned": rep.scanned, "sites": rep.sites,
            "unresolved": rep.unresolved,
            "hits": [h.__dict__ for h in rep.hits]}


#: In-tree artefacts whose AES tables `placement` locates by byte signature and
#: whose keys were recovered on the F429. This finder knows nothing about AES, so
#: agreement on the *same base addresses* is the check that matters: two
#: independent methods, one answer. Paths are relative to the repository root.
SELFTEST_ARTEFACTS = (
    ("rigs/fw_f4_lib/fw.elf", "f4"),
    ("rigs/fw_f4_lib/fw_tinyaes128.bin", "f4"),
    ("rigs/fw_f4_lib/fixed_tinyaes.bin", "f4"),
    ("rigs/fw_f4_lib/fw_tinycrypt.bin", "f4"),
)


def selftest() -> int:
    """Does this finder agree with `placement` on builds with known truth?"""
    from . import placement as pl

    root = Path(__file__).resolve().parents[2]
    print("codescan selftest - agreement with placement's byte-signature finder\n")
    bad = skipped = 0
    for rel, part in SELFTEST_ARTEFACTS:
        p = root / rel
        if not p.exists():
            print(f"  SKIP  {rel} (not present)")
            skipped += 1
            continue
        mine = analyse(str(p), part)
        theirs = pl.analyse(str(p), part)
        want = {x.runtime_addr for x in theirs.placements
                if x.runtime_addr is not None}
        got = {h.base for h in mine.hits if h.base is not None}
        missed = want - got
        ok = not missed and (mine.verdict == theirs.verdict or not want)
        bad += not ok
        print(f"  {'ok  ' if ok else 'FAIL'}  {rel}")
        print(f"          placement: {theirs.verdict:12s} "
              f"{sorted(hex(a) for a in want)}")
        print(f"          codescan : {mine.verdict:12s} "
              f"{sorted(hex(a) for a in got)[:6]}")
        if missed:
            print(f"          MISSED by codescan: {sorted(hex(a) for a in missed)}")
    print("\n  " + ("agrees on every artefact" if not bad
                    else f"{bad} disagreement(s)")
          + (f", {skipped} skipped" if skipped else ""))
    return 1 if bad else 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("path")
    ap.add_argument("--part")
    ap.add_argument("--base", type=lambda s: int(s, 0),
                    help="flash base for a raw .bin (default 0x08000000)")
    ap.add_argument("--window", type=int, default=DEFAULT_WINDOW)
    ap.add_argument("--top", type=int, default=12)
    ap.add_argument("--json")
    ap.add_argument("--fail-on", choices=["exposed"], default=None)
    a = ap.parse_args(argv)

    rep = analyse(a.path, a.part, a.base, a.window)
    print(render(rep, a.top))
    if a.json:
        Path(a.json).write_text(json.dumps(to_dict(rep), indent=2), encoding="utf-8")
    if a.fail_on == "exposed" and rep.verdict == "EXPOSED":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
