"""flashleak.placement: does it get the *build* question right?

Three kinds of test, in increasing distance from the tool's own assumptions:

  * unit tests on the decoders (Thumb literal loads, the copy-loop chain, the
    linker-script dialects, `ar`), against hand-built inputs whose answer is
    arithmetic rather than opinion;
  * a **synthetic matched pair** - the same S-box bytes in the same image at
    the same offset, once as `.rodata` in flash and once as a `.data`
    initialiser bound for RAM - which is the exact discrimination the raw-.bin
    path exists to make, built here so the test needs no toolchain;
  * the repo's own committed firmware, whose leak/no-leak status came off real
    silicon.

The corpus in STATIC_ANALYSIS.md §5 is larger (38 artefacts) because it rebuilds
every library variant; those builds need WSL and an ARM toolchain, so they are
not reproduced here. What is here runs anywhere.
"""
from __future__ import annotations

import os as _os
# No sys.path walk: the packages sit at the repository root here, so pytest
# from the root (or an editable install) finds them.  In the repository this
# was extracted from they lived under flashwhisperer/ and this file walked up
# to the .git marker to reach them.

import pathlib
import struct

import pytest

from flashleak import placement as P

# The firmware images and linker scripts these tests read belong to the
# FIRMWARE repository, not to this one - this is the host toolkit.  Every use
# goes through `_need()`, which SKIPS when the asset is absent, so the suite
# says what it did not check instead of failing on a tree it does not own.
# Point FLASHWHISPERER_RIGS at a firmware checkout's rigs/ to run them.
ROOT = pathlib.Path(__file__).resolve().parents[1]
RIGS = pathlib.Path(_os.environ.get("FLASHWHISPERER_RIGS") or (ROOT / "rigs"))
LIB = RIGS / "fw_f4_lib"

SBOX = bytes(P.fwscan._SBOX)
BASE = 0x0800_0000


# --------------------------------------------------------------------------
# Part memory maps - the part of this tool that is a judgement call
# --------------------------------------------------------------------------

def test_flash_is_exposed_everywhere():
    for name in ("stm32f1", "stm32f3", "stm32f4", "stm32f7", "stm32g4",
                 "stm32h7", "stm32l4", "stm32l5"):
        part = P.resolve_part(name)
        assert part.classify(0x0800_0000).exposure == P.EXPOSED, name


def test_ccm_and_tcm_are_safe_not_flash():
    """0x10000000 is *safer* than SRAM on a G4/F3/F4, not more dangerous."""
    assert P.resolve_part("g4").classify(0x1000_0000).exposure == P.SAFE
    assert P.resolve_part("f4").classify(0x1000_0000).exposure == P.SAFE
    assert P.resolve_part("h7").classify(0x2000_0000).exposure == P.SAFE   # DTCM


def test_h7_axi_sram_is_cached_not_safe():
    """On an H7, 0x20000000 is DTCM and 0x24000000 is cached AXI-SRAM.

    A tool that only checks "is it 0x08xxxxxx" calls both of these safe, and one
    of them is a classical cache-timing surface.
    """
    h7 = P.resolve_part("h7")
    assert h7.classify(0x2000_0000).exposure == P.SAFE
    assert h7.classify(0x2400_0000).exposure == P.CACHED_RAM
    assert h7.classify(0x3000_0000).exposure == P.CACHED_RAM


def test_f7_dtcm_boundary_moves_inside_the_family():
    """The same address is cached SRAM1 on an F746 and DTCM on an F769."""
    assert P.resolve_part("f746").classify(0x2001_0140).exposure == P.CACHED_RAM
    assert P.resolve_part("f769").classify(0x2001_0140).exposure == P.SAFE


def test_generic_part_refuses_to_classify_sram():
    """Without a part number the SRAM region is UNKNOWN, not 'safe'."""
    g = P.resolve_part(None)
    assert g.classify(0x2000_0000).exposure == P.UNKNOWN
    assert g.classify(0x0800_0000).exposure == P.EXPOSED


def test_unknown_part_raises():
    with pytest.raises(KeyError):
        P.resolve_part("stm32z99")


# --------------------------------------------------------------------------
# Thumb-2 literal decoding
# --------------------------------------------------------------------------

def _ldr_t1(rt: int, insn_off: int, lit_off: int) -> bytes:
    imm = lit_off - ((insn_off + 4) & ~3)
    assert 0 <= imm <= 1020 and imm % 4 == 0, imm
    return struct.pack("<H", 0x4800 | (rt << 8) | (imm // 4))


def test_ldr_literal_t1_decodes_to_the_loaded_value():
    img = bytearray(b"\x00" * 32)
    img[0:2] = _ldr_t1(3, 0, 12)
    img[12:16] = struct.pack("<I", 0xDEAD_BEEF)
    sites = P.ldr_literal_sites(bytes(img), BASE)
    assert 0xDEAD_BEEF in sites
    assert 0 in sites[0xDEAD_BEEF]


def test_movw_movt_pair_is_reconstructed():
    """MOVW r3,#0x1234 ; MOVT r3,#0x0800  ->  0x08001234."""
    def enc(hi: bool, rd: int, v: int) -> bytes:
        i = (v >> 11) & 1
        imm4 = (v >> 12) & 0xF
        imm3 = (v >> 8) & 7
        imm8 = v & 0xFF
        hw1 = (0xF2C0 if hi else 0xF240) | (i << 10) | imm4
        hw2 = (imm3 << 12) | (rd << 8) | imm8
        return struct.pack("<HH", hw1, hw2)

    img = enc(False, 3, 0x1234) + enc(True, 3, 0x0800) + b"\x00" * 8
    vals = P.movw_movt_values(img)
    assert 0x0800_1234 in vals


# --------------------------------------------------------------------------
# A synthetic matched pair: the same table, flash vs RAM, in one image each.
# --------------------------------------------------------------------------

def _build_image(table_in_ram: bool, ref_table: bool = True,
                 table_first: bool = True) -> bytes:
    """A minimal but honest STM32 image.

    layout:   [vector table 0x100] [reset handler + literal pool] [pad]
              [ .rodata (S-box, flash build only) ] [ .data initialiser ]

    The reset handler really contains three `LDR Rt,[PC,#n]` that load
    `_sdata`, `_edata` and `_sidata`, exactly as a GCC startup does, and the
    "cipher" really contains an `LDR` that loads the table's run-time address.
    """
    ram_base = 0x2000_0000
    img = bytearray()
    img += struct.pack("<II", 0x2001_8000, BASE + 0x101)       # SP, reset (thumb)
    img += b"\x00" * (0x100 - len(img))

    code = bytearray()
    lit_at = 0x40                                              # pool inside `code`
    code += _ldr_t1(0, 0x00, lit_at + 0)                       # _sdata
    code += _ldr_t1(1, 0x02, lit_at + 4)                       # _edata
    code += _ldr_t1(2, 0x04, lit_at + 8)                       # _sidata
    code += _ldr_t1(3, 0x06, lit_at + 12)                      # table base
    code += b"\x00" * (lit_at - len(code))
    code += b"\x00" * 16                                       # literals, patched below
    code += b"\x00" * 16                                       # pad

    body = bytearray()
    if not table_in_ram:
        body += SBOX                                           # .rodata, stays in flash
    rodata_off = 0x100 + len(code)
    data_off = rodata_off + len(body)
    data_init = bytearray()
    if not table_first:
        data_init += b"\x55" * 8               # ordinary .data ahead of the table
    if table_in_ram:
        data_init += SBOX
    data_init += b"\x11\x22\x33\x44"                           # some ordinary .data

    sidata = BASE + data_off
    sdata = ram_base
    edata = ram_base + len(data_init)
    tbl_ram = ram_base + (0 if table_first else 8)
    table_addr = tbl_ram if table_in_ram else BASE + rodata_off
    if not ref_table:
        table_addr = 0xE000_ED00                  # a peripheral, not the table
    code[lit_at:lit_at + 16] = struct.pack("<IIII", sdata, edata, sidata, table_addr)

    img += code + body + data_init
    return bytes(img)


def test_synthetic_flash_build_is_exposed():
    rep = P.analyse_bin(_build_image(False), P.resolve_part("f4"))
    assert rep.verdict == "EXPOSED"
    assert any(p.runtime_addr >= BASE for p in rep.placements)


def test_synthetic_ram_build_is_safe():
    """Same table bytes, same image, one placement apart."""
    rep = P.analyse_bin(_build_image(True), P.resolve_part("f4"))
    assert rep.verdict == "SAFE", "\n".join(rep.notes + [
        e for p in rep.placements for e in p.evidence])
    assert rep.placements[0].runtime_addr == 0x2000_0000


def test_the_two_synthetic_images_contain_the_same_table_bytes():
    """The point of the exercise: `fwscan` cannot tell them apart."""
    a, b = _build_image(False), _build_image(True)
    fa = P.fwscan.scan(a)
    fb = P.fwscan.scan(b)
    assert {h.name for h in fa["hits"]} == {h.name for h in fb["hits"]}
    assert SBOX[:32] in a and SBOX[:32] in b


def test_copy_region_is_recovered_from_the_literal_pool():
    img = _build_image(True)
    regions = P.find_copy_regions(img, BASE, P.resolve_part("f4"))
    assert regions, "no copy region found"
    r = regions[0]
    assert r.dst == 0x2000_0000
    assert r.src - BASE + r.length == len(img)          # tiles the tail exactly


def test_copy_chain_rejects_a_bss_shaped_phantom():
    """The bss-clear loop is (_sbss,_ebss) + any flash word, and it once ate an
    S-box on rigs/fw_f7. A region that does not reach the end of the image
    must not be accepted as a .data initialiser."""
    img = bytearray(_build_image(True))
    # splice in a plausible-looking (flash, ram, ram) triple that ends nowhere
    phantom = struct.pack("<III", BASE + 0x120, 0x2000_5000, 0x2000_5100)
    img[0x70:0x70 + 12] = phantom
    regions = P.find_copy_regions(bytes(img), BASE, P.resolve_part("f4"))
    assert all(r.dst != 0x2000_5000 for r in regions), [
        (hex(r.src), hex(r.dst), r.length) for r in regions]


# --------------------------------------------------------------------------
# The linker-script check - easy, exact, and it would have caught ST
# --------------------------------------------------------------------------

def test_stock_script_does_not_place_the_cta_section():
    ld = _need(RIGS / "fw_g4_st" / "link.ld").read_text()
    r = P.check_linker_script(ld, "CMOX_CTA_PROTECTED_DATA")
    assert not r.found


def test_cta_script_places_it_in_data_with_a_load_region():
    ld = _need(RIGS / "fw_g4_st" / "link_cta.ld").read_text()
    r = P.check_linker_script(ld, "CMOX_CTA_PROTECTED_DATA")
    assert r.found
    assert r.output_section == ".data"
    assert r.region == "RAM AT > FLASH"


def test_a_commented_out_rule_places_nothing():
    """ST's own published snippet appears inside a comment in link_cta.ld's
    header. A comment is not a linker rule."""
    ld = """
    SECTIONS {
      /* user_SAFEMEM 0x20030000 : { *(CMOX_CTA_PROTECTED_DATA) } */
      .text : { *(.text*) } > FLASH
    }
    """
    r = P.check_linker_script(ld, "CMOX_CTA_PROTECTED_DATA")
    assert not r.found
    assert "comment" in r.output_section


def test_ram_placement_with_no_load_region_is_detectable():
    """ST's published STM32CubeIDE snippet has no `AT >`, so the tables arrive
    uninitialised. `region` must show that, not just 'it is mentioned'."""
    ld = """
    SECTIONS {
      user_SAFEMEM 0x20030000 : { . = ALIGN(8); *(CMOX_CTA_PROTECTED_DATA) } > RAM
    }
    """
    r = P.check_linker_script(ld, "CMOX_CTA_PROTECTED_DATA")
    assert r.found
    assert r.region == "RAM"
    assert "AT" not in r.region


def test_iar_icf_dialect():
    icf = 'place in RAM_region { section CMOX_CTA_PROTECTED_DATA };'
    r = P.check_linker_script(icf, "CMOX_CTA_PROTECTED_DATA")
    assert r.dialect == "icf" and r.found and r.region == "RAM_region"


def test_strip_comments_preserves_offsets():
    src = "a /* xx */ b\n// y\nc"
    out = P.strip_comments(src)
    assert len(out) == len(src)
    assert out.count("\n") == src.count("\n")
    assert "xx" not in out and "y" not in out


# --------------------------------------------------------------------------
# `ar` archives
# --------------------------------------------------------------------------

def test_iter_archive_round_trip():
    def member(name: str, body: bytes) -> bytes:
        hdr = f"{name:<16}{'0':<12}{'0':<6}{'0':<6}{'100644':<8}{len(body):<10}`\n"
        return hdr.encode() + body + (b"\n" if len(body) & 1 else b"")

    arch = b"!<arch>\n" + member("a.o/", b"hello") + member("b.o/", b"world!")
    got = list(P.iter_archive(arch))
    assert got == [("a.o", b"hello"), ("b.o", b"world!")]


# --------------------------------------------------------------------------
# Real artefacts from this repo, whose labels came off silicon
# --------------------------------------------------------------------------

def _need(path: pathlib.Path) -> pathlib.Path:
    if not path.exists():
        pytest.skip(f"{path.name} not built")
    return path


@pytest.mark.parametrize("name", [
    "fixed_mbedtls.bin", "fixed_mbedtls_compact.bin",
    "fixed_tinyaes.bin", "fixed_tinycrypt.bin",
])
def test_committed_leaky_library_images_are_exposed(name):
    """These four are the images whose keys were recovered on the F429."""
    rep = P.analyse(str(_need(LIB / name)), "f4")
    assert rep.verdict == "EXPOSED"
    assert all(p.runtime_addr >= BASE for p in rep.placements)


@pytest.mark.parametrize("name", ["fw_bearssl_ct.bin", "fw_openssl_ct.bin"])
def test_constant_time_negative_controls_stay_clean(name):
    """BearSSL aes_ct and OpenSSL CT measured 0/16 on hardware. If these come
    back EXPOSED the tool has a false positive on the two builds that matter
    most for that."""
    rep = P.analyse(str(_need(LIB / name)), "f4")
    assert rep.verdict == "NO-TABLES"
    assert rep.placements == []


def test_own_aes_elf_is_exposed_and_names_the_symbols():
    rep = P.analyse(str(_need(RIGS / "fw_f4" / "fw.elf")), "f4")
    assert rep.verdict == "EXPOSED"
    syms = {p.symbol for p in rep.placements}
    assert "SBOX" in syms and "Te0" in syms
    assert all(p.section in (".text", ".rodata") for p in rep.placements)


def test_own_aes_elf_hedges_about_the_runtime_pointer_flip():
    """rigs/fw_f4 and fw_f4_ctguard share aes.c, which swaps between a flash
    table and a .bss copy at run time. The tool cannot decide that - but it
    must not be quietly confident about it either."""
    rep = P.analyse(str(_need(RIGS / "fw_f4" / "fw.elf")), "f4")
    assert any("RUNTIME decision" in n for n in rep.notes)


def test_elf_and_bin_paths_agree_on_the_same_build():
    elf = _need(RIGS / "fw_f4" / "fw.elf")
    raw = _need(RIGS / "fw_f4" / "fw.bin")
    a = P.analyse(str(elf), "f4")
    b = P.analyse(str(raw), "f4")
    assert a.verdict == b.verdict
    a_addrs = {p.runtime_addr for p in a.placements}
    b_addrs = {p.runtime_addr for p in b.placements}
    assert a_addrs == b_addrs, (sorted(map(hex, a_addrs)), sorted(map(hex, b_addrs)))


def test_shadow_ram_tables_do_not_masquerade_as_a_group_relocation():
    """rigs/fw_f4 keeps te0_ram..te3_ram in .bss at exactly the same 1 KB
    spacing as Te0..Te3 in flash, so those four .bss addresses fit a "the whole
    group moved to RAM" hypothesis perfectly. They must not win: SBOX's own
    flash address is in a literal, which proves the group did not move."""
    rep = P.analyse(str(_need(RIGS / "fw_f4" / "fw.bin")), "f4")
    assert rep.verdict == "EXPOSED"
    assert all(p.runtime_addr >= BASE for p in rep.placements), \
        sorted(hex(p.runtime_addr) for p in rep.placements)


def test_st_archive_is_conditional_and_names_the_rule():
    """ST's X-CUBE-CRYPTOLIB: the archive cannot be more than conditional, and
    the required rule is the finding."""
    cands = [
        pathlib.Path("C:/dev/xcube-analysis/STM32CubeExpansion_Crypto_V5.0.0/"
                     "Middlewares/ST/STM32_Cryptographic/lib/"
                     "libSTM32Cryptographic_CM4.a"),
    ]
    path = next((c for c in cands if c.exists()), None)
    if path is None:
        pytest.skip("X-CUBE-CRYPTOLIB not available")
    rep = P.analyse(str(path), "g4")
    assert rep.verdict == "CONDITIONAL"
    assert {p.section for p in rep.placements} == {"CMOX_CTA_PROTECTED_DATA"}
    joined = " ".join(rep.notes)
    assert "CMOX_CTA_PROTECTED_DATA" in joined and "> RAM AT > FLASH" in joined


def test_intel_hex_agrees_with_the_same_build_as_a_bin():
    """MCU firmware ships as .hex at least as often as .bin, and the record
    stream carries the real flash base - the thing the raw-.bin path most often
    lacks."""
    hexf = _need(RIGS / "fw_f3_aes" / "fw.hex")
    raw = _need(RIGS / "fw_f3_aes" / "fw.bin")
    a = P.analyse(str(hexf), "f3")
    b = P.analyse(str(raw), "f3")
    assert a.kind == "ihex"
    assert a.verdict == b.verdict
    assert {p.runtime_addr for p in a.placements} == {p.runtime_addr for p in b.placements}
    assert any("Intel HEX flattened" in n for n in a.notes)


def test_a_wrong_base_is_detected_from_the_literal_pool():
    """Tell it the image is XIP at 0x90000000 when it is really at 0x08000000:
    the group-relocation arithmetic recovers the true base and says so, instead
    of quietly reporting every address 0x88000000 too high."""
    raw = _need(LIB / "fixed_tinyaes.bin")
    rep = P.analyse(str(raw), "h7", base=0x9000_0000)
    joined = " ".join(rep.notes)
    assert "0x08000000 is itself a plausible flash base" in joined
    assert "--base 0x8000000" in joined


def test_ci_gate_fails_a_leaky_build_and_passes_a_fixed_one(tmp_path):
    """`--fail-on exposed` is what makes this a deployment linter rather than a
    report: a build whose tables are read from flash exits non-zero."""
    leaky = _need(LIB / "fixed_tinyaes.bin")
    clean = _need(LIB / "fw_bearssl_ct.bin")
    assert P.main([str(leaky), "--part", "f4", "--quiet", "--fail-on", "exposed"]) == 1
    assert P.main([str(clean), "--part", "f4", "--quiet", "--fail-on", "exposed"]) == 0
    assert P.main([str(leaky), "--part", "f4", "--quiet"]) == 0        # report mode


def test_a_linker_script_missing_the_rule_fails_the_gate(tmp_path):
    """The check that would have caught ST: archive + stock script -> non-zero."""
    obj = tmp_path / "fake.ld"
    obj.write_text("SECTIONS { .text : { *(.text*) } > FLASH }\n")
    img = _need(LIB / "fixed_tinyaes.bin")
    # a clean image plus a script that does not place the named section
    clean = _need(LIB / "fw_bearssl_ct.bin")
    rc = P.main([str(clean), "--part", "f4", "--quiet",
                 "--section", "CMOX_CTA_PROTECTED_DATA", "--ld", str(obj),
                 "--fail-on", "exposed"])
    assert rc == 1, "a missing placement rule must fail the gate"
    assert img.exists()


def test_json_output_is_machine_readable(tmp_path):
    import json
    out = tmp_path / "p.json"
    P.main([str(_need(LIB / "fixed_tinyaes.bin")), "--part", "f4", "--quiet",
            "--json", str(out)])
    d = json.loads(out.read_text())
    assert d[0]["verdict"] == "EXPOSED"
    assert d[0]["tables"][0]["runtime_addr"].startswith("0x08")
    assert d[0]["tables"][0]["exposure"] == P.EXPOSED


def test_no_vector_table_says_so_rather_than_assuming():
    """A partial dump has no vector table at offset 0. The base is then a guess,
    and the tool has to say so."""
    blob = b"\xff" * 64 + SBOX + b"\xff" * 64
    rep = P.analyse_bin(blob, P.resolve_part("f4"))
    assert any("no Cortex-M vector table" in n for n in rep.notes)
    assert rep.verdict == "UNDETERMINED"


def test_a_guessed_base_cannot_produce_a_confident_verdict():
    """An image with no vector table has an assumed base, so a copy-loop mapping
    computed from it is arithmetic on an assumption. ST-LINK's `f1_1.bin`
    answered SAFE this way before the check existed."""
    img = bytearray(_build_image(True, ref_table=False))
    img[0:8] = b"\xff" * 8                    # destroy the vector table
    rep = P.analyse_bin(bytes(img), P.resolve_part("f4"))
    assert any("no Cortex-M vector table" in n for n in rep.notes)
    assert rep.verdict == "UNDETERMINED"


def test_an_explicit_base_restores_the_verdict():
    img = bytearray(_build_image(True, ref_table=False))
    img[0:8] = b"\xff" * 8
    rep = P.analyse_bin(bytes(img), P.resolve_part("f4"), base=BASE)
    assert rep.verdict == "SAFE"


def test_a_corroborating_literal_survives_a_guessed_base():
    """The downgrade is about *uncorroborated* arithmetic. A literal that holds
    the mapped RAM address would not match under a wrong base, so it stands.

    The table is deliberately NOT first in .data here, so its run-time address
    differs from `_sdata` - otherwise the only RAM literal in the image is the
    copy loop's own destination, which proves nothing about where the cipher
    reads.
    """
    img = bytearray(_build_image(True, table_first=False))
    img[0:8] = b"\xff" * 8
    rep = P.analyse_bin(bytes(img), P.resolve_part("f4"))
    assert rep.verdict == "SAFE", "\n".join(
        rep.notes + [e for p in rep.placements for e in p.evidence])


def test_a_table_with_no_evidence_at_all_is_undetermined_not_exposed():
    """No copy loop, no literal, no anchor: 'stays in flash' is an assumption."""
    blob = struct.pack("<II", 0x2001_8000, BASE + 0x101) + b"\x00" * 0xF8 + SBOX
    rep = P.analyse_bin(blob, P.resolve_part("f4"))
    assert rep.verdict == "UNDETERMINED"
    assert any("assumption, not a finding" in e
               for p in rep.placements for e in p.evidence)
