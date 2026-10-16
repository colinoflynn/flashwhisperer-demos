"""Static triage of a firmware image: is this target a candidate at all?

The step *before* `flashleak probe`. Given a firmware blob downloaded from a
vendor's support page, answer the two questions that eliminate most products
without touching hardware:

  1. Does it execute in place from flash on an MCU?  A Cortex-M vector table
     at the head of the image says yes, and gives the flash base address.
     Anything that turns out to be a Linux/ARM9 image running from SDRAM is
     the classic cache-timing target, not this one.

  2. Does it contain AES *tables*, and in which layout?  The layout decides
     the outcome, and it is visible statically:

       S-box only ............. leaks (measured: tiny-AES, TinyCrypt, GmSSL)
       one T-table + S-box .... leaks, and is also round-2 recoverable
       four T-tables .......... resists round 2; the last round still falls
                                if the final round reads a single table
       no tables at all ....... possibly constant-time (BearSSL aes_ct,
                                OpenSSL CT) - or just compressed, check that

The scanner reports where the tables sit relative to the flash base, because a
table in `.rodata` is the whole precondition; mbedTLS without
MBEDTLS_AES_ROM_TABLES builds them in RAM at startup and is immune, and that
is the most common false positive in this whole exercise.

    python -m flashleak fwscan firmware.bin
    python -m flashleak fwscan firmware.bin --base 0x08000000 --decompress
"""
from __future__ import annotations

import argparse
import gzip
import lzma
import re
import zlib
from dataclasses import dataclass, field

from flashattack.aesref import SBOX as _SBOX, SINV as _SINV

# Fingerprints, not copies: enough bytes to be unique in a megabyte, taken from
# the FIPS-verified tables in flashattack.aesref so there is one source of truth.
SBOX = bytes(_SBOX[:32])
ISBOX = bytes(_SINV[:32])
RCON = bytes([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36])


def _xtime(a: int) -> int:
    a <<= 1
    return (a ^ 0x1b) & 0xff if a & 0x100 else a


def _te_prefix(rot: int, big_endian: bool, n: int = 16) -> bytes:
    """First `n` bytes of Te<rot>, as they appear in memory.

    Te0[i] = [2.S[i], S[i], S[i], 3.S[i]] as a big-endian word; Te1..Te3 are
    byte rotations of it. Both endiannesses are searched because the stored
    order depends on the target, not on the library.
    """
    out = bytearray()
    for i in range(n // 4):
        s = int(_SBOX[i])
        word = [_xtime(s), s, s, _xtime(s) ^ s]          # Te0 = [2s, s, s, 3s]
        if rot:
            word = word[-rot:] + word[:-rot]
        if not big_endian:
            word = word[::-1]
        out += bytes(word)
    return bytes(out)


@dataclass
class Hit:
    name: str
    offsets: list[int] = field(default_factory=list)


def _gf_mul(a: int, b: int) -> int:
    """Multiply in GF(2^8) with the AES polynomial."""
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        a = _xtime(a)
        b >>= 1
    return r


def _td_prefix(rot: int, big_endian: bool, n: int = 16) -> bytes:
    """First `n` bytes of Td<rot>, the AES *decryption* T-table.

    Td0[x] = [14.S'[x], 9.S'[x], 13.S'[x], 11.S'[x]] as a big-endian word, with
    Td1..Td3 as byte rotations. Worth searching separately from Te: a decrypt-only
    build (a bootloader, typically) carries Td and no Te at all.
    """
    out = bytearray()
    for i in range(n // 4):
        s = int(_SINV[i])
        word = [_gf_mul(s, 14), _gf_mul(s, 9), _gf_mul(s, 13), _gf_mul(s, 11)]
        if rot:
            word = word[-rot:] + word[:-rot]
        if not big_endian:
            word = word[::-1]
        out += bytes(word)
    return bytes(out)


def _gf_sb(mul: int, n: int = 24) -> bytes:
    """First n bytes of Gladman's gfm<mul>_sb table: mul . S[x] in GF(2^8)."""
    out = bytearray()
    for i in range(n):
        s = int(_SBOX[i])
        out.append(_xtime(s) if mul == 2 else _xtime(s) ^ s)
    return bytes(out)


def patterns() -> list[tuple[str, bytes]]:
    pats: list[tuple[str, bytes]] = [
        ("AES S-box", SBOX),
        ("AES inverse S-box", ISBOX),
        ("Rcon", RCON),
        ("gfm2_sb (Gladman)", _gf_sb(2)),
        ("gfm3_sb (Gladman)", _gf_sb(3)),
    ]
    for rot in range(4):
        for be in (False, True):
            pats.append((f"Te{rot} ({'BE' if be else 'LE'})", _te_prefix(rot, be)))
            pats.append((f"Td{rot} ({'BE' if be else 'LE'})", _td_prefix(rot, be)))
    return pats


def find_vector_table(data: bytes) -> tuple[int, int] | None:
    """Return (flash_base, reset_handler) if the head looks like Cortex-M.

    Entry 0 is the initial stack pointer, which lands in SRAM (0x2000_0000 on
    every STM32, 0x1000_0000/0x2000_0000 elsewhere). Entry 1 is the reset
    vector: a Thumb address, so bit 0 is set.
    """
    if len(data) < 8:
        return None
    sp = int.from_bytes(data[0:4], "little")
    reset = int.from_bytes(data[4:8], "little")
    sp_ok = 0x1000_0000 <= sp < 0x2010_0000 and sp % 4 == 0
    reset_ok = reset & 1 and 0x0000_0000 <= reset < 0x2000_0000
    if not (sp_ok and reset_ok):
        return None
    return reset & ~0xFFFFF, reset & ~1


def inflate_streams(data: bytes, limit: int = 64) -> list[tuple[str, int, bytes]]:
    """Best-effort: pull decompressible streams out of a packed image."""
    out: list[tuple[str, int, bytes]] = []
    for m in re.finditer(rb"\x1f\x8b\x08", data):
        try:
            out.append(("gzip", m.start(), gzip.decompress(data[m.start():])))
        except Exception:
            pass
        if len(out) >= limit:
            return out
    for m in re.finditer(rb"\x78[\x01\x5e\x9c\xda]", data):
        try:
            d = zlib.decompressobj()
            blob = d.decompress(data[m.start():])
            if len(blob) > 4096:
                out.append(("zlib", m.start(), blob))
        except Exception:
            pass
        if len(out) >= limit:
            return out
    for m in re.finditer(rb"\xfd7zXZ\x00", data):
        try:
            out.append(("xz", m.start(), lzma.decompress(data[m.start():])))
        except Exception:
            pass
        if len(out) >= limit:
            break
    rle = unpack_rle(data)
    if len(rle) > len(data):
        out.append(("run-length (PackBits-style)", 0, rle))
    return out


def unpack_rle(data: bytes, limit: int = 4 << 20) -> bytes:
    """PackBits-style literal/run decode.

    Found the hard way on ST's ST-LINK firmware: after AES decryption the image
    is still run-length packed, so the 256-byte S-box shows up as 127-byte
    literal runs with a count byte wedged in between, and an exact table search
    matches only the first 32 bytes. Control byte n < 0x80 means "n+1 literals
    follow"; n >= 0x80 means "repeat the next byte 257-n times".
    """
    out = bytearray()
    i = 0
    while i < len(data) and len(out) < limit:
        n = data[i]
        i += 1
        if n < 0x80:
            out += data[i:i + n + 1]
            i += n + 1
        else:
            if i >= len(data):
                break
            out += bytes([data[i]]) * (257 - n)
            i += 1
    return bytes(out)


def scan(data: bytes) -> dict:
    hits = []
    for name, pat in patterns():
        offs = [m.start() for m in re.finditer(re.escape(pat), data)]
        if offs:
            hits.append(Hit(name, offs))
    return {"hits": hits, "vector": find_vector_table(data), "size": len(data)}


def verdict(res: dict) -> list[str]:
    names = {h.name for h in res["hits"]}
    te = sorted({n.split()[0] for n in names if n.startswith("Te")})
    td = sorted({n.split()[0] for n in names if n.startswith("Td")})
    lines = []
    if not (names & {"AES S-box", "AES inverse S-box"}) and not te and not td:
        lines.append("no AES lookup tables in flash" +
                     (" (but Rcon is present, so AES is compiled in)" if "Rcon" in names else "") +
                     " - consistent with a constant-time/bitsliced core "
                     "(BearSSL aes_ct, OpenSSL CT: both measured 0/16 here), or "
                     "with tables built into RAM at startup (mbedTLS without "
                     "MBEDTLS_AES_ROM_TABLES). Either way, not exposed. If the "
                     "image is packed, re-run with --decompress before believing it.")
        return lines
    if len(te) >= 4:
        lines.append(f"four T-tables present ({', '.join(te)}) - the 4-table "
                     "layout. Round 2 resists; the LAST round still falls if the "
                     "final round reads one table (measured: mbedTLS, wolfSSL, "
                     "OpenSSL, Nettle all 16/16 on the F429).")
    elif te:
        lines.append(f"single T-table ({', '.join(te)}) - the compact build. "
                     "Leaks the full key AND is round-2 recoverable from one side "
                     "of the cipher (mbedTLS FEWER_TABLES shape).")
    if "AES S-box" in names and not te:
        lines.append("byte S-box only - the tiny-AES / TinyCrypt / GmSSL shape. "
                     "Leaks the full key on any part whose flash data cache is "
                     "smaller than 256 B (F2/F4 = 128 B; F1/F3 = no data cache).")
    elif "AES S-box" in names:
        lines.append("S-box also present (used by the key schedule and, in most "
                     "builds, the final round - that is the round the attack reads).")
    if "gfm2_sb (Gladman)" in names and "gfm3_sb (Gladman)" in names:
        lines.append("sbox + gfm2_sb + gfm3_sb -> the Gladman compact AES table "
                     "triple. That is the layout of LoRaMac-node's soft-se "
                     "(Semtech's reference LoRaWAN end-device stack), which we "
                     "compiled and broke on the F429: 16/16 at 400 k traces.")
    if td:
        lines.append(f"decryption T-table(s) present ({', '.join(td)}) - {len(td)} KB of "
                     "inverse tables in flash. Bigger than the F2/F4 128 B and the G4/L4 256 B "
                     "ART data cache alike, so this leaks on every measured band, unlike a lone "
                     "256 B S-box which fits the 256 B cache.")
    if "AES inverse S-box" in names:
        lines.append("inverse S-box present -> this image DECRYPTS. A decrypt "
                     "oracle recovers rk[0] = the master key directly.")
    return lines


def render(path: str, res: dict, base_override: int | None = None) -> str:
    out = [f"{path}: {res['size']} bytes"]
    vec = res["vector"]
    if vec:
        out.append(f"  Cortex-M vector table: flash base ~{vec[0]:#010x}, "
                   f"reset {vec[1]:#010x}  -> XIP MCU image (in scope)")
    else:
        out.append("  no Cortex-M vector table at offset 0 - either not a raw "
                   "flash image, or not an MCU target (packed/ELF/Linux?)")
    base = base_override if base_override is not None else (vec[0] if vec else None)
    for h in res["hits"]:
        where = ""
        if base is not None:
            where = "  @ " + ", ".join(f"{base + o:#010x}" for o in h.offsets[:4])
        out.append(f"  HIT {h.name:18s} x{len(h.offsets):<3d} "
                   f"off {', '.join(hex(o) for o in h.offsets[:4])}{where}")
    for line in verdict(res):
        out.append(f"  => {line}")
    return "\n".join(out)


def ihex_to_bin(text: str) -> tuple[bytes, int] | None:
    """Flatten Intel HEX to (image, base_address). MCU firmware ships this way
    at least as often as it ships as a .bin, and the record stream also gives
    us the real flash base for free."""
    chunks: dict[int, int] = {}
    upper = 0
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith(":"):
            continue
        try:
            rec = bytes.fromhex(line[1:])
        except ValueError:
            return None
        n, addr, rtype = rec[0], int.from_bytes(rec[1:3], "big"), rec[3]
        body = rec[4:4 + n]
        if rtype == 0x00:
            for i, b in enumerate(body):
                chunks[upper + addr + i] = b
        elif rtype == 0x04:
            upper = int.from_bytes(body, "big") << 16
        elif rtype == 0x02:
            upper = int.from_bytes(body, "big") << 4
        elif rtype == 0x01:
            break
    if not chunks:
        return None
    lo, hi = min(chunks), max(chunks)
    out = bytearray(b"\xff" * (hi - lo + 1))
    for a, b in chunks.items():
        out[a - lo] = b
    return bytes(out), lo


def iter_members(path: str, max_bytes: int = 64 << 20):
    """Yield (label, bytes) for a file, every file in a directory, or every
    member of a zip/tar/gz archive. Vendor firmware almost never arrives as a
    bare .bin, and unpacking by hand is the slow part of triage."""
    import os
    import tarfile
    import zipfile

    if os.path.isdir(path):
        for root, _dirs, files in os.walk(path):
            for name in sorted(files):
                full = os.path.join(root, name)
                if os.path.getsize(full) <= max_bytes:
                    yield os.path.relpath(full, path), open(full, "rb").read()
        return

    raw = open(path, "rb").read()
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            for info in z.infolist():
                if not info.is_dir() and info.file_size <= max_bytes:
                    try:
                        yield info.filename, z.read(info)
                    except Exception as exc:                       # encrypted member
                        yield f"{info.filename} <unreadable: {exc}>", b""
        return
    try:
        with tarfile.open(path) as t:
            for m in t.getmembers():
                if m.isfile() and m.size <= max_bytes:
                    f = t.extractfile(m)
                    if f:
                        yield m.name, f.read()
            return
    except tarfile.TarError:
        pass
    if raw[:3] == b"\x1f\x8b\x08":
        try:
            yield path + " (gunzipped)", gzip.decompress(raw)
            return
        except Exception:
            pass
    yield path, raw


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="flashleak fwscan", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("image", help="firmware binary, directory, or zip/tar archive")
    ap.add_argument("--base", type=lambda s: int(s, 0), default=None,
                    help="flash base address, if the vector table is not at offset 0")
    ap.add_argument("--decompress", action="store_true",
                    help="also scan decompressible streams inside the image")
    ap.add_argument("--only-hits", action="store_true",
                    help="for archives/directories, print only members with findings")
    args = ap.parse_args(argv)
    return run(args.image, base=args.base, decompress=args.decompress,
               only_hits=args.only_hits)


def run(path: str, base=None, decompress=False, only_hits=False) -> int:
    members = list(iter_members(path))
    if len(members) > 1:
        print(f"{path}: {len(members)} members")
    found = 0
    for label, data in members:
        if not data:
            continue
        member_base = base
        if data[:1] == b":" or label.lower().endswith((".hex", ".ihx", ".ihex")):
            conv = ihex_to_bin(data.decode("latin-1"))
            if conv:
                data, lo = conv
                member_base = base if base is not None else lo
                label = f"{label} (Intel HEX, base {lo:#010x}, {len(data)} bytes)"
        res = scan(data)
        interesting = bool(res["hits"] or res["vector"])
        found += interesting
        if only_hits and not interesting:
            continue
        print(render(label, res, base))
        if decompress:
            streams = inflate_streams(data)
            for kind, off, blob in streams:
                sub = scan(blob)
                if sub["hits"] or sub["vector"]:
                    print(render(f"  {kind} stream @ {off:#x}", sub, base))
    if len(members) > 1:
        print(f"-- {found}/{len(members)} members had a vector table or AES tables")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
