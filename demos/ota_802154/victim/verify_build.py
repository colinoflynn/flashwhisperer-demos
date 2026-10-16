"""Confirm the build flags actually reached the images, rather than trusting make.

`make` exiting 0 does not mean a -D landed.  Two ways it silently does not, both
hit while building this rig:

  * the shell BRACE-EXPANDS a value like {0x01,0x02,...}, so one -D becomes
    sixteen and the macro ends up defined as its last byte.  The build still
    compiles for a while before failing, and a near-miss variant would compile
    clean with the wrong value;
  * EXTRA_DEFINES is not tracked by the Makefile, so a rebuild with different
    flags happily reuses stale objects unless the output tree is removed.

So every value that matters is checked against the linked binary here.  Grepping
the .bin for a constant gives a FALSE NEGATIVE for anything the compiler emits
as an immediate, so scalars are read from the initialised data of the radio
config struct and the key is looked for as a byte string in .rodata.

    python3 verify_build.py <outdir> <key-hex> <datarate>
"""
from __future__ import annotations
import glob, os, struct, subprocess, sys

OK, BAD, SKIP = "  ok   ", "  FAIL ", "  skip "
fails = []


def _tool(args):
    """Run a binutils command, or return None if the toolchain is absent.

    This script is invoked from build_rig.sh, which runs where
    arm-none-eabi-* lives.  Run by hand from a different shell it may not,
    and a missing toolchain should skip the checks that need it rather than
    raise -- the checks that only need to read the ELF still work.
    """
    try:
        return subprocess.run(args, capture_output=True, text=True).stdout
    except (FileNotFoundError, OSError):
        return None


def _elf(d):
    e = glob.glob(os.path.join(d, "*.elf"))
    return e[0] if e else None


def _sym_bytes(elf, sym, n):
    """n bytes of an initialised symbol, read out of the ELF's sections."""
    out = _tool(["arm-none-eabi-nm", elf])
    if out is None:
        return None
    addr = None
    for ln in out.splitlines():
        f = ln.split()
        if len(f) == 3 and f[2] == sym:
            addr = int(f[0], 16)
    if addr is None:
        return None
    dump = _tool(["arm-none-eabi-objdump", "-s", elf])
    if dump is None:
        return None
    blob = {}
    for ln in dump.splitlines():
        f = ln.split()
        if len(f) >= 2 and len(f[0]) == 8:
            try:
                a = int(f[0], 16)
            except ValueError:
                continue
            hexpart = "".join(f[1:5])
            try:
                blob[a] = bytes.fromhex(hexpart)
            except ValueError:
                continue
    buf = b""
    a = addr & ~0xF
    while len(buf) < n + 16 and a in blob:
        buf += blob[a]
        a += 16
    off = addr - (addr & ~0xF)
    return buf[off:off + n] if len(buf) >= off + n else None


def check(label, got, want):
    same = got == want
    print("%s%-34s got %-22s want %s" % (OK if same else BAD, label, got, want))
    if not same:
        fails.append(label)


def main():
    outdir, key_hex, datarate = sys.argv[1], sys.argv[2].lower(), int(sys.argv[3])
    key = bytes.fromhex(key_hex)

    for role in ("victim", "coord"):
        elf = _elf(os.path.join(outdir, role))
        if not elf:
            print("%s%s: no .elf" % (BAD, role)); fails.append(role); continue
        print("\n== %s  (%s)" % (role, os.path.basename(elf)))

        # The LLSEC key is a 16-byte array in .rodata, so it IS findable as a
        # literal byte string -- unlike scalars, which become immediates.
        raw = open(elf, "rb").read()
        check("LLSEC key present", key in raw, True)
        # and the upstream default must NOT be there, which would mean the
        # RIG_KEY override silently did not apply
        check("upstream default key absent",
              bytes(range(16)) not in raw, True)

        # The EUI-64 is deliberately NOT checked here.  `node_mac` lives in .bss
        # and is filled at run time, so there is nothing in the ELF to read; the
        # `rig_mac` constant it is copied from is `static const`, gets inlined,
        # and its value -- seven zero bytes and a 1 or a 2 -- occurs by chance
        # in any padded image, so searching for it would pass whether or not
        # NODE_MAC_FIXED took effect.  A check that cannot fail is worse than no
        # check.  The addresses are verified ON AIR instead, where they are
        # unambiguous: capture a few hundred records with
        # instruments/sniff802154/capture.py and decode one frame's addresses
        # with demos/ota_802154/host/frames.py.  That is the authoritative test
        # anyway, since it confirms what the running node transmits rather than
        # what was linked.

        # What IS worth asserting about the victim: it carries no instrumentation.
        if role == "victim":
            nm = _tool(["arm-none-eabi-nm", elf])
            if nm is None:
                print("%sno ota_ instrumentation (arm-none-eabi-nm not on PATH)" % SKIP)
            else:
                check("no ota_ instrumentation",
                      sum(1 for l in nm.splitlines() if "ota_" in l.lower()), 0)

    elf = _elf(os.path.join(outdir, "sniffer"))
    if elf:
        print("\n== sniffer  (%s)" % os.path.basename(elf))
        xr = _sym_bytes(elf, "xRadioInit", 20)
        if xr:
            base, mod, rate, dev, bw = struct.unpack("<IIIII", xr)
            check("base frequency", base, 915000000)
            check("datarate", rate, datarate)
        else:
            print("%sradio config (arm-none-eabi-* not on PATH)" % SKIP)
        # the sniffer must never contain the key
        check("key absent from sniffer", key not in open(elf, "rb").read(), True)

    print()
    if fails:
        print("VERIFY FAILED: %s" % ", ".join(fails))
        return 1
    print("verify: all checked values are present in the linked images")
    return 0


if __name__ == "__main__":
    sys.exit(main())
