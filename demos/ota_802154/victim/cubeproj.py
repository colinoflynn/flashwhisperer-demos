#!/usr/bin/env python3
"""Extract the build recipe (sources, includes, defines, MCU) from an
STM32CubeIDE project, so it can be built with plain make + arm-none-eabi-gcc.

Emits GNU make variable assignments on stdout.  Paths are printed relative
to --rel (default: cwd).

Usage: cubeproj.py <path-to-STM32CubeIDE-dir> [--rel DIR]
"""
import os
import re
import sys

# Cortex core per STM32 family, for -mcpu.
CORE_BY_FAMILY = {
    "F0": "cortex-m0", "F1": "cortex-m3", "F2": "cortex-m3",
    "F3": "cortex-m4", "F4": "cortex-m4", "F7": "cortex-m7",
    "G0": "cortex-m0plus", "G4": "cortex-m4",
    "L0": "cortex-m0plus", "L1": "cortex-m3", "L4": "cortex-m4",
    "L5": "cortex-m33", "WB": "cortex-m4", "WL": "cortex-m4",
}

# An <option ...> that is not self-closing, i.e. one that has children.
OPTION_WITH_BODY = re.compile(r"<option\b((?:[^>]*[^/>])?)>(.*?)</option>",
                              re.S)


def project_loc_parent(cube_dir, n):
    """Resolve Eclipse's PARENT-<n>-PROJECT_LOC against the project dir."""
    p = cube_dir
    for _ in range(n):
        p = os.path.dirname(p)
    return p


def linked_sources(cube_dir):
    """Source files the CubeIDE project pulls in as linked resources."""
    with open(os.path.join(cube_dir, ".project")) as f:
        text = f.read()
    out = []
    for link in re.findall(r"<link>(.*?)</link>", text, re.S):
        loc = (re.search(r"<locationURI>(.*?)</locationURI>", link)
               or re.search(r"<location>(.*?)</location>", link))
        if not loc:
            continue
        uri = loc.group(1)
        if not uri.endswith((".c", ".s", ".S")):
            continue
        m = re.match(r"PARENT-(\d+)-PROJECT_LOC/(.*)", uri)
        if m:
            path = os.path.join(project_loc_parent(cube_dir, int(m.group(1))),
                                m.group(2))
        else:
            path = os.path.join(cube_dir, uri)
        out.append(os.path.normpath(path))
    return out


def option_values(text, superclass_substr):
    """listOptionValue entries of every <option> whose superClass matches."""
    vals = []
    for m in OPTION_WITH_BODY.finditer(text):
        if superclass_substr not in m.group(1):
            continue
        vals += re.findall(r'<listOptionValue\b[^>]*\bvalue="([^"]*)"',
                           m.group(2))
    return vals


def scalar_option(text, superclass_substr):
    m = re.search(r'<option\b[^>]*superClass="[^"]*' + superclass_substr
                  + r'"[^>]*\bvalue="([^"]*)"', text)
    return m.group(1) if m else None


def uniq(seq):
    seen, out = set(), []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def dir_files(path, exts):
    if not os.path.isdir(path):
        return []
    return [os.path.join(path, f) for f in sorted(os.listdir(path))
            if f.endswith(exts)]


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    rel = os.getcwd()
    for i, a in enumerate(sys.argv):
        if a == "--rel":
            rel = sys.argv[i + 1]
    cube_dir = os.path.abspath(args[0])

    with open(os.path.join(cube_dir, ".cproject")) as f:
        cproj = f.read()

    sources = linked_sources(cube_dir)
    # Startup assembly and the syscall stubs live inside the project dir
    # rather than being linked in.
    sources += dir_files(os.path.join(cube_dir, "Application", "Startup"),
                         (".s", ".S"))
    sources += dir_files(os.path.join(cube_dir, "Application", "User"), (".c",))

    # CubeIDE include paths are relative to the build output directory
    # (<project>/Debug or <project>/Release), one level below the project.
    inc_base = os.path.join(cube_dir, "Debug")
    includes = [os.path.normpath(os.path.join(inc_base, p))
                for p in option_values(cproj,
                                       "c.compiler.option.includepaths")]

    # DEBUG is left to the caller's build configuration.
    defines = [d for d in option_values(cproj,
                                        "c.compiler.option.definedsymbols")
               if d != "DEBUG"]

    mcu = scalar_option(cproj, r"managedbuild\.option\.target_mcu") or ""
    fpu = scalar_option(cproj, r"managedbuild\.option\.fpu")
    abi = scalar_option(cproj, r"managedbuild\.option\.floatabi")
    fpu = fpu.rsplit(".", 1)[-1] if fpu else "none"
    abi = abi.rsplit(".", 1)[-1] if abi else "soft"
    core = CORE_BY_FAMILY.get(mcu[5:7].upper(), "cortex-m4")

    lds = sorted(f for f in os.listdir(cube_dir) if f.endswith("_FLASH.ld"))

    def r(p):
        return os.path.relpath(p, rel).replace(os.sep, "/")

    print("# Generated from %s by cubeproj.py -- do not edit." % r(cube_dir))
    print("MCU := %s" % mcu)
    print("CORE := %s" % core)
    print("FPU := %s" % fpu)
    print("FLOAT_ABI := %s" % abi)
    print("LDSCRIPT := %s" % (r(os.path.join(cube_dir, lds[0])) if lds else ""))
    print("DEFINES := %s" % " ".join(uniq(defines)))
    for name, items in (("INCLUDES", includes), ("SOURCES", sources)):
        print("%s :=" % name)
        for it in uniq(items):
            print("%s += %s" % (name, r(it)))


if __name__ == "__main__":
    main()
