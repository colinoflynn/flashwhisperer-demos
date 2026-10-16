"""Arms E: rewrite PRECON *after* SYS_Initialize, cache left ON.

    python arm_e_precon.py apply --pfmws 7 --prefen 3
    python arm_e_precon.py apply --pfmws 2 --prefen 3
    python arm_e_precon.py apply --pfmws 3 --prefen 1
    python arm_e_precon.py revert

WHY AFTER, AND WHY THIS SCRIPT EXISTS.  Harmony's generated `SYS_Initialize`
writes the flash controller itself, unguarded, immediately after
`CLK_Initialize` (`initialization.c:873`, disassembled at `0x9D03E458` in the
linked image):

    PRECONbits.PREFEN = 3;      /* all four prefetch lines, incl. CPU data */
    PRECONbits.PFMWS  = 3;      /* a RESERVED encoding on MZ EF            */
    CFGCONbits.ECCCON = 3;

So the shipped demo does NOT run with the part's reset `PFMWS = 7, PREFEN = 0`.
`arm_d_cache_off_prefetch_on.py` set PRECON at the top of `main()` and had it
overwritten on the very next line; this one writes after `SYS_Initialize`
returns, which is the only placement that sticks.

WHAT THE THREE ARMS ASK.

  `--pfmws 7`   The wait state is a gain factor on miss cost (findings ledger,
                section A).  Raising it amplifies whatever eviction misses
                FreeRTOS, the TCP/IP stack and the Ethernet buffers cause in the
                4 KB D-cache -- and, unlike `Config.K0 = 2`, it leaves the cache
                on, so the victim stays fast and the IV-run averaging that the
                remote measurement depends on survives.  This is the most
                promising untried way to make a shipped-SHAPED build leak.

  `--pfmws 2`   The rated value at this part's 200 MHz.  `011` is **reserved** on
                MZ EF and is not three wait states -- it was three on MX (part
                dossier section 1a).  Comparing the reply latency at 2 against
                the shipped 3 says what the reserved encoding actually does,
                which nobody has measured and every deployment of this demo is
                running.

  `--prefen 1`  Instructions only, dropping the CPU-data prefetch line while the
                cache stays on.  The bare-metal sweep found the step that matters
                is `PREFEN` 0 -> 1 -- the instruction line -- with 1 -> 2 barely
                differing; this is that comparison on the network victim.

THE CACHE IS NOT TOUCHED by any of them, which is the point: `Config.K0 = 2`
costs 3.3x on the reply, collapses the IV runs from ~5 to 1-2, and takes sigma
from 217 to 17 300 cycles, i.e. it destroys the instrument that would measure it.

The SYSKEY unlock and the read-back are taken from this project's bare-metal
PIC32MZ rig,
where PRECON's SYSKEY protection is sourced rather than measured -- so the unlock
is done anyway and the value is read back.  Interrupts ARE enabled by this point
(unlike arm D's placement), so the unlock sequence is wrapped in a critical
section; it must be atomic with respect to interrupts.
"""
import argparse
import os
import shutil
import sys

APP = ("C:/devtools/microchip/harmony3/net_apps_pic32mz/apps/"
       "snmpv3_nvm_mpfs/firmware")
MAIN = os.path.join(APP, "src", "main.c")
ORIG = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "..", "..", "..", "main.c.orig")
BACKUP = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                      "arm_e_main.c.stock")

MARK = "flash-timing research: PRECON after SYS_Initialize"

INC = '#include "definitions.h"                // SYS function prototypes\n'
CALL_ANCHOR = "    SYS_Initialize ( NULL );\n"

BLOCK = r'''
/* ---- flash-timing research: PRECON after SYS_Initialize ----------------- *
 *
 * A DELIBERATELY NON-DEFAULT BUILD, and NOT a cache change: `Config.K0` is left
 * at the 3 that XC32's crt0 sets, so the data cache stays on, the victim stays
 * fast, and the ~5-deep IV runs that the remote measurement averages over
 * survive.  Only the flash controller moves.
 *
 * Harmony's SYS_Initialize writes PREFEN = 3 and PFMWS = 3 itself, so this has
 * to run AFTER it returns or it is simply overwritten -- which is what happened
 * to arm D.
 *
 * PFMWS = 3 is a RESERVED encoding on MZ EF (it was three wait states on MX);
 * the rated value at 200 MHz is 2.  research_precon_set refuses nothing here on
 * purpose: writing 3 back is how the control arm is built.
 */
static uint32_t research_precon_set(uint32_t pfmws, uint32_t prefen)
{
    uint32_t v, st;

    if (pfmws > 7u || prefen > 3u)
    {
        return 0xFFFFFFFFu;
    }
    v = (PRECON & ~0x3Fu) | (pfmws & 7u) | ((prefen & 3u) << 4);

    /* Interrupts are live by now, and the SYSKEY sequence must be atomic with
       respect to them -- three writes with an ISR in the middle re-locks it. */
    st = __builtin_disable_interrupts();
    SYSKEY = 0x00000000u;
    SYSKEY = 0xAA996655u;
    SYSKEY = 0x556699AAu;
    PRECON = v;
    SYSKEY = 0x33333333u;
    if ((st & 1u) != 0u)
    {
        (void)__builtin_enable_interrupts();
    }

    return PRECON;
}

'''


def _eol(raw):
    return "\r\n" if b"\r\n" in raw else "\n"


def apply(pfmws, prefen):
    raw = open(MAIN, "rb").read()
    src = raw.decode("utf-8")
    if MARK in src:
        print("already patched -- revert first")
        return
    if not os.path.exists(BACKUP):
        shutil.copy(MAIN, BACKUP)
        print("saved the stock main.c to %s" % os.path.basename(BACKUP))
    eol = _eol(raw)

    def fix(t):
        return t.replace("\r\n", "\n").replace("\n", eol)

    a1 = fix(INC)
    assert src.count(a1) == 1, "include anchor: %d" % src.count(a1)
    src = src.replace(a1, a1 + fix(BLOCK))

    a2 = fix(CALL_ANCHOR)
    assert src.count(a2) == 1, "SYS_Initialize anchor: %d" % src.count(a2)
    call = fix("\n    /* flash-timing research: AFTER SYS_Initialize, which writes\n"
               "       PREFEN = 3 / PFMWS = 3 itself and would otherwise win. */\n"
               "    (void)research_precon_set(%du, %du);\n" % (pfmws, prefen))
    src = src.replace(a2, a2 + call)
    open(MAIN, "wb").write(src.encode("utf-8"))
    print("patched %s: PFMWS=%d PREFEN=%d (%s preserved)"
          % (MAIN, pfmws, prefen, "CRLF" if eol == "\r\n" else "LF"))


def revert():
    if not os.path.exists(BACKUP):
        raise SystemExit("no saved stock main.c at %s" % BACKUP)
    shutil.copy(BACKUP, MAIN)
    print("restored %s" % MAIN)


def status():
    raw = open(MAIN, "rb").read()
    src = raw.decode("utf-8")
    cur = "stock"
    if MARK in src:
        for line in src.splitlines():
            if "research_precon_set(" in line and "void)" in line:
                cur = "PATCHED " + line.strip()
    print("%s: %s, %s, %d bytes"
          % (MAIN, cur, "CRLF" if _eol(raw) == "\r\n" else "LF", len(raw)))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("action", choices=["apply", "revert", "status"])
    ap.add_argument("--pfmws", type=int, default=7)
    ap.add_argument("--prefen", type=int, default=3)
    a = ap.parse_args()
    if a.action == "apply":
        apply(a.pfmws, a.prefen)
    elif a.action == "revert":
        revert()
    else:
        status()
