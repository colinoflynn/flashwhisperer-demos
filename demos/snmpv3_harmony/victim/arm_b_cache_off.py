"""Patch the Harmony SNMPv3 demo's main.c into the cache-off arm.

The k0_write/k0_set body is lifted from this project's bare-metal PIC32MZ rig, which is
where the two failure modes were found on this silicon: the write must not be
executed from a cached address (call it through its KSEG1 alias), and the
write-back/invalidate must be INLINE in the same leaf function as the mtc0 or
the part goes silent with no diagnostic.

Microchip ships main.c with CRLF endings and MPLAB writes it back that way, so
the patch preserves whatever the file already uses -- rewriting it LF would turn
a two-hunk change into a whole-file diff against the vendor checkout.

Usage:  python cacheoff_patch.py apply|revert|status
"""
import os
import shutil
import sys

APP = ("C:/devtools/microchip/harmony3/net_apps_pic32mz/apps/"
       "snmpv3_nvm_mpfs/firmware")
MAIN = os.path.join(APP, "src", "main.c")
ORIG = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    "stock_build", "main.c.orig")

MARK = "flash-timing research: the cache-off arm"

INC = '#include "definitions.h"                // SYS function prototypes\n'
MAINSIG = "int main ( void )\n{\n"

BLOCK = r'''
/* ---- flash-timing research: the cache-off arm --------------------------- *
 *
 * THIS IS A DELIBERATELY NON-DEFAULT BUILD.  The stock demo runs with
 * Config.K0 = 3 (write-back, write-allocate, KSEG0 cached), set by XC32's
 * __pic32_init_cache out of crt0 before main.  This build sets K0 = 2,
 * UNCACHED, as the control arm for a flash-timing measurement: it is the
 * configuration in which this silicon's byte S-box stops being bit-exactly
 * constant.
 *
 * On this part "turn the data cache off" is a CP0 field rather than a
 * peripheral bit -- Config.K0<2:0> is the KSEG0 coherency algorithm, so
 * cacheability and write policy are one axis:
 *
 *   0  write-through, no write-allocate
 *   1  write-through, write-allocate
 *   2  UNCACHED                        <- this build
 *   3  write-back, write-allocate      <- the reset value, what the demo ships
 *
 * Two things make this more than an mtc0, both found the hard way on the
 * bare-metal rig for this part, from which this is lifted:
 *
 *  1. The write cannot execute from a cached address -- changing the
 *     cacheability of the memory you are fetching from while you fetch from it
 *     is undefined.  KSEG1 is an uncached alias at `address | 0x20000000`, so
 *     k0_set calls k0_write through its own alias.
 *  2. The write-back/invalidate must be INLINE in the same leaf function as
 *     the mtc0.  Flush, call a helper, flush again HANGS THE PART: turning
 *     KSEG0 uncached does not empty the D-cache, so any dirty line written
 *     after the last flush is stranded -- the stack most fatally, because the
 *     call that performs the switch dirties it on the way in and then returns
 *     through data the CPU can no longer see.  No diagnostic; it goes silent.
 */
#define RESEARCH_KSEG1(p)       ((uint32_t)(p) | 0x20000000u)
#define RESEARCH_DCACHE_BYTES   4096u    /* 4 KB, 4-way, 16-byte lines        */
#define RESEARCH_DCACHE_LINE      16u

static void __attribute__((noinline)) research_k0_write(uint32_t k0)
{
    uint32_t c = (uint32_t)_CP0_GET_CONFIG();
    uint32_t a;

    c = (c & ~7u) | (k0 & 7u);

    /* `cache 0x01` is Index_Writeback_Invalidate on the D-cache, indexed by
       address, so sweeping the array size covers every way of every set. */
    for (a = 0x80000000u;
         a < (0x80000000u + RESEARCH_DCACHE_BYTES);
         a += RESEARCH_DCACHE_LINE)
    {
        __asm__ __volatile__("cache 0x01, 0(%0)" : : "r"(a) : "memory");
    }
    __asm__ __volatile__("sync" : : : "memory");

    /* cp0defs.h offers a getter and no setter, because Config is read-only
       apart from K0.  So the write is the raw instruction. */
    __asm__ __volatile__("mtc0 %0, $16, 0" : : "r"(c));
    __asm__ __volatile__("ehb" : : : "memory");     /* clear the CP0 hazard   */

    for (a = 0x80000000u;
         a < (0x80000000u + RESEARCH_DCACHE_BYTES);
         a += RESEARCH_DCACHE_LINE)
    {
        __asm__ __volatile__("cache 0x01, 0(%0)" : : "r"(a) : "memory");
    }
    __asm__ __volatile__("sync" : : : "memory");
}

static uint32_t research_k0_set(uint32_t k0)
{
    void (*uncached)(uint32_t) =
        (void (*)(uint32_t))RESEARCH_KSEG1(research_k0_write);

    if (k0 > 7u)
    {
        return 0xFFFFFFFFu;
    }
    uncached(k0);
    return (uint32_t)_CP0_GET_CONFIG() & 7u;
}

'''

CALL = r'''    /* flash-timing research, the cache-off arm: K0 = 2 (UNCACHED).  Done
       FIRST, before SYS_Initialize, so the whole application -- FreeRTOS, the
       TCP/IP stack, the Ethernet driver's buffers and wolfCrypt's AES tables
       -- runs with KSEG0 uncached, which is what makes this a control for the
       stock build rather than a partial one.  Expect roughly 8x runtime. */
    (void)research_k0_set(2u);

'''


def _eol(raw):
    return "\r\n" if b"\r\n" in raw else "\n"


def apply():
    raw = open(MAIN, "rb").read()
    src = raw.decode("utf-8")
    if MARK in src:
        print("already patched")
        return
    eol = _eol(raw)

    def fix(t):
        return t.replace("\r\n", "\n").replace("\n", eol)

    a1 = fix(INC)
    assert src.count(a1) == 1, "include anchor: %d" % src.count(a1)
    src = src.replace(a1, a1 + fix(BLOCK))
    a2 = fix(MAINSIG)
    assert src.count(a2) == 1, "main anchor: %d" % src.count(a2)
    src = src.replace(a2, a2 + fix(CALL))
    open(MAIN, "wb").write(src.encode("utf-8"))
    print("patched %s (%s preserved)" % (MAIN, "CRLF" if eol == "\r\n" else "LF"))


def revert():
    shutil.copy(ORIG, MAIN)
    print("restored %s from the saved stock copy" % MAIN)


def status():
    raw = open(MAIN, "rb").read()
    print("%s: %s, %s endings, %d bytes"
          % (MAIN, "PATCHED (cache off)" if MARK in raw.decode("utf-8")
             else "stock", "CRLF" if _eol(raw) == "\r\n" else "LF", len(raw)))


if __name__ == "__main__":
    {"apply": apply, "revert": revert, "status": status}[sys.argv[1]]()
