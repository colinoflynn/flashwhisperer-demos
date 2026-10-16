"""Arm F: time the victim's OWN AES call, in situ, and dump it over the console.

    python arm_f_aes_probe.py apply           # instrument
    python arm_f_aes_probe.py revert

WHAT THIS ANSWERS.  Every null in RESULTS.md is measured at the wire, where the
AES is ~3 % of a 1.75 ms reply and sigma is ~195 victim cycles.  That cannot
distinguish "the cipher does not leak" from "the cipher leaks and the observation
path buries it".  This arm puts the clock **around the AES call itself** --
`wc_AesCfbEncrypt` in `SNMPv3AESEncryptResponseScopedPdu`, the exact call whose
output the attack consumes -- with no TCP/IP stack, no Ethernet driver and no
scheduler inside the measured interval.

Two things then become measurable that are not measurable at the wire:

  * **sigma of the cipher alone**, which is the numerator of every SNR argument
    in RESULTS.md and has so far been assumed rather than measured; and
  * whether the recovery works **at the call** in a configuration where it fails
    at the wire, which localises the loss to the observation path rather than to
    the cipher.

WHY THE CONSOLE AND NOT THE DIAGNOSTIC UDP PORT.  `fw_attacker` already speaks a
ring-fetch protocol on UDP 5684 and its trace records carry a spare 4-byte slot
for the victim's own count -- but `trace_batch()` writes that value to `r[24]`,
which with `WINDOW = 32` is **inside the ciphertext window** rather than at
`r[g_win_len + 8]`.  It has been harmless only because no victim on this bench
has ever answered the diagnostic, so `g_diag_ok` stayed 0; the moment one does,
every captured ciphertext gets four bytes corrupted.  Fixing that means
rebuilding and reflashing the attacker mid-campaign, so this arm takes the
console route instead and leaves the wire path untouched.  The bug is recorded
in RESULTS.md.

HOW THE JOIN IS CHECKED RATHER THAN ASSUMED.  The ring stores, per response, the
cycle count AND the first ciphertext byte of the AES output.  The host already
has that byte from the wire, so the two streams are matched on content, not on
position.  A dump also reports the head index, so a batch that lost a response
shows up as a head delta that disagrees with the trace count.

The counter is CP0 Count, which on PIC32MZ increments once per two core clocks:
at 200 MHz that is one tick per 10 ns, and every figure this arm produces is in
TICKS, i.e. 2 core cycles each.  Quoting it as "cycles" without that factor is
the obvious way to be wrong by 2x.
"""
import argparse
import os
import shutil

CFG = ("C:/devtools/microchip/harmony3/net_apps_pic32mz/apps/snmpv3_nvm_mpfs/"
       "firmware/src")
APP = os.path.join(CFG, "app.c")
USM = os.path.join(CFG, "config", "pic32mz_ef_sk_freertos", "library", "tcpip",
                   "src", "snmpv3_usm.c")
HERE = os.path.dirname(os.path.abspath(__file__))
BK_APP = os.path.join(HERE, "arm_f_app.c.stock")
BK_USM = os.path.join(HERE, "arm_f_snmpv3_usm.c.stock")

MARK = "RESEARCH_AES_PROBE"

APP_ANCHOR = "void APP_Initialize ( void )\n{\n"

APP_BLOCK = r'''
/* ---- RESEARCH_AES_PROBE: time the victim's own AES call ------------------ *
 *
 * A ring of (cycles, first output byte) per SNMP response, filled in
 * snmpv3_usm.c around wc_AesCfbEncrypt and drained by the `aesdump` console
 * command.  The output byte is stored so the host can match this stream to the
 * one it captured off the wire by CONTENT rather than by position.
 *
 * CP0 Count ticks once per two core clocks: at 200 MHz, 10 ns per tick.  Every
 * number this produces is in ticks, not core cycles.
 */
#define RESEARCH_RING_N   4096u          /* power of two */
volatile uint32_t research_cyc[RESEARCH_RING_N];
volatile uint8_t  research_ct0[RESEARCH_RING_N];
volatile uint32_t research_head = 0u;

/* SYS_CONSOLE's print is ASYNCHRONOUS: it queues into a ring that SYS_Tasks
   drains, and this command RUNS INSIDE SYS_Tasks, so the ring never drains
   while the loop runs.  A 3 500-line dump came back as 192 lines -- silently
   truncated at the buffer size, which looks exactly like a short ring rather
   than a lost console.  So the dump writes UART2 directly and blocks on the
   hardware FIFO.  That is safe here precisely because it is slow and
   synchronous: it runs between capture batches, never inside a measured
   interval. */
static void research_putc(char c)
{
    while (U2STAbits.UTXBF) { /* FIFO full -- spin */ }
    U2TXREG = (uint32_t)(uint8_t)c;
}

static void research_putu(uint32_t v)
{
    char b[12];
    int i = 0;
    if (v == 0u) { research_putc('0'); return; }
    while (v && i < 11) { b[i++] = (char)('0' + (v % 10u)); v /= 10u; }
    while (i) { research_putc(b[--i]); }
}

static void research_puts(const char* s)
{
    while (*s) { research_putc(*s++); }
}

static int research_cmd_dump(SYS_CMD_DEVICE_NODE* pCmdIO, int argc, char** argv)
{
    uint32_t n = RESEARCH_RING_N, i, head = research_head;
    (void)pCmdIO;

    if (argc > 1)
    {
        n = (uint32_t)atoi(argv[1]);
        if (n > RESEARCH_RING_N) { n = RESEARCH_RING_N; }
    }
    if (n > head) { n = head; }

    research_puts("\r\nAESDUMP head=");
    research_putu(head);
    research_puts(" n=");
    research_putu(n);
    research_puts("\r\n");
    for (i = 0; i < n; i++)
    {
        uint32_t k = (head - n + i) & (RESEARCH_RING_N - 1u);
        research_putu(research_cyc[k]);
        research_putc(' ');
        research_putu((uint32_t)research_ct0[k]);
        research_puts("\r\n");
    }
    research_puts("AESEND\r\n");
    return 0;
}

static const SYS_CMD_DESCRIPTOR research_cmd_tbl[] =
{
    {"aesdump", research_cmd_dump, ": dump the AES timing ring"},
};

'''

APP_CALL = r'''    /* RESEARCH_AES_PROBE */
    (void)SYS_CMD_ADDGRP(research_cmd_tbl,
                         sizeof(research_cmd_tbl) / sizeof(*research_cmd_tbl),
                         "aes", ": AES timing probe");

'''

USM_ANCHOR = """    ret = wc_AesCfbEncrypt(&dec, encrypted_text, plainText, plaintextLen);
"""

USM_BLOCK = r'''    /* ---- RESEARCH_AES_PROBE ---------------------------------------------
     * The clock goes around the AES call and nothing else: no stack, no driver,
     * no scheduler inside the interval.
     *
     * INTERRUPTS ARE MASKED for the duration, and that is the whole point of
     * this version.  Leaving them on measured 1 212 victim cycles of run-to-run
     * variation on a 38 140-cycle call -- ~100x any plausible flash-line effect
     * -- because an ISR landing inside the window lands in the measurement.  It
     * also made the probe useless for the question being asked: that noise does
     * NOT reach the wire (an interrupt inside the AES window would have run
     * somewhere in the reply path anyway), so the AES-to-wire regression slope
     * came out at 0.01 and told us nothing about the cipher.
     *
     * The cost is ~190 us of masked interrupts per response.  The Ethernet MAC
     * is DMA-descriptor driven and tolerates it; a dropped frame would show up
     * as a capture timeout, which the host records per batch.
     */
    {
        extern volatile uint32_t research_cyc[];
        extern volatile uint8_t  research_ct0[];
        extern volatile uint32_t research_head;
        uint32_t st = __builtin_disable_interrupts();
        uint32_t t0 = _CP0_GET_COUNT();
        ret = wc_AesCfbEncrypt(&dec, encrypted_text, plainText, plaintextLen);
        {
            uint32_t dt = _CP0_GET_COUNT() - t0;
            uint32_t k = research_head & 4095u;
            research_cyc[k] = dt;
            research_ct0[k] = encrypted_text[0];
            research_head = research_head + 1u;
        }
        if ((st & 1u) != 0u) { (void)__builtin_enable_interrupts(); }
    }
'''


def _eol(raw):
    return "\r\n" if b"\r\n" in raw else "\n"


def _fix(t, eol):
    return t.replace("\r\n", "\n").replace("\n", eol)


def apply():
    for src, bk in ((APP, BK_APP), (USM, BK_USM)):
        if not os.path.exists(bk):
            shutil.copy(src, bk)
            print("saved %s" % os.path.basename(bk))

    raw = open(APP, "rb").read()
    s = raw.decode("utf-8")
    if MARK in s:
        print("app.c already patched")
    else:
        eol = _eol(raw)
        a = _fix(APP_ANCHOR, eol)
        assert s.count(a) == 1, "APP_Initialize anchor: %d" % s.count(a)
        s = s.replace(a, _fix(APP_BLOCK, eol) + a + _fix(APP_CALL, eol))
        open(APP, "wb").write(s.encode("utf-8"))
        print("patched app.c")

    raw = open(USM, "rb").read()
    s = raw.decode("utf-8")
    if MARK in s:
        print("snmpv3_usm.c already patched")
    else:
        eol = _eol(raw)
        a = _fix(USM_ANCHOR, eol)
        assert s.count(a) == 1, "wc_AesCfbEncrypt anchor: %d" % s.count(a)
        s = s.replace(a, _fix(USM_BLOCK, eol))
        open(USM, "wb").write(s.encode("utf-8"))
        print("patched snmpv3_usm.c")


def revert():
    for src, bk in ((APP, BK_APP), (USM, BK_USM)):
        if os.path.exists(bk):
            shutil.copy(bk, src)
            print("restored %s" % os.path.basename(src))


def status():
    for src in (APP, USM):
        s = open(src, "rb").read().decode("utf-8")
        print("%-18s %s" % (os.path.basename(src),
                            "PATCHED" if MARK in s else "stock"))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("action", choices=["apply", "revert", "status"])
    a = ap.parse_args()
    {"apply": apply, "revert": revert, "status": status}[a.action]()
