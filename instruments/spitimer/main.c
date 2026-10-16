/* Bus-side chip-select timer for the SAM D21 SBSFU oracle.
 *
 * NUCLEO-F303RE watching the SAM D21 Xplained Pro's serial-flash chip-select
 * on EXT3 pin 8.  Wiring and the reasoning behind the pin choice are in
 * WIRING.md; the short version is that #CS arrives on PA0, which is
 * TIM2_CH1_ETR on alternate function 1, and TIM2 is this part's 32-bit
 * timer.
 *
 * WHAT IT MEASURES
 * ----------------
 * The interval the attack wants is CS-rise of read N to CS-fall of read
 * N+1: the bootloader has finished reading a chunk and is decrypting it.
 * So every edge is timestamped, rising and falling alike, and the host
 * pairs them up.  Both edges come from ONE pin through ONE capture channel
 * -- CC1P and CC1NP both set is "capture on both edges" -- so there is one
 * DMA stream, one buffer, and no chance of the two channels disagreeing
 * about which edge came first.
 *
 * WHY HARDWARE CAPTURE AND NOT AN INTERRUPT
 * ------------------------------------------
 * An EXTI handler on a Cortex-M4 costs 12 cycles of exception entry plus
 * whatever the prologue adds, and it varies with what the core was doing.
 * That jitter is the same order as the signal being measured.  The timer
 * latches the timestamp in hardware and DMA moves it with the core asleep,
 * so the only uncertainty left is the 15.6 ns tick.
 *
 * RESOLUTION, AND WHY 64 MHz
 * ---------------------------
 * The core runs from HSI/2 x 16 = 64 MHz, giving 15.6 ns per tick and 67 s
 * before the 32-bit counter wraps.  72 MHz would need the HSE that arrives
 * from the ST-LINK on PF0 through a solder bridge; 64 MHz needs nothing but
 * the internal oscillator, and the difference in resolution does not matter
 * here.  The per-collision effect on the SAM D21 is one of its cycles --
 * 20.8 ns at 48 MHz -- so a tick is about three quarters of the smallest
 * thing worth seeing, and averaging over traces recovers the rest.
 *
 * WHY IT BUFFERS INSTEAD OF STREAMING
 * ------------------------------------
 * One verify pass over a 100 KB image at SFU_IMG_CHUNK_SIZE 64 is 1600 data
 * envelopes, and SBSFU polls the flash's status register before every one of
 * them, so the bus carries about 3200 envelopes and 6400 edges per pass.
 * At 4 bytes each that is 25 KB -- it fits in this part's 64 KB of SRAM with
 * room to spare, so the whole pass is captured at full rate and read out
 * afterwards.  Streaming at 115200 would cap the edge rate at about 3000/s
 * and drop edges exactly when the bootloader is busiest.
 *
 * HOST PROTOCOL, over the ST-LINK virtual COM port at 115200 8N1:
 *   'I'  identify        -> "SPITIMER1 <hz> <capacity>\n"
 *   'A'  arm             -> clears the buffer and starts capture, "OK\n"
 *   'S'  status          -> "<count> <overflow>\n"
 *   'D'  dump            -> "D <count>\n" then count little-endian uint32
 *   'Z'  zero the timer  -> "OK\n"
 * Binary on the dump only; everything else is a line of ASCII, so a human
 * can drive it from a terminal.
 */
#include <stdint.h>

#define REG32(a) (*(volatile uint32_t *)(a))
#define REG16(a) (*(volatile uint16_t *)(a))

/* ---------------------------------------------------------- STM32F303RE -- */
#define RCC_BASE     0x40021000UL
#define RCC_CR       REG32(RCC_BASE + 0x00)
#define RCC_CFGR     REG32(RCC_BASE + 0x04)
#define RCC_AHBENR   REG32(RCC_BASE + 0x14)
#define RCC_APB1ENR  REG32(RCC_BASE + 0x1C)

#define FLASH_ACR    REG32(0x40022000UL)

#define GPIOA_BASE   0x48000000UL
#define GPIOA_MODER  REG32(GPIOA_BASE + 0x00)
#define GPIOA_PUPDR  REG32(GPIOA_BASE + 0x0C)
#define GPIOA_AFRL   REG32(GPIOA_BASE + 0x20)

#define TIM2_BASE    0x40000000UL
#define TIM2_CR1     REG32(TIM2_BASE + 0x00)
#define TIM2_DIER    REG32(TIM2_BASE + 0x0C)
#define TIM2_SR      REG32(TIM2_BASE + 0x10)
#define TIM2_CCMR1   REG32(TIM2_BASE + 0x18)
#define TIM2_CCER    REG32(TIM2_BASE + 0x20)
#define TIM2_CNT     REG32(TIM2_BASE + 0x24)
#define TIM2_PSC     REG32(TIM2_BASE + 0x28)
#define TIM2_ARR     REG32(TIM2_BASE + 0x2C)
#define TIM2_CCR1    REG32(TIM2_BASE + 0x34)

#define DMA1_BASE    0x40020000UL
#define DMA1_ISR     REG32(DMA1_BASE + 0x00)
#define DMA1_IFCR    REG32(DMA1_BASE + 0x04)
/* Channels are 1-based in the reference manual; TIM2_CH1 is DMA1 channel 5. */
#define DMA1_C(n, o) REG32(DMA1_BASE + 0x08UL + (0x14UL * ((n) - 1UL)) + (o))
#define DMA1_CCR(n)   DMA1_C(n, 0x00)
#define DMA1_CNDTR(n) DMA1_C(n, 0x04)
#define DMA1_CPAR(n)  DMA1_C(n, 0x08)
#define DMA1_CMAR(n)  DMA1_C(n, 0x0C)
#define CS_DMA_CH    5UL

#define USART2_BASE  0x40004400UL
#define USART2_CR1   REG32(USART2_BASE + 0x00)
#define USART2_BRR   REG32(USART2_BASE + 0x0C)
#define USART2_ISR   REG32(USART2_BASE + 0x1C)
#define USART2_RDR   REG32(USART2_BASE + 0x24)
#define USART2_TDR   REG32(USART2_BASE + 0x28)

#define SYSCLK_HZ    64000000UL
#define BAUD         115200UL

/* 12288 timestamps = 48 KB.  One verify pass at chunk 64 over a 100 KB image
 * is about 6400 edges, so this holds a whole pass with margin; the margin is
 * what absorbs the status-poll envelopes, which are not always two per
 * chunk. */
#define CAP_N        12288U
static volatile uint32_t cap[CAP_N];

static volatile uint32_t g_overflow;

/* ------------------------------------------------------------- clocking -- */

static void clock_init(void)
{
    /* HSI is 8 MHz and is already running out of reset.  PLL source HSI/2,
     * multiplier 16 -> 64 MHz.  Two flash wait states are required above
     * 48 MHz; they are set BEFORE the switch, because the code doing the
     * switching is fetched from that flash. */
    FLASH_ACR = (FLASH_ACR & ~7UL) | 2UL | (1UL << 4);   /* LATENCY=2, PRFTBE */

    RCC_CFGR &= ~(0xFUL << 18);
    RCC_CFGR |= (14UL << 18);            /* PLLMUL = x16                     */
    RCC_CFGR &= ~(1UL << 16);            /* PLLSRC = HSI/2                   */
    RCC_CR |= (1UL << 24);               /* PLLON                            */
    while ((RCC_CR & (1UL << 25)) == 0UL)
    {
    }
    RCC_CFGR = (RCC_CFGR & ~3UL) | 2UL;  /* SW = PLL                         */
    while (((RCC_CFGR >> 2) & 3UL) != 2UL)
    {
    }
}

/* ----------------------------------------------------------------- UART -- */

static void uart_init(void)
{
    RCC_AHBENR |= (1UL << 17);                    /* IOPAEN                  */
    RCC_APB1ENR |= (1UL << 17);                   /* USART2EN                */

    /* PA2 = TX, PA3 = RX, both AF7. */
    GPIOA_MODER = (GPIOA_MODER & ~((3UL << 4) | (3UL << 6)))
                  | (2UL << 4) | (2UL << 6);
    GPIOA_AFRL = (GPIOA_AFRL & ~((0xFUL << 8) | (0xFUL << 12)))
                 | (7UL << 8) | (7UL << 12);

    USART2_BRR = SYSCLK_HZ / BAUD;
    USART2_CR1 = (1UL << 3) | (1UL << 2) | 1UL;   /* TE | RE | UE            */
}

static void uart_tx(uint8_t c)
{
    while ((USART2_ISR & (1UL << 7)) == 0UL)      /* TXE                     */
    {
    }
    USART2_TDR = c;
}

static void uart_str(const char *s)
{
    while (*s != '\0')
    {
        uart_tx((uint8_t)*s++);
    }
}

static void uart_u32(uint32_t v)
{
    char b[11];
    int i = 10;

    b[10] = '\0';
    if (v == 0UL)
    {
        uart_tx('0');
        return;
    }
    while (v != 0UL)
    {
        b[--i] = (char)('0' + (v % 10UL));
        v /= 10UL;
    }
    uart_str(&b[i]);
}

static int uart_rx_ready(void)
{
    return (USART2_ISR & (1UL << 5)) != 0UL;      /* RXNE                    */
}

/* ------------------------------------------------------- capture engine -- */

static void capture_init(void)
{
    RCC_AHBENR |= 1UL;                            /* DMA1EN                  */
    RCC_APB1ENR |= 1UL;                           /* TIM2EN                  */

    /* PA0 = TIM2_CH1, AF1.  No pull: the SAM D21 drives this line and an
     * internal pull would only fight it when it is released. */
    GPIOA_MODER = (GPIOA_MODER & ~3UL) | 2UL;
    GPIOA_PUPDR &= ~3UL;
    GPIOA_AFRL = (GPIOA_AFRL & ~0xFUL) | 1UL;

    TIM2_CR1 = 0UL;
    TIM2_PSC = 0UL;                               /* full 64 MHz resolution  */
    TIM2_ARR = 0xFFFFFFFFUL;

    /* CC1S = 01: IC1 mapped to TI1.  No input filter and no prescaler: a
     * filter would reject exactly the short envelopes a status poll makes,
     * and those have to be counted to pair the data reads correctly. */
    TIM2_CCMR1 = 1UL;
    /* CC1E | CC1P | CC1NP -- both edges.  This is the one non-obvious bit
     * pattern here: CC1P alone is falling, CC1P+CC1NP is both. */
    TIM2_CCER = (1UL << 0) | (1UL << 1) | (1UL << 3);
    TIM2_DIER = (1UL << 9);                       /* CC1DE: DMA on capture   */
    TIM2_CNT = 0UL;
    TIM2_CR1 = 1UL;                               /* CEN                     */
}

static void capture_arm(void)
{
    /* TURN THE REQUEST OFF FIRST.  Clearing CC1IF is not enough on its own:
     * the request reaching the DMA controller survives the channel being
     * disabled, so the first arm after a stretch of uncaptured traffic
     * services it and lands one stale timestamp in cap[0].  Dropping
     * CC1DE deasserts the request line itself. */
    TIM2_DIER &= ~(1UL << 9);
    TIM2_CCER &= ~1UL;                            /* CC1E off                */

    DMA1_CCR(CS_DMA_CH) = 0UL;
    DMA1_CPAR(CS_DMA_CH) = (uint32_t)&TIM2_CCR1;
    DMA1_CMAR(CS_DMA_CH) = (uint32_t)&cap[0];
    DMA1_CNDTR(CS_DMA_CH) = CAP_N;
    DMA1_IFCR = 0xFUL << (4UL * (CS_DMA_CH - 1UL));

    /* STOP THE CAPTURE CHANNEL BEFORE TOUCHING ANYTHING, and clear the
     * pending request while it is stopped.
     *
     * CC1IF latches on every edge whether or not anything is armed, and
     * CCR1 keeps the last timestamp.  CC1DE turns that flag into a DMA
     * request as a LEVEL, so enabling the DMA channel while the flag is
     * set makes the channel fire at once and write a stale timestamp --
     * from the previous epoch, before TIM2_CNT was rezeroed -- into
     * cap[0].  Everything after it is then one slot out, which no
     * histogram of envelope widths reveals and which silently attributes
     * every trace to the wrong block.
     *
     * That is exactly what happened: arming right after a YMODEM upload
     * reported one edge at tick 606872394 -- about 9.5 s into the OLD
     * count, i.e. the last chip select of the upload.  It was reproducible
     * and self-clearing: the FIRST arm after uncaptured traffic showed the
     * stale edge and every arm after it was clean, which is what a single
     * latched request looks like.
     */
    (void)TIM2_CCR1;                              /* clears CC1IF            */
    TIM2_SR = 0UL;                                /* and CC1OF               */
    TIM2_CNT = 0UL;

    /* MSIZE=32, PSIZE=32, MINC, no CIRC: the buffer holds a whole pass, and
     * wrapping would silently overwrite the start of it.  Running out is
     * reported instead. */
    DMA1_CCR(CS_DMA_CH) = (2UL << 10) | (2UL << 8) | (1UL << 7) | 1UL;
    g_overflow = 0UL;

    /* Capture first, then the request: enabling CC1DE last means the DMA
     * can only ever see a request generated after the channel was armed. */
    TIM2_CCER |= 1UL;                             /* CC1E back on            */
    TIM2_DIER |= (1UL << 9);                      /* CC1DE back on           */
}

static uint32_t capture_count(void)
{
    return CAP_N - DMA1_CNDTR(CS_DMA_CH);
}

/* ------------------------------------------------------------------ main -- */

int main(void)
{
    clock_init();
    uart_init();
    capture_init();
    capture_arm();

    uart_str("\r\nSPITIMER1 ");
    uart_u32(SYSCLK_HZ);
    uart_tx(' ');
    uart_u32(CAP_N);
    uart_str("\r\n");

    for (;;)
    {
        uint8_t c;
        uint32_t n;
        uint32_t i;

        if (!uart_rx_ready())
        {
            /* Overrun is latched rather than polled for by the host: once
             * the buffer is full the DMA stops and later edges are lost, and
             * a capture that silently lost its tail is worse than one that
             * says so. */
            if (DMA1_CNDTR(CS_DMA_CH) == 0UL)
            {
                g_overflow = 1UL;
            }
            continue;
        }
        c = (uint8_t)USART2_RDR;

        switch (c)
        {
            case 'I':
                uart_str("SPITIMER1 ");
                uart_u32(SYSCLK_HZ);
                uart_tx(' ');
                uart_u32(CAP_N);
                uart_str("\r\n");
                break;

            case 'A':
                capture_arm();
                uart_str("OK\r\n");
                break;

            case 'S':
                n = capture_count();
                uart_u32(n);
                uart_tx(' ');
                uart_u32(g_overflow);
                uart_str("\r\n");
                break;

            case 'Z':
                TIM2_CNT = 0UL;
                uart_str("OK\r\n");
                break;

            case 'D':
                n = capture_count();
                uart_str("D ");
                uart_u32(n);
                uart_str("\r\n");
                for (i = 0U; i < n; i++)
                {
                    uint32_t v = cap[i];

                    uart_tx((uint8_t)(v & 0xFFU));
                    uart_tx((uint8_t)((v >> 8) & 0xFFU));
                    uart_tx((uint8_t)((v >> 16) & 0xFFU));
                    uart_tx((uint8_t)((v >> 24) & 0xFFU));
                }
                break;

            default:
                break;
        }
    }
}
