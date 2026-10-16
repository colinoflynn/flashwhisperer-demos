/**
  ******************************************************************************
  * @file    samd21_hal.c
  * @brief   SAM D21 implementation of the small HAL surface SBSFU needs.
  *          See samd21_hal.h for why the surface is this small.
  ******************************************************************************
  */
#include "samd21_hal.h"

#include "samd21.h"

/* SERCOM3 = EDBG virtual COM port, user guide Table 4-10. */
#define UART_PORTA        0U
#define UART_TX_PIN       22U            /* PA22, SERCOM3 PAD[0], mux C      */
#define UART_RX_PIN       23U            /* PA23, SERCOM3 PAD[1], mux C      */
#define UART_MUX_C        2U
#define UART_TXPO         0U             /* TxD on PAD[0]                    */
#define UART_RXPO         1U             /* RxD on PAD[1]                    */

/* Factory DFLL48M coarse calibration, NVM software calibration area word 1,
 * bits 31:26.  0x3F means unprogrammed, in which case mid-range is used. */
#define NVM_CAL_WORD1     (*(volatile uint32_t *)0x00806024UL)

/* CMSIS declares this in system_samd21.h and Microchip defines it in
 * system_samd21.c, which is NOT vendored: that file's SystemInit() does its
 * own clock bring-up, and having two things configure the clock tree is how a
 * board ends up running at a rate nothing in the source says it runs at.
 * HAL_ClockInit() is this port's single owner of the clock, so it owns the
 * variable too. */
uint32_t SystemCoreClock = 1000000UL;      /* OSC8M / 8, the reset state */

static volatile uint32_t tick_ms;
static volatile uint8_t  tick_suspended;

/* ------------------------------------------------------------------ tick -- */

void SysTick_Handler(void)
{
  tick_ms++;
}

uint32_t HAL_GetTick(void)
{
  return tick_ms;
}

void HAL_Delay(uint32_t Delay)
{
  uint32_t start = tick_ms;

  if (tick_suspended != 0U)
  {
    /* ST calls HAL_Delay on error paths that run after HAL_SuspendTick, so a
     * tick-based delay there would spin forever.  Fall back to a calibrated
     * busy loop rather than hang: this is an LED-blink and settle delay, and
     * being 20 % out matters to nobody, whereas hanging in an error handler
     * hides the error. */
    volatile uint32_t n = Delay * (SAMD21_CPU_HZ / 8000UL);
    while (n-- != 0U)
    {
    }
    return;
  }
  while ((tick_ms - start) < Delay)
  {
  }
}

/* se_callgate.c hands the Secure Engine the core clock so that ST's
 * se_utils.c can run its own SysTick-free tick.  This port does not build
 * se_utils.c -- there is no isolation, so the SE shares this file's tick --
 * but se_callgate.c still calls this, so it lives here, with the clock it
 * describes.  See the SE_SRC note in the Makefile. */
void SE_SetSystemCoreClock(uint32_t uSystemCoreClock)
{
  SystemCoreClock = uSystemCoreClock;
}

void HAL_SuspendTick(void)
{
  SysTick->CTRL &= ~SysTick_CTRL_TICKINT_Msk;
  tick_suspended = 1U;
}

void HAL_ResumeTick(void)
{
  tick_suspended = 0U;
  SysTick->CTRL |= SysTick_CTRL_TICKINT_Msk;
}

/* ------------------------------------------------------------------- MPU -- */

/* The MPU registers are addressed literally rather than through CMSIS's `MPU`
 * pointer, because core_cm0plus.h only declares that pointer when
 * __MPU_PRESENT is 1 and Microchip's samd21j18a.h:223 sets it to 0.  That
 * header line is the vendor's claim; the read below is the check. */
#define MPU_TYPE_ADDR   (*(volatile uint32_t *)0xE000ED90UL)
#define MPU_CTRL_ADDR   (*(volatile uint32_t *)0xE000ED94UL)
#define MPU_TYPE_DREGION_MASK  (0x0000FF00UL)

void HAL_MPU_Disable(void)
{
  /* MPU_TYPE.DREGION == 0 means no MPU is fitted.  This is checked rather
   * than asserted in a comment because "the SAM D21 has no MPU" is a claim
   * about silicon, and this project has been wrong about exactly that class
   * of claim before -- the nRF52840's undocumented read latch, the H723's
   * cache size.  If a part ever turns up with one fitted, the regions get
   * disabled properly instead of being silently left enabled across the jump
   * into the user application. */
  if ((MPU_TYPE_ADDR & MPU_TYPE_DREGION_MASK) != 0U)
  {
    __DMB();
    MPU_CTRL_ADDR = 0U;
    __DSB();
    __ISB();
  }
}

/* ----------------------------------------------------------------- clock -- */

static void gclk_sync(void)
{
  while ((GCLK->STATUS.reg & GCLK_STATUS_SYNCBUSY) != 0U)
  {
  }
}

/* Start DFLL48M in OPEN LOOP at the factory coarse calibration.
 *
 * ORDER IS FROM THE ERRATA, NOT FROM TASTE, and this sequence is carried over
 * verbatim in spirit from rigs/fw_samd21_aes/main.c, where it was established
 * on this exact die.  DFLLCTRL comes out of reset with ONDEMAND set (SVD reset
 * value 0x0080), and writing DFLLVAL while ONDEMAND is set can hang on a part
 * that has not been requested.  So: clear DFLLCTRL, wait DFLLRDY, write
 * DFLLVAL, then set ENABLE.
 *
 * Open loop rather than closed: closed loop needs a reference routed to
 * GCLK_DFLL48M and a multiplier, and a few per cent of DCO error changes
 * nothing here.  It does mean the SPI bus rate is 8 MHz nominal rather than
 * exact -- which is why the attack times DIFFERENCES between chip-select
 * edges in the same trace, where a common clock error cancels.
 */
static void dfll_start(void)
{
  uint32_t coarse;

  SYSCTRL->DFLLCTRL.reg = 0U;
  __DSB();
  while ((SYSCTRL->PCLKSR.reg & SYSCTRL_PCLKSR_DFLLRDY) == 0U)
  {
  }

  coarse = (NVM_CAL_WORD1 >> 26) & 0x3FU;
  if (coarse == 0x3FU)
  {
    coarse = 0x1FU;                      /* unprogrammed -> mid range        */
  }
  SYSCTRL->DFLLVAL.reg = (coarse << 10) | 512U;      /* FINE mid-scale       */
  __DSB();
  SYSCTRL->DFLLCTRL.reg = SYSCTRL_DFLLCTRL_ENABLE;   /* MODE = 0: open loop  */
  __DSB();
  while ((SYSCTRL->PCLKSR.reg & SYSCTRL_PCLKSR_DFLLRDY) == 0U)
  {
  }
  __ISB();
}

void HAL_ClockInit(void)
{
  /* 1. Wait states FIRST, and generously.  Too few wait states for the clock
   *    about to be selected corrupts instruction fetch -- and the code doing
   *    the fetching is itself in flash, so the failure is a hardfault in the
   *    middle of this function rather than a wrong answer later.  RWS = 3 is
   *    safe at every clock this part supports. */
  HAL_FlashReadPathConfig(3U, SAMD21_READMODE_NO_MISS_PENALTY, 0U);

  /* 2. Park generator 0 on OSC8M at full speed before touching the DFLL.
   *
   *    THIS STEP COST THREE WEDGED BOARDS ON THIS BENCH and is documented at
   *    length in rigs/fw_samd21_aes/main.c.  dfll_start() begins by CLEARING
   *    DFLLCTRL, which disables the DFLL; doing that while generator 0 is
   *    already sourced from it stops the CPU clock dead, after which the part
   *    answers SWD with WAIT ACK forever and reads exactly like a dead board.
   *    (`python -m pyocd reset -m hw` recovers it; nothing in flash is
   *    harmed.)  A bootloader only ever makes this transition once, from the
   *    reset state where generator 0 is already on OSC8M, so it would survive
   *    without the park -- it is here anyway because the cost is four register
   *    writes and the failure mode is indistinguishable from dead hardware. */
  PM->CPUSEL.reg = PM_CPUSEL_CPUDIV_DIV1;
  SYSCTRL->OSC8M.reg = (SYSCTRL->OSC8M.reg & ~SYSCTRL_OSC8M_PRESC_Msk)
                       | SYSCTRL_OSC8M_PRESC(0)
                       | SYSCTRL_OSC8M_ENABLE;
  __DSB();
  while ((SYSCTRL->PCLKSR.reg & SYSCTRL_PCLKSR_OSC8MRDY) == 0U)
  {
  }
  GCLK->GENDIV.reg = GCLK_GENDIV_ID(0);
  gclk_sync();
  GCLK->GENCTRL.reg = GCLK_GENCTRL_ID(0) | GCLK_GENCTRL_SRC_OSC8M
                      | GCLK_GENCTRL_GENEN;
  gclk_sync();

  /* 3. and only now the DFLL, with nothing running off it */
  dfll_start();
  GCLK->GENCTRL.reg = GCLK_GENCTRL_ID(0) | GCLK_GENCTRL_SRC_DFLL48M
                      | GCLK_GENCTRL_GENEN;
  gclk_sync();
  PM->CPUSEL.reg = PM_CPUSEL_CPUDIV_DIV1;            /* 48 MHz               */
  __DSB();
  __ISB();

  /* 4. The read path the demo actually runs in.  RWS = 1 is REQUIRED above
   *    24 MHz at 3.3 V (datasheet table 37-42) -- and it is also the value
   *    research/targets/samd21j18a.md measured the channel at, so the shipped
   *    configuration and the vulnerable one are the same configuration.  That
   *    is the finding, not a convenience. */
  HAL_FlashReadPathConfig(SBSFU_NVM_RWS, SBSFU_NVM_READMODE, SBSFU_NVM_CACHEDIS);

  SystemCoreClock = SAMD21_CPU_HZ;
}

void HAL_Init(void)
{
  tick_ms = 0U;
  tick_suspended = 0U;
  SysTick_Config(SAMD21_CPU_HZ / 1000UL);            /* 1 ms                 */
}

/* ------------------------------------------------------- flash read path -- */

void HAL_FlashReadPathConfig(uint32_t rws, uint32_t readmode, uint32_t cachedis)
{
  uint32_t v = NVMCTRL->CTRLB.reg;

  v &= ~(NVMCTRL_CTRLB_RWS_Msk | NVMCTRL_CTRLB_READMODE_Msk
         | NVMCTRL_CTRLB_CACHEDIS);
  v |= NVMCTRL_CTRLB_RWS(rws) | NVMCTRL_CTRLB_READMODE(readmode);
  if (cachedis != 0U)
  {
    v |= NVMCTRL_CTRLB_CACHEDIS;
  }
  NVMCTRL->CTRLB.reg = v;
  __DSB();
  __ISB();

  /* Lines filled under the previous configuration are still valid tags.
   * Leaving them is how a runtime reconfiguration comes to behave differently
   * from the same configuration set at boot -- a confound
   * MEASURING_CHANNELS.md names and one this project has already been bitten
   * by on the STM32F4 (see fw_f401_ct's flash_acr_set). */
  HAL_FlashCacheInvalidate();
}

void HAL_FlashCacheInvalidate(void)
{
  NVMCTRL->CTRLA.reg = (uint16_t)(NVMCTRL_CTRLA_CMDEX_KEY
                                  | NVMCTRL_CTRLA_CMD_INVALL);
  while (NVMCTRL->INTFLAG.bit.READY == 0U)
  {
  }
}

/* ------------------------------------------------------------------ UART -- */

/* INTERRUPT-BUFFERED RECEIVE, AND IT IS NOT AN OPTIMISATION.
 *
 * The first version polled the SERCOM's receive register directly.  That is
 * what ST's STM32 HAL_UART_Receive does too, and it works there because the
 * peripheral has enough buffering and the port is not doing anything else.
 * Here it failed in a specific and instructive way: SBSFU's YMODEM receiver
 * (sfu_com_loader.c ReceivePacket) reads ONE byte to identify the packet
 * type, then issues a second call for the remaining 1028 -- and between
 * retries it PRINTS a 'C' through the same UART.  A 1 KB packet arriving
 * while the receiver is between calls loses its leading bytes, the start
 * byte is then not STX, and the packet is rejected.  Five retries later the
 * loader aborts with CA.  From the host it looks like a dead link.
 *
 * A two-byte hardware buffer cannot cover that gap; a ring buffer filled by
 * the RXC interrupt can, and is what any real bootloader UART does.  1 KB is
 * comfortably more than one YMODEM packet plus the overhead, so a whole
 * packet can land while the receiver is busy.
 *
 * The buffer size MUST be a power of two: the index arithmetic masks rather
 * than divides, so that the ISR stays short.
 */
#define RX_BUF_SIZE   1024U
static volatile uint8_t  rx_buf[RX_BUF_SIZE];
static volatile uint16_t rx_head;
static volatile uint16_t rx_tail;

void SERCOM3_Handler(void)
{
  while ((SERCOM3->USART.INTFLAG.reg & SERCOM_USART_INTFLAG_RXC) != 0U)
  {
    uint8_t c = (uint8_t)SERCOM3->USART.DATA.reg;
    uint16_t nh = (uint16_t)((rx_head + 1U) & (RX_BUF_SIZE - 1U));

    /* On overflow the OLDEST byte is dropped by not advancing -- i.e. the
     * new byte is discarded.  Either choice loses data; discarding the new
     * one keeps the buffer's contents contiguous, so a packet already in
     * flight still parses and YMODEM's CRC catches the truncation. */
    if (nh != rx_tail)
    {
      rx_buf[rx_head] = c;
      rx_head = nh;
    }
  }
  /* Error flags are cleared here rather than reported.  A framing or
   * overflow error corrupts a byte; YMODEM's CRC is what decides whether a
   * packet survived, and aborting the whole read on the first bad byte --
   * which the polled version did -- turns a recoverable glitch into a
   * failed transfer. */
  SERCOM3->USART.STATUS.reg = SERCOM_USART_STATUS_BUFOVF
                              | SERCOM_USART_STATUS_FERR
                              | SERCOM_USART_STATUS_PERR;
}

void HAL_UART_Init(uint32_t baud)
{
  PortGroup *pa = &PORT->Group[UART_PORTA];
  uint64_t br;

  pa->PINCFG[UART_TX_PIN].reg = PORT_PINCFG_PMUXEN;
  pa->PMUX[UART_TX_PIN / 2].bit.PMUXE = UART_MUX_C;  /* PA22 even            */
  pa->PINCFG[UART_RX_PIN].reg = PORT_PINCFG_PMUXEN | PORT_PINCFG_INEN;
  pa->PMUX[UART_RX_PIN / 2].bit.PMUXO = UART_MUX_C;  /* PA23 odd             */

  PM->APBCMASK.reg |= PM_APBCMASK_SERCOM3;
  GCLK->CLKCTRL.reg = (uint16_t)(GCLK_CLKCTRL_ID_SERCOM3_CORE
                                 | GCLK_CLKCTRL_GEN(SPIF_GCLK_GEN)
                                 | GCLK_CLKCTRL_CLKEN);
  gclk_sync();

  SERCOM3->USART.CTRLA.reg = SERCOM_USART_CTRLA_SWRST;
  while ((SERCOM3->USART.SYNCBUSY.reg & SERCOM_USART_SYNCBUSY_SWRST) != 0U)
  {
  }

  /* Asynchronous arithmetic baud: BAUD = 65536 * (1 - 16 * f_baud / f_ref).
   * Computed in 64-bit because 65536 * 16 * baud overflows 32 bits at any
   * baud above ~4 kbit/s -- an overflow that produces a plausible-looking
   * wrong divisor rather than an obvious failure. */
  br = (uint64_t)65536UL * (uint64_t)(16UL * baud);
  br = 65536ULL - (br / SAMD21_CPU_HZ);
  SERCOM3->USART.BAUD.reg = (uint16_t)br;

  SERCOM3->USART.CTRLA.reg = SERCOM_USART_CTRLA_MODE_USART_INT_CLK
                             | SERCOM_USART_CTRLA_DORD          /* LSB first */
                             | SERCOM_USART_CTRLA_TXPO(UART_TXPO)
                             | SERCOM_USART_CTRLA_RXPO(UART_RXPO);
  SERCOM3->USART.CTRLB.reg = SERCOM_USART_CTRLB_TXEN
                             | SERCOM_USART_CTRLB_RXEN;         /* 8N1        */
  while ((SERCOM3->USART.SYNCBUSY.reg & SERCOM_USART_SYNCBUSY_CTRLB) != 0U)
  {
  }

  SERCOM3->USART.CTRLA.reg |= SERCOM_USART_CTRLA_ENABLE;
  while ((SERCOM3->USART.SYNCBUSY.reg & SERCOM_USART_SYNCBUSY_ENABLE) != 0U)
  {
  }

  rx_head = 0U;
  rx_tail = 0U;
  SERCOM3->USART.INTENSET.reg = SERCOM_USART_INTENSET_RXC;
  NVIC_ClearPendingIRQ(SERCOM3_IRQn);
  NVIC_EnableIRQ(SERCOM3_IRQn);
}

HAL_StatusTypeDef HAL_UART_Transmit(const uint8_t *pData, uint16_t Size,
                                    uint32_t Timeout)
{
  uint16_t i;

  (void)Timeout;                         /* TX cannot stall: no flow control */
  for (i = 0U; i < Size; i++)
  {
    while ((SERCOM3->USART.INTFLAG.reg & SERCOM_USART_INTFLAG_DRE) == 0U)
    {
    }
    SERCOM3->USART.DATA.reg = pData[i];
  }
  while ((SERCOM3->USART.INTFLAG.reg & SERCOM_USART_INTFLAG_TXC) == 0U)
  {
  }
  return HAL_OK;
}

HAL_StatusTypeDef HAL_UART_Receive(uint8_t *pData, uint16_t Size,
                                   uint32_t Timeout)
{
  uint32_t start = HAL_GetTick();
  uint16_t i;

  for (i = 0U; i < Size; i++)
  {
    for (;;)
    {
      uint16_t t = rx_tail;

      if (t != rx_head)
      {
        pData[i] = rx_buf[t];
        rx_tail = (uint16_t)((t + 1U) & (RX_BUF_SIZE - 1U));
        break;
      }
      /* YMODEM's whole flow control is timeouts -- the loader tells "no
       * host" from "host is slow" by them -- so this one is real, not a
       * safety net.  Per-CALL, matching STM32Cube's HAL_UART_Receive,
       * because that is what sfu_com_loader.c expects. */
      if ((HAL_GetTick() - start) >= Timeout)
      {
        return HAL_TIMEOUT;
      }
    }
  }
  return HAL_OK;
}

void HAL_UART_Flush(void)
{
  rx_tail = rx_head;
}

/* -------------------------------------------------------------- watchdog -- */

/* 0 = armed, non-zero = which step gave up.  Read by HAL_WDT_Status() so the
 * boot log can say the watchdog is not running rather than implying it is. */
static uint8_t g_wdt_failed = 0xFFU;

/* ~50 ms at 48 MHz, which is 50 GCLK2 periods at 1024 Hz -- an order of
 * magnitude more than a WDT sync needs and still imperceptible at boot. */
#define WDT_SYNC_SPIN  (200000UL)

static uint32_t wdt_sync_bounded(void)
{
  uint32_t n = WDT_SYNC_SPIN;

  while (n-- != 0U)
  {
    if (WDT->STATUS.bit.SYNCBUSY == 0U)
    {
      return 0U;
    }
  }
  return 1U;
}

uint8_t HAL_WDT_Status(void)
{
  return g_wdt_failed;
}

void HAL_WDT_Init(uint32_t timeout_s)
{
  uint32_t per;

  /* Run the WDT from a 32 kHz source through generator 2, NOT from the CPU's
   * generator.  If the watchdog were clocked from generator 0 its timeout
   * would scale with the CPU clock axis, so changing the clock would silently
   * change how long a verify pass is allowed to take -- and a verify pass
   * that is reset halfway through looks exactly like a corrupt image.
   *
   * OSCULP32K, NOT OSC32K, AND THAT IS MEASURED RATHER THAN PREFERRED.  The
   * first version of this function enabled OSC32K and waited for
   * PCLKSR.OSC32KRDY.  On this die that bit never set, and the bootloader
   * hung here on its first boot -- silently, because a watchdog that has not
   * started yet cannot reset the part that is stuck starting it.
   *
   * OSCULP32K is the ultra-low-power 32 kHz oscillator.  It is ALWAYS
   * RUNNING out of reset, needs no enable, no calibration load and no
   * readiness wait, and it is the source the WDT is designed around.  There
   * is no wait loop below for the same reason: there is nothing to wait
   * for. */
  GCLK->GENDIV.reg = GCLK_GENDIV_ID(2) | GCLK_GENDIV_DIV(4);   /* 2^(4+1)=32 */
  gclk_sync();
  GCLK->GENCTRL.reg = GCLK_GENCTRL_ID(2) | GCLK_GENCTRL_SRC_OSCULP32K
                      | GCLK_GENCTRL_DIVSEL | GCLK_GENCTRL_GENEN;
  gclk_sync();
  GCLK->CLKCTRL.reg = (uint16_t)(GCLK_CLKCTRL_ID_WDT
                                 | GCLK_CLKCTRL_GEN_GCLK2
                                 | GCLK_CLKCTRL_CLKEN);
  gclk_sync();
  PM->APBAMASK.reg |= PM_APBAMASK_WDT;

  /* EVERY WAIT BELOW IS BOUNDED, AND THAT IS NOT DEFENSIVE PROGRAMMING --
   * it is the fix for a real hang.  The first version of this function spun
   * forever on WDT.STATUS.SYNCBUSY, and the failure had a nasty shape: a
   * watchdog that has not finished starting cannot reset the part that is
   * stuck starting it, and this runs before SBSFU's trace is up, so the
   * board simply sat there saying nothing.
   *
   * A bootloader may fail to arm its watchdog.  It may NOT hang while
   * trying.  On timeout the WDT is left disabled and g_wdt_failed records
   * it, so the boot continues and the condition is reportable instead of
   * invisible. */
  if (wdt_sync_bounded() != 0U)
  {
    g_wdt_failed = 1U;
    return;
  }
  WDT->CTRL.reg = 0U;                                /* disable while config */
  if (wdt_sync_bounded() != 0U)
  {
    g_wdt_failed = 2U;
    return;
  }

  /* Generator 2 is 32768 / 32 = 1024 Hz, so PER is roughly timeout_s * 1024
   * rounded up to the next power of two the peripheral offers.  PER_16K is
   * 16384 cycles = 16 s, which covers ST's SFU_IWDG_TIMEOUT of 6 s with
   * margin; a verify pass over a 1 MB slot at 8 MHz SCLK is well under a
   * second of bus time, so this is not tight. */
  per = (timeout_s <= 4U)  ? WDT_CONFIG_PER_4K
        : (timeout_s <= 8U) ? WDT_CONFIG_PER_8K
                            : WDT_CONFIG_PER_16K;
  WDT->CONFIG.reg = (uint8_t)per;
  WDT->CTRL.reg = WDT_CTRL_ENABLE;
  if (wdt_sync_bounded() != 0U)
  {
    g_wdt_failed = 3U;
    WDT->CTRL.reg = 0U;
    return;
  }
  g_wdt_failed = 0U;
}

void HAL_WDT_Refresh(void)
{
  if ((g_wdt_failed != 0U) || ((WDT->CTRL.reg & WDT_CTRL_ENABLE) == 0U))
  {
    return;
  }
  WDT->CLEAR.reg = (uint8_t)WDT_CLEAR_CLEAR_KEY;
  /* Bounded for the same reason, and it matters more here: this is called
   * from inside the verify loop, once per erase block and once per written
   * page.  An unbounded spin here would stall a capture rather than a boot. */
  (void)wdt_sync_bounded();
}
