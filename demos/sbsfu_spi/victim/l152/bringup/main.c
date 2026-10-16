/* Bring-up self-test for the NUCLEO-L152RE SBSFU port's serial-flash BSP.
 *
 * This is not part of the bootloader.  It exists because
 * research/mechanism/MEASURING_CHANNELS.md's first rule is that a rig you
 * have not verified produces statistics, not evidence -- and the specific
 * failure it guards against here is real: a driver that returns success
 * while reading 0xFF would make SBSFU "verify" an empty slot, and every
 * timing capture taken through it would be a capture of a cipher decrypting
 * nothing.
 *
 * It compiles the SAME NUCLEO_L152RE/BSP source the bootloader does, reached
 * sibling-relative rather than copied, so a green self-test is a statement
 * about the code that will actually run.  If those two ever diverge the test
 * stops meaning anything.
 *
 * What it proves, in the order it reports them:
 *
 *   1. the clock came up at 32 MHz with one flash wait state -- reported as
 *      a REGISTER READBACK, never as the value that was requested;
 *   2. the SPI2 pins reach the memory at all: the raw JEDEC ID, printed
 *      before anything interprets it, so "no reply" is distinguishable from
 *      "a part the driver does not know";
 *   3. BSP_QSPI_Init succeeds and resolves a capacity from that ID;
 *   4. a 64 KB block erase really erases -- checked by reading the block
 *      back blank, not by trusting the status register;
 *   5. page programming works ACROSS a 256-byte page boundary, which is the
 *      one arithmetic bug in an SPI-NOR driver that corrupts the start of an
 *      image and surfaces much later as an authentication failure;
 *   6. reads of 16, 64, 512 and 4096 bytes all return what was written, so
 *      every chunk size the demo might use is covered;
 *   7. the bus-transaction counters agree with the number of reads issued,
 *      which is the target side of the envelope-count control in
 *      rigs/fw_f303_spitimer/WIRING.md section 5.
 *
 * IT ERASES THE FIRST 64 KB OF THE ATTACHED SERIAL FLASH.  That chip holds
 * nothing but staged firmware images, so this is cheap -- but it is not
 * read-only, and it should not be run against a board mid-campaign.
 *
 * Output is plain text on USART2 (PA2/PA3, AF7) -> the ST-LINK virtual COM
 * port at 115200 8N1, which is the same path rigs/fw_l1_aes uses on this
 * board.  After the self-test it accepts single-letter commands; `P` is the
 * one that matters for wiring work, because it drives chip-select
 * continuously so a probe or a scope has something to find.
 */
#include <stdint.h>
#include <string.h>

#include "stm32l1xx_hal.h"
#include "l152_nucleo_spif.h"

/* The first 64 KB block, and a write straddling a page boundary inside it. */
#define TEST_BLOCK   0x00000000UL
#define XPAGE_ADDR   (0x00000100UL - 8UL)   /* 8 bytes before a page edge   */
#define XPAGE_LEN    (16U)
#define BIGBUF       (4096U)

static UART_HandleTypeDef huart2;
static int ctrs_carried;        /* did the .noinit counters survive a reset */
static uint8_t buf[BIGBUF];
static uint8_t pat[BIGBUF];

/* ------------------------------------------------------------- plumbing -- */

static void uart_putc(char c)
{
  (void)HAL_UART_Transmit(&huart2, (uint8_t *)&c, 1U, 100U);
}

static void put(const char *s)
{
  while (*s != '\0')
  {
    uart_putc(*s++);
  }
}

static void put_hex(uint32_t v, int digits)
{
  static const char H[] = "0123456789abcdef";
  int i;

  for (i = digits - 1; i >= 0; i--)
  {
    uart_putc(H[(v >> (4 * i)) & 0xFU]);
  }
}

static void put_dec(uint32_t v)
{
  char t[11];
  int n = 0;

  if (v == 0U)
  {
    uart_putc('0');
    return;
  }
  while (v != 0U)
  {
    t[n++] = (char)('0' + (v % 10U));
    v /= 10U;
  }
  while (n-- > 0)
  {
    uart_putc(t[n]);
  }
}

/* PASS/FAIL on one line, so a scroll-back is greppable and a partial run is
 * still readable.  Returns the verdict so main can count failures. */
static int verdict(const char *what, int ok)
{
  put(ok ? "  PASS  " : "  FAIL  ");
  put(what);
  put("\r\n");
  return ok ? 0 : 1;
}

/* ---------------------------------------------------------------- clocks -- */

/* Copied verbatim from ST's own NUCLEO-L152RE example,
 * Projects/NUCLEO-L152RE/Examples/SPI/SPI_FullDuplex_ComPolling/Src/main.c
 * in STM32CubeL1 v1.10.6, except that its Error_Handler() calls are replaced
 * by returning a status -- this image has to be able to REPORT a clock
 * failure rather than spin in one.
 *
 * HSI 16 MHz -> PLLMUL6 -> 96 MHz VCO -> PLLDIV3 -> 32 MHz SYSCLK, voltage
 * range 1, one flash wait state.  That last is not incidental: on this part
 * LATENCY is a single bit, and 32 MHz in range 1 is the only configuration
 * where it is set.  A zero-wait-state L152 is a different experiment. */
static int SystemClock_Config(void)
{
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};

  RCC_OscInitStruct.OscillatorType      = RCC_OSCILLATORTYPE_HSI;
  RCC_OscInitStruct.HSIState            = RCC_HSI_ON;
  RCC_OscInitStruct.HSICalibrationValue = RCC_HSICALIBRATION_DEFAULT;
  RCC_OscInitStruct.PLL.PLLState        = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource       = RCC_PLLSOURCE_HSI;
  RCC_OscInitStruct.PLL.PLLMUL          = RCC_PLL_MUL6;
  RCC_OscInitStruct.PLL.PLLDIV          = RCC_PLL_DIV3;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    return -1;
  }

  __HAL_RCC_PWR_CLK_ENABLE();
  __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE1);
  while (__HAL_PWR_GET_FLAG(PWR_FLAG_VOS) != RESET) {}

  RCC_ClkInitStruct.ClockType = (RCC_CLOCKTYPE_SYSCLK | RCC_CLOCKTYPE_HCLK |
                                 RCC_CLOCKTYPE_PCLK1 | RCC_CLOCKTYPE_PCLK2);
  RCC_ClkInitStruct.SYSCLKSource   = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider  = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV1;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;
  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_1) != HAL_OK)
  {
    return -1;
  }
  return 0;
}

static void uart_init(void)
{
  GPIO_InitTypeDef g = {0};

  __HAL_RCC_GPIOA_CLK_ENABLE();
  __HAL_RCC_USART2_CLK_ENABLE();

  g.Pin       = GPIO_PIN_2 | GPIO_PIN_3;
  g.Mode      = GPIO_MODE_AF_PP;
  g.Pull      = GPIO_PULLUP;
  g.Speed     = GPIO_SPEED_HIGH;
  g.Alternate = GPIO_AF7_USART2;
  HAL_GPIO_Init(GPIOA, &g);

  huart2.Instance        = USART2;
  huart2.Init.BaudRate   = 115200U;
  huart2.Init.WordLength = UART_WORDLENGTH_8B;
  huart2.Init.StopBits   = UART_STOPBITS_1;
  huart2.Init.Parity     = UART_PARITY_NONE;
  huart2.Init.Mode       = UART_MODE_TX_RX;
  huart2.Init.HwFlowCtl  = UART_HWCONTROL_NONE;
  huart2.Init.OverSampling = UART_OVERSAMPLING_16;
  (void)HAL_UART_Init(&huart2);
}

/* Cortex-M3 DWT cycle counter.  Used only to report how long a read takes,
 * which is a sanity figure here rather than a measurement -- the real
 * timing is taken off the wire by rigs/fw_f303_spitimer, never by the
 * victim itself. */
static void dwt_init(void)
{
  CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
  DWT->CYCCNT = 0U;
  DWT->CTRL  |= DWT_CTRL_CYCCNTENA_Msk;
}

/* Does the cycle counter actually count?
 *
 * Not a formality.  DWT is debug hardware: it needs TRCENA set, it can be
 * left disabled by whatever attached last, and on some parts CYCCNT is
 * simply not implemented (DWT_CTRL's NOCYCCNT bit).  Every "cycles" figure
 * this image prints is worthless if it is not running, and a dead counter
 * reads as a suspiciously round ZERO rather than as an error -- which is
 * exactly how a saturated measurement disguises itself as a real result. */
static int dwt_alive(void)
{
  uint32_t a = DWT->CYCCNT;
  volatile uint32_t spin = 100U;
  while (spin-- != 0U) { __NOP(); }
  return (DWT->CYCCNT != a);
}

/* A cycle count built from SysTick, because DWT's is not available here.
 *
 * MEASURED, not assumed: on this board DWT_CTRL comes back 0x40000001 --
 * NOCYCCNT clear, CYCCNTENA set, so the counter exists and is switched on
 * -- while DEMCR reads 0x00000000 after being written.  The debug block
 * ignores the write once the ST-LINK has detached, which it has by the
 * time this firmware runs, so CYCCNT never advances.  It works under a
 * debugger and not otherwise, which is the worst of both worlds: numbers
 * that look right while you are watching and are zero when you are not.
 *
 * SysTick is the application's own timer, HAL already runs it at 1 kHz,
 * and it is what rigs/fw_l1_aes uses on this same part.  Reading the
 * millisecond count and the down-counter together needs the re-read
 * below: the two are updated independently and a tick landing between
 * them yields a value nearly a millisecond out.
 *
 * Wraps every 134 seconds at 32 MHz, which is fine for differences and
 * would not be for absolute time.  Nothing here uses absolute time.
 */
static uint32_t cyc(void)
{
  uint32_t m1, v, m2, reload;

  reload = SysTick->LOAD + 1U;
  do
  {
    m1 = HAL_GetTick();
    v  = SysTick->VAL;
    m2 = HAL_GetTick();
  } while (m1 != m2);
  return (m1 * reload) + (reload - v);
}

/* ------------------------------------------------------- wiring forensics -- */

static const char *const PINNAME[4] = { "CS/PA8", "SCK/PB13",
                                        "MISO/PB14", "MOSI/PB15" };

/* Read the JEDEC ID at four bus rates.
 *
 * A flying-lead bus that answers at 125 kHz and not at 8 MHz has a signal
 * problem -- lead length, no ground return beside the clock, a missing
 * decoupling cap.  One that answers at neither does not, and the two want
 * completely different things done about them.  Asking once at one rate
 * cannot tell them apart, so this asks four times. */
static int id_speed_sweep(void)
{
  static const struct { uint32_t pre; const char *hz; } RATE[] = {
    { SPI_BAUDRATEPRESCALER_4,   "8 MHz"   },
    { SPI_BAUDRATEPRESCALER_16,  "2 MHz"   },
    { SPI_BAUDRATEPRESCALER_64,  "500 kHz" },
    { SPI_BAUDRATEPRESCALER_256, "125 kHz" },
  };
  int answered = 0;
  unsigned i;

  for (i = 0U; i < sizeof(RATE) / sizeof(RATE[0]); i++)
  {
    uint8_t id[3] = { 0U, 0U, 0U };

    if (BSP_SPIF_SetBaudPrescaler(RATE[i].pre) != QSPI_OK)
    {
      continue;
    }
    (void)BSP_SPIF_ReadId(id);
    put("        at ");
    put(RATE[i].hz);
    put("\t");
    put_hex(id[0], 2); put(" "); put_hex(id[1], 2); put(" ");
    put_hex(id[2], 2);
    if ((id[0] == 0x00U && id[1] == 0x00U && id[2] == 0x00U) ||
        (id[0] == 0xFFU && id[1] == 0xFFU && id[2] == 0xFFU))
    {
      put("   (no reply)");
    }
    else
    {
      put("   <- a reply");
      answered++;
    }
    put("\r\n");
  }
  (void)BSP_SPIF_SetBaudPrescaler(SPI_BAUDRATEPRESCALER_4);
  return answered;
}

/* Is there a wire on each pin? */
static void load_probe(void)
{
  static const char *const NAME[6] = {
    "CS/PA8   ", "SCK/PB13 ", "MISO/PB14", "MOSI/PB15",
    "PA9  bare", "PB12 bare"
  };
  uint32_t c[6];
  int i;

  BSP_SPIF_ProbeLoad(c);

  put("\r\nload    read-back polls for each line to be dragged up by its\r\n"
      "        own pull-up -- a capacitance measurement, so a lead and a\r\n"
      "        chip read HIGHER than a bare pin:\r\n");
  for (i = 0; i < 6; i++)
  {
    put("          ");
    put(NAME[i]);
    put("  ");
    if (c[i] == 0xFFFFFFFFUL)
    {
      put("never rose -- held low from the other end\r\n");
    }
    else
    {
      put_dec(c[i]);
      put(" polls\r\n");
    }
  }

  /* The comparison, spelled out rather than left to the reader: the
   * question is whether each bus line looks like its bare neighbour. */
  {
    static const int ref[4] = { 4, 5, 5, 5 };
    int loaded = 0;

    put("        against the bare reference on the same connector:\r\n");
    for (i = 0; i < 4; i++)
    {
      uint32_t r = c[ref[i]];

      put("          ");
      put(NAME[i]);
      put("  ");
      if (c[i] == 0xFFFFFFFFUL)
      {
        put("held low\r\n");
      }
      else if (r != 0xFFFFFFFFUL && c[i] > r + (r / 2U) + 2U)
      {
        put("clearly loaded -- something is on this pin\r\n");
        loaded++;
      }
      else
      {
        put("same as a bare pin -- nothing detected on it\r\n");
      }
    }
    /* NO CONCLUSION UNLESS THE REFERENCES HAVE ROOM TO SHOW ONE.
     *
     * A bare pin rising in one or two polls means this probe's whole
     * dynamic range is one or two counts, and "nothing is attached" would
     * then be a statement about the instrument wearing the clothes of a
     * statement about the harness.  The first version printed exactly
     * that, confidently, from six readings of zero.  Eight polls of
     * baseline is the point at which a 50% difference is more than
     * quantisation noise; below it this section says nothing.
     *
     * The measurement is left in because it costs nothing and would be
     * decisive on a board whose pull-up is weaker.  The refusal is the
     * part that has to be right. */
    if (c[4] < 8U || c[5] < 8U)
    {
      put("        -> THE BARE REFERENCES RISE IN ");
      put_dec(c[4] < c[5] ? c[4] : c[5]);
      put(" POLLS, so this probe has\r\n"
          "           no useful resolution on this board and the four\r\n"
          "           readings above mean nothing either way. Ignore\r\n"
          "           this section; the MISO float test above is the\r\n"
          "           one carrying the evidence.\r\n");
    }
    else if (loaded == 0)
    {
      put("        -> none of the four lines carries a detectable load,\r\n"
          "           and the references do resolve. The harness is not\r\n"
          "           reaching these pins: wrong header, wrong row, or\r\n"
          "           the leads are not seated.\r\n");
    }
  }
}

/* Square wave on ONE line, slow enough to chase with a meter.
 *
 * A chip-select envelope in normal operation is microseconds wide, which
 * is findable with a scope on the right pin and with nothing else.  For
 * tracing a lead -- is this the pin, does it reach the chip, is the
 * breakout soldered -- what is wanted is a level that sits still long
 * enough to read: one second high, one second low, forever.
 *
 * The other three lines are left as unpulled inputs while this runs, so a
 * meter moved onto any of them reads the harness and not this board.
 *
 * Runs until a byte arrives on the console, then puts the peripheral back.
 * Each transition is printed, so a reading can be matched to an edge
 * without watching the clock.
 */
static void pin_toggle(int idx, const char *name)
{
  uint32_t n = 0U;
  int level = 0;

  if (BSP_SPIF_PinGpioMode(idx) != QSPI_OK)
  {
    put("toggle  bad pin index\r\n");
    return;
  }

  put("\r\ntoggle  ");
  put(name);
  put(": 1 s high, 1 s low, push-pull, 0 V / 3.3 V.\r\n"
      "        The other three lines are inputs and are NOT being driven.\r\n"
      "        Any key stops it and hands the pin back to SPI2.\r\n\r\n");

  for (;;)
  {
    uint8_t c;

    BSP_SPIF_PinWrite(idx, level);
    put("        ");
    put_dec(n);
    put("  ");
    put(name);
    put(level ? " = HIGH (3.3 V)\r\n" : " = LOW  (0 V)\r\n");

    /* One second, in short waits, so a keystroke stops it promptly
     * rather than after the rest of the level. */
    {
      int k;
      for (k = 0; k < 20; k++)
      {
        if (HAL_UART_Receive(&huart2, &c, 1U, 50U) == HAL_OK)
        {
          BSP_SPIF_PinWrite(idx, 1);
          BSP_SPIF_PinRestore();
          put("\r\ntoggle  stopped; SPI2 has the pins back.\r\n");
          return;
        }
      }
    }
    level = !level;
    n++;
  }
}

/* Ask for the ID both ways round, by hand, off the peripheral entirely. */
static void swap_probe(void)
{
  uint8_t id[3];
  int i;

  put("\r\nswap    bit-banged ID, all four lines as GPIO:\r\n");
  for (i = 0; i < 2; i++)
  {
    (void)BSP_SPIF_BitbangId(id, i);
    put(i ? "        SI/SO SWAPPED (SO on PB15, SI on PB14)  "
          : "        as wired    (SO on PB14, SI on PB15)  ");
    put_hex(id[0], 2); put(" "); put_hex(id[1], 2); put(" ");
    put_hex(id[2], 2);
    if ((id[0] == 0x00U && id[1] == 0x00U && id[2] == 0x00U) ||
        (id[0] == 0xFFU && id[1] == 0xFFU && id[2] == 0xFFU))
    {
      put("   (no reply)\r\n");
    }
    else
    {
      put(i ? "   <- THE DATA PAIR IS CROSSED\r\n"
            : "   <- a reply\r\n");
    }
  }
}

/* Take the four lines off the peripheral and interrogate them as pins. */
static void wiring_probe(void)
{
  uint32_t w = BSP_SPIF_ProbeWiring();
  int shorts = 0;
  int i, j;

  put("\r\nwiring  MISO with a pull-up reads ");
  put((w & 1U) ? "HIGH" : "LOW");
  put(", with a pull-down reads ");
  put((w & 2U) ? "LOW" : "HIGH");
  put("\r\n        -> ");
  if ((w & 3U) == 3U)
  {
    put("MISO FLOATS: it follows whichever way it is pulled, so\r\n"
        "           nothing on the other end is driving it. The memory is\r\n"
        "           unpowered, or SO is not landing on PB14.\r\n");
  }
  else if ((w & 3U) == 2U)
  {
    put("MISO is HELD LOW: it cannot be pulled up, so something is\r\n"
        "           driving it or it is shorted to ground.\r\n");
  }
  else if ((w & 3U) == 1U)
  {
    put("MISO is HELD HIGH: it cannot be pulled down, so it is\r\n"
        "           shorted to 3V3.\r\n");
  }
  else
  {
    put("MISO reads inverted to both pulls, which should not happen.\r\n");
  }

  put("        short matrix (one pin driven low, the rest pulled up):\r\n");
  for (i = 0; i < 4; i++)
  {
    for (j = 0; j < 4; j++)
    {
      if (i != j && (w & (1UL << (4 + 4 * i + j))) != 0U)
      {
        put("          ");
        put(PINNAME[i]);
        put(" low pulls down ");
        put(PINNAME[j]);
        put("  <- SHORTED\r\n");
        shorts++;
      }
    }
  }
  if (shorts == 0)
  {
    put("          none: the four lines are independent of each other\r\n");
  }
}

/* ------------------------------------------------------------- the tests -- */

static int test_read_sizes(void)
{
  static const uint32_t sizes[] = { 16U, 64U, 512U, 4096U };
  int bad = 0;
  unsigned i;

  for (i = 0U; i < sizeof(sizes) / sizeof(sizes[0]); i++)
  {
    uint32_t n = sizes[i];
    uint32_t t0, t1;

    memset(buf, 0x00, n);
    t0 = cyc();
    if (BSP_QSPI_Read(buf, TEST_BLOCK, n) != QSPI_OK)
    {
      put("  FAIL  read ");
      put_dec(n);
      put(" returned an error\r\n");
      bad++;
      continue;
    }
    t1 = cyc();

    if (memcmp(buf, pat, n) != 0)
    {
      put("  FAIL  read ");
      put_dec(n);
      put(" mismatched at byte ");
      {
        uint32_t j = 0U;
        while (j < n && buf[j] == pat[j]) { j++; }
        put_dec(j);
        put(" (got ");
        put_hex(buf[j], 2);
        put(" want ");
        put_hex(pat[j], 2);
        put(")\r\n");
      }
      bad++;
      continue;
    }

    put("  PASS  read ");
    put_dec(n);
    put(" bytes, ");
    put_dec(t1 - t0);
    put(" cycles (");
    put_dec((t1 - t0) / 32U);
    put(" us)\r\n");
  }
  return bad;
}

static int selftest(void)
{
  QSPI_Info info;
  uint8_t id[3];
  uint8_t sr1 = 0U;
  uint32_t i;
  int bad = 0;
  uint32_t reads0;

  put("\r\n=== NUCLEO-L152RE serial-flash bring-up ===\r\n");

  /* Before anything prints a total.  The counters live in .noinit, so on
   * a cold start they hold whatever SRAM held, and the first successful
   * run of this image published 584059292 reads as though it meant
   * something. */
  ctrs_carried = BSP_SPIF_CountersInit();

  /* 1. the clock, as the registers report it rather than as configured. */
  put("clock   SYSCLK ");
  put_dec(HAL_RCC_GetSysClockFreq());
  put(" Hz, PCLK1 ");
  put_dec(HAL_RCC_GetPCLK1Freq());
  put(" Hz, FLASH_ACR 0x");
  put_hex(FLASH->ACR, 8);
  put("\r\n        wait states ");
  put_dec((FLASH->ACR & FLASH_ACR_LATENCY) ? 1U : 0U);
  put(", 64-bit access ");
  put((FLASH->ACR & FLASH_ACR_ACC64) ? "on" : "off");
  put(", prefetch ");
  put((FLASH->ACR & FLASH_ACR_PRFTEN) ? "on" : "off");
  put("\r\n        DBGMCU IDCODE 0x");
  put_hex(DBGMCU->IDCODE, 8);
  /* Whether this die has an MPU decides one line of the bootloader's
   * configuration (SFU_MPU_PROTECT_ENABLE), and it is the kind of thing
   * that gets asserted from a datasheet and turns out to be wrong on the
   * part in hand -- the SAM D21 port found MPU_TYPE reading 0 where the
   * headers said __MPU_PRESENT.  So it is measured here and quoted from
   * here, never from a document. */
  put("\r\n        MPU_TYPE 0x");
  put_hex(MPU->TYPE, 8);
  put(" -> ");
  put(((MPU->TYPE >> 8) & 0xFFU) ? "MPU fitted" : "no MPU on this die");
  put(", ");
  put_dec((MPU->TYPE >> 8) & 0xFFU);
  put(" regions\r\n");
  bad += verdict("SYSCLK is 32 MHz", HAL_RCC_GetSysClockFreq() == 32000000U);
  {
    int alive = dwt_alive();

    put("        DWT_CTRL 0x");
    put_hex(DWT->CTRL, 8);
    put(", DEMCR 0x");
    put_hex(CoreDebug->DEMCR, 8);
    put(", NOCYCCNT ");
    put((DWT->CTRL & (1UL << 25)) ? "SET -- this die has no cycle counter"
                                  : "clear -- the counter exists");
    put("\r\n");
    put("        timing source: ");
    put(alive ? "DWT cycle counter" : "SysTick (DWT is dead once the "
                                      "debugger detaches)");
    put(", ");
    put(cyc() != cyc() ? "counting\r\n" : "STUCK -- timings are worthless\r\n");
  }
  bad += verdict("one flash wait state (the channel's gain)",
                 (FLASH->ACR & FLASH_ACR_LATENCY) != 0U);

  /* 2. the raw ID, printed BEFORE anything interprets it.  BSP_QSPI_Init
   *    reads the same bytes, but if it rejects them this line is the only
   *    place the actual reply appears -- and "what came back" is the first
   *    question when a lead is on the wrong pin. */
  put("\r\nbus     JEDEC ID ");
  if (BSP_SPIF_ReadId(id) != QSPI_OK)
  {
    put("<SPI transfer failed>\r\n");
    return bad + 1;
  }
  put_hex(id[0], 2); put(" "); put_hex(id[1], 2); put(" "); put_hex(id[2], 2);
  put("\r\n");

  /* 3. init, which is also where the ID gets a meaning. */
  if (BSP_QSPI_Init() != QSPI_OK)
  {
    put("  FAIL  BSP_QSPI_Init: ");
    put(BSP_SPIF_PartName());
    put("\r\n");
    /* Do not just stop.  A failed ID read has at least four causes and
     * they are fixed at different ends of the lead, so the next two probes
     * run automatically -- the point of a bring-up image is to say WHICH
     * thing is wrong, not that something is. */
    put("\r\nsweep   the same read at four bus rates:\r\n");
    (void)id_speed_sweep();
    swap_probe();
    wiring_probe();
    load_probe();
    put("\r\nStopping here: nothing below this line means anything if the\r\n"
        "driver cannot talk to the memory.  Pin 1 of a SOIC-8 serial NOR is\r\n"
        "/CS, 2 is SO, 3 is /WP, 4 is GND, 5 is SI, 6 is SCK, 7 is /HOLD\r\n"
        "and 8 is VCC -- /WP and /HOLD must be tied to VCC, not left open.\r\n");
    return bad + 1;
  }
  put("  PASS  BSP_QSPI_Init, part reads as ");
  put(BSP_SPIF_PartName());
  put("\r\n");

  (void)BSP_QSPI_GetInfo(&info);
  if (BSP_SPIF_SizeClamped())
  {
    put("        NOTE: the part is larger than 24-bit addressing reaches.\r\n"
        "        The driver reports and will touch only the low 16 MB; the\r\n"
        "        rest needs the 4-byte opcodes and nothing here uses it.\r\n");
  }
  put("        capacity ");
  put_dec(info.FlashSize / 1024U);
  put(" KB addressable, ");
  put_dec(info.EraseSectorsNumber);
  put(" sectors of ");
  put_dec(info.EraseSectorSize);
  put(", ");
  put_dec(info.ProgPagesNumber);
  put(" pages of ");
  put_dec(info.ProgPageSize);
  put("\r\n");
  (void)BSP_SPIF_ReadStatus(&sr1);
  put("        status register 1 0x");
  put_hex(sr1, 2);
  put("\r\n");
  bad += verdict("block protection is clear", (sr1 & 0x7CU) == 0U);

  /* 4. erase, verified by reading it back rather than by the status bit. */
  put("\r\nerase   64 KB block at 0x000000 ... ");
  if (BSP_QSPI_Erase_Block(TEST_BLOCK) != QSPI_OK)
  {
    put("error\r\n");
    return bad + 1;
  }
  put("done\r\n");

  {
    int blank = 1;
    uint32_t off;

    for (off = 0U; off < 65536U && blank; off += BIGBUF)
    {
      if (BSP_QSPI_Read(buf, TEST_BLOCK + off, BIGBUF) != QSPI_OK)
      {
        blank = 0;
        break;
      }
      for (i = 0U; i < BIGBUF; i++)
      {
        if (buf[i] != 0xFFU) { blank = 0; break; }
      }
    }
    bad += verdict("the whole 64 KB block reads back as 0xFF", blank);
  }

  /* 5. program, including across a page boundary. */
  for (i = 0U; i < BIGBUF; i++)
  {
    /* A pattern where every byte differs from its neighbours and from its
     * own address low byte, so an off-by-one and a stuck bus look
     * different: a shifted read mismatches, a repeated read does not. */
    pat[i] = (uint8_t)((i * 7U) ^ (i >> 5)) ^ 0x5AU;
  }
  put("\r\nwrite   4096 bytes from 0x000000 ... ");
  if (BSP_QSPI_Write(pat, TEST_BLOCK, BIGBUF) != QSPI_OK)
  {
    put("error\r\n");
    return bad + 1;
  }
  put("done\r\n");

  bad += test_read_sizes();

  {
    /* The page-crossing case, written separately so a failure names it.
     * 0xF8..0x107 spans the boundary at 0x100. */
    uint8_t x[XPAGE_LEN];
    uint8_t y[XPAGE_LEN];

    for (i = 0U; i < XPAGE_LEN; i++)
    {
      x[i] = (uint8_t)(0xA0U + i);
    }
    if (BSP_QSPI_Erase_Sector(TEST_BLOCK) != QSPI_OK)
    {
      return bad + 1;
    }
    if (BSP_QSPI_Write(x, XPAGE_ADDR, XPAGE_LEN) != QSPI_OK)
    {
      return bad + 1;
    }
    memset(y, 0U, XPAGE_LEN);
    if (BSP_QSPI_Read(y, XPAGE_ADDR, XPAGE_LEN) != QSPI_OK)
    {
      return bad + 1;
    }
    bad += verdict("a 16-byte write across a page boundary reads back whole",
                   memcmp(x, y, XPAGE_LEN) == 0);
  }

  /* 6. the counters, which are what the F303's edge count is checked
   *    against.  Six reads were issued above with the sector test; the
   *    exact figure is printed rather than asserted, because the assertion
   *    that matters is made on the wire, not here. */
  reads0 = g_spif_reads;
  for (i = 0U; i < 100U; i++)
  {
    (void)BSP_QSPI_Read(buf, TEST_BLOCK + 16U * i, 16U);
  }
  put("\r\nenvelopes 100 reads of 16 bytes -> counter moved by ");
  put_dec(g_spif_reads - reads0);
  put("\r\n");
  bad += verdict("one counted envelope per BSP_QSPI_Read",
                 (g_spif_reads - reads0) == 100U);
  put(ctrs_carried
      ? "        counters CARRIED OVER from a previous boot\r\n"
      : "        counters were zeroed at the top of this run\r\n");
  put("        totals: reads ");
  put_dec(g_spif_reads);
  put(", bytes ");
  put_dec(g_spif_read_bytes);
  put(", status polls ");
  put_dec(g_spif_status_polls);
  put(", writes ");
  put_dec(g_spif_writes);
  put(", erases ");
  put_dec(g_spif_erases);
  put("\r\n");

  return bad;
}

/* A chip-select train for wiring work: N reads back to back, nothing else
 * on the bus.  This is what to run while hunting for the tap with a scope
 * or while checking that rigs/fw_f303_spitimer sees an edge at all --
 * WIRING.md section 0 is the procedure, and it needs a target that is
 * producing envelopes on demand rather than once at boot. */
static void cs_train(uint32_t n, uint32_t size)
{
  uint32_t i;
  uint32_t t0, t1;

  put("train   ");
  put_dec(n);
  put(" reads of ");
  put_dec(size);
  put(" bytes, back to back ... ");
  t0 = cyc();
  for (i = 0U; i < n; i++)
  {
    (void)BSP_QSPI_Read(buf, (i * size) & 0x0000FFF0UL, size);
  }
  t1 = cyc();
  put("done, ");
  put_dec((t1 - t0) / 32U);
  put(" us total, ");
  put_dec((t1 - t0) / 32U / (n ? n : 1U));
  put(" us per envelope\r\n");
}

int main(void)
{
  int bad;

  HAL_Init();
  if (SystemClock_Config() != 0)
  {
    /* The UART has not been set up yet and cannot say so.  LD2 on PA5 is
     * the only channel left, and a fast blink is the agreed meaning. */
    __HAL_RCC_GPIOA_CLK_ENABLE();
    {
      GPIO_InitTypeDef g = {0};
      g.Pin = GPIO_PIN_5; g.Mode = GPIO_MODE_OUTPUT_PP;
      HAL_GPIO_Init(GPIOA, &g);
    }
    for (;;)
    {
      HAL_GPIO_TogglePin(GPIOA, GPIO_PIN_5);
      HAL_Delay(100);
    }
  }
  SystemCoreClockUpdate();
  uart_init();
  dwt_init();

  bad = selftest();
  put("\r\n");
  if (bad == 0)
  {
    put("ALL PASS -- the BSP is talking to the memory.\r\n");
  }
  else
  {
    put("FAILURES: ");
    put_dec((uint32_t)bad);
    put(" -- do not take a capture through this.\r\n");
  }
  put("\r\ncommands: R rerun  I read the ID  W wiring probe + speed sweep\r\n"
      "          1/2/3/4  toggle CS / SCK / MISO / MOSI at 1 s, to probe\r\n"
      "          P 1000 x 16-byte read train  Q 1000 x 64-byte train\r\n"
      "          C counters\r\n");

  for (;;)
  {
    uint8_t c;

    if (HAL_UART_Receive(&huart2, &c, 1U, HAL_MAX_DELAY) != HAL_OK)
    {
      continue;
    }
    switch (c)
    {
      case 'R': case 'r':
        bad = selftest();
        put(bad == 0 ? "\r\nALL PASS\r\n" : "\r\nFAILURES\r\n");
        break;
      case 'I': case 'i':
      {
        uint8_t id[3];
        (void)BSP_SPIF_ReadId(id);
        put("id      ");
        put_hex(id[0], 2); put(" "); put_hex(id[1], 2); put(" ");
        put_hex(id[2], 2); put("  ("); put(BSP_SPIF_PartName()); put(")\r\n");
        break;
      }
      case 'W': case 'w':
        put("\r\nsweep   the same read at four bus rates:\r\n");
        (void)id_speed_sweep();
        swap_probe();
        wiring_probe();
        load_probe();
        break;
      case 'L': case 'l': load_probe(); break;
      case '1': pin_toggle(0, "CS/PA8");    break;
      case '2': pin_toggle(1, "SCK/PB13");  break;
      case '3': pin_toggle(2, "MISO/PB14"); break;
      case '4': pin_toggle(3, "MOSI/PB15"); break;
      case 'P': case 'p': cs_train(1000U, 16U); break;
      case 'Q': case 'q': cs_train(1000U, 64U); break;
      case 'C': case 'c':
        put("counters reads ");
        put_dec(g_spif_reads);
        put(", bytes ");
        put_dec(g_spif_read_bytes);
        put(", polls ");
        put_dec(g_spif_status_polls);
        put(", writes ");
        put_dec(g_spif_writes);
        put(", erases ");
        put_dec(g_spif_erases);
        put(", last reject 0x");
        put_hex(g_spif_reject, 8);
        put("\r\n");
        break;
      default:
        break;
    }
  }
}

/* HAL's millisecond tick.  ST ships this in stm32l1xx_it.c per project; the
 * bring-up image has no other interrupt, so the one handler it needs lives
 * here rather than dragging in a file that is all empty stubs. */
void SysTick_Handler(void)
{
  HAL_IncTick();
}
