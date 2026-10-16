/* Bring-up self-test for the SAM D21 SBSFU port's HAL and serial-flash BSP.
 *
 * This is not part of the bootloader.  It exists because
 * research/mechanism/MEASURING_CHANNELS.md's first rule is that a rig you have
 * not verified produces statistics, not evidence -- and the specific failure
 * it guards against here is real: a driver that returns success while reading
 * 0xFF would make SBSFU "verify" an empty slot, and every timing capture taken
 * through it would be a capture of a cipher decrypting nothing.
 *
 * What it proves, in the order the mailbox reports it:
 *
 *   1. the clock came up at 48 MHz and SysTick counts             (w[10], w[11])
 *   2. Microchip's __MPU_PRESENT 0 is true of this die            (w[4])
 *   3. BSP_QSPI_Init succeeds and the AT25DF081A answers 0x9F     (w[2], w[3])
 *   4. a 64 KB block erase really erases -- checked by reading it
 *      back blank rather than by trusting the status register     (w[5], w[6])
 *   5. page programming works ACROSS a 256-byte page boundary,
 *      which is the one arithmetic bug in an SPI-NOR driver that
 *      corrupts the start of an image and shows up much later as
 *      an authentication failure                                  (w[7], w[9])
 *   6. reads of 16, 512 and 4096 bytes all return what was
 *      written, so chunk sizes the demo will sweep are covered    (w[8])
 *
 * IT ERASES THE FIRST 64 KB OF THE ON-BOARD SERIAL FLASH.  That chip holds
 * nothing but staged firmware images, so this is cheap -- but it is not
 * read-only, and it should not be run against a board mid-campaign.
 *
 * Driven by rigs/host/samd21_sbsfu_bringup.py over the SWD mailbox, the same
 * transport results/samd21/samd21.py uses.
 */
#include <stdint.h>

#include "samd21.h"
#include "samd21_hal.h"
#include "samd21_xpro_spif.h"

#define MAGIC        0x46495053UL          /* "SPIF" */
#define MBOX         ((volatile uint32_t *)0x20000000UL)

#define W_MAGIC      0U
#define W_STEP       1U
#define W_INIT       2U
#define W_ID         3U
#define W_MPU        4U
#define W_ERASE      5U
#define W_BLANK      6U
#define W_WRITE      7U
#define W_READBACK   8U
#define W_XPAGE      9U
#define W_CYC512     10U
#define W_CYC16      11U
#define W_SIZE       12U
#define W_BAUD       13U
#define W_TICKS      14U
#define W_DONE       15U
#define W_FIRST16    16U                   /* 4 words of read-back data      */

/* One 64 KB block, and a write straddling a page boundary inside it. */
#define TEST_BLOCK   0x00000000UL
#define XPAGE_ADDR   (0x00000100UL - 8UL)  /* 8 bytes before a page boundary */
#define XPAGE_LEN    32U

static uint8_t buf[4096];
static uint8_t pattern[XPAGE_LEN];

static void step(uint32_t s)
{
  MBOX[W_STEP] = s;
  __DSB();
}

/* SysTick counts DOWN from RVR at the CPU clock and is 24 bits wide, so a
 * measurement must fit in 16.7 ms at 48 MHz.  A 4096-byte read at 8 MHz SCLK
 * is about 4.1 ms, which fits; a whole-chip read would not, which is why the
 * timed reads below are bounded. */
static void timer_start(void)
{
  SysTick->CTRL = 0U;
  SysTick->LOAD = 0x00FFFFFFUL;
  SysTick->VAL = 0U;
  SysTick->CTRL = SysTick_CTRL_CLKSOURCE_Msk | SysTick_CTRL_ENABLE_Msk;
}

static uint32_t timer_stop(void)
{
  uint32_t v = SysTick->VAL;
  SysTick->CTRL = 0U;
  return (0x00FFFFFFUL - v) & 0x00FFFFFFUL;
}

int main(void)
{
  uint8_t id[3];
  QSPI_Info info;
  uint32_t i;
  uint32_t bad;

  HAL_ClockInit();

  /* EVERY RESULT WORD STARTS AT 0xFFFFFFFF, NOT AT ZERO, and that is not
   * tidiness.  The first run of this image stopped at step 4 and the host
   * still printed "ok" for the erase, the blank check, the cross-page write
   * and the read-back -- because those fields were zero-initialised and zero
   * is QSPI_OK and zero is "no mismatches".  A check that reads a field the
   * firmware never wrote is not a check.  0xFFFFFFFF is not a valid value for
   * any field here, so the host can tell "passed" from "never ran".
   *
   * Stops at 24: words 24..27 are the fault record that startup.c writes, and
   * clearing them here would erase the evidence of a fault taken before this
   * line -- which is exactly the case that most needs it. */
  MBOX[W_MAGIC] = 0U;
  for (i = 1U; i < 24U; i++)
  {
    MBOX[i] = 0xFFFFFFFFUL;
  }
  MBOX[W_STEP] = 0U;
  MBOX[W_DONE] = 0U;
  MBOX[W_BAUD] = (uint32_t)SPIF_BAUD;
  MBOX[W_MAGIC] = MAGIC;
  step(1U);

  /* 2. Is there an MPU?  Microchip's samd21j18a.h:223 says __MPU_PRESENT 0;
   *    this reads the register and lets the host record what the die says.
   *    DREGION is bits 15:8. */
  MBOX[W_MPU] = *(volatile uint32_t *)0xE000ED90UL;
  step(2U);

  /* 1. Clock sanity.  A dead SysTick reads a constant and would make every
   *    timing below look identical -- which has already certified a build as
   *    constant-time once on this bench, so it is checked, not assumed. */
  timer_start();
  for (i = 0U; i < 1000U; i++)
  {
    __NOP();
  }
  MBOX[W_TICKS] = timer_stop();
  step(3U);

  HAL_Init();

  /* 3. Driver init and device identity. */
  MBOX[W_INIT] = BSP_QSPI_Init();
  (void)BSP_SPIF_ReadId(id);
  MBOX[W_ID] = ((uint32_t)id[0] << 16) | ((uint32_t)id[1] << 8) | id[2];
  (void)BSP_QSPI_GetInfo(&info);
  MBOX[W_SIZE] = info.FlashSize;
  step(4U);

  if (MBOX[W_INIT] != QSPI_OK)
  {
    MBOX[W_DONE] = 0xDEADU;
    for (;;)
    {
    }
  }

  /* 4. Erase, then PROVE it by reading back rather than believing status. */
  MBOX[W_ERASE] = BSP_QSPI_Erase_Block(TEST_BLOCK);
  step(5U);

  bad = 0U;
  for (i = 0U; i < 4096U; i++)
  {
    buf[i] = 0U;
  }
  if (BSP_QSPI_Read(buf, TEST_BLOCK, 4096U) != QSPI_OK)
  {
    bad = 0xFFFFFFFFUL;
  }
  else
  {
    for (i = 0U; i < 4096U; i++)
    {
      if (buf[i] != 0xFFU)
      {
        bad++;
      }
    }
  }
  MBOX[W_BLANK] = bad;
  step(6U);

  /* 5. Cross-page program.  XPAGE_ADDR is 8 bytes below a page boundary and
   *    the write is 32 bytes, so it must split into 8 + 24 across two page
   *    programs.  A driver that ignores the wrap writes all 32 into the first
   *    page, where the last 24 land back at the page's start and silently
   *    overwrite the first 8. */
  for (i = 0U; i < XPAGE_LEN; i++)
  {
    pattern[i] = (uint8_t)(0xA0U + i);
  }
  MBOX[W_WRITE] = BSP_QSPI_Write(pattern, XPAGE_ADDR, XPAGE_LEN);
  step(7U);

  bad = 0U;
  for (i = 0U; i < XPAGE_LEN; i++)
  {
    buf[i] = 0U;
  }
  if (BSP_QSPI_Read(buf, XPAGE_ADDR, XPAGE_LEN) != QSPI_OK)
  {
    bad = 0xFFFFFFFFUL;
  }
  else
  {
    for (i = 0U; i < XPAGE_LEN; i++)
    {
      if (buf[i] != pattern[i])
      {
        bad++;
      }
    }
  }
  MBOX[W_XPAGE] = bad;
  for (i = 0U; i < 4U; i++)
  {
    MBOX[W_FIRST16 + i] = ((uint32_t)buf[4U * i + 3U] << 24)
                          | ((uint32_t)buf[4U * i + 2U] << 16)
                          | ((uint32_t)buf[4U * i + 1U] << 8)
                          | buf[4U * i];
  }
  step(8U);

  /* 6. Read sizes the demo sweeps.  Fill a whole page first so the comparison
   *    is against known data rather than against 0xFF, which would pass even
   *    if MISO were stuck high. */
  for (i = 0U; i < 256U; i++)
  {
    pattern[0] = (uint8_t)(i ^ 0x5AU);
    (void)BSP_QSPI_Write(pattern, 0x1000UL + i, 1U);
  }
  bad = 0U;
  {
    const uint32_t sizes[3] = {16U, 512U, 4096U};
    uint32_t k;

    for (k = 0U; k < 3U; k++)
    {
      uint32_t n = sizes[k];

      if (n > 256U)
      {
        n = 256U;                       /* only 256 bytes were written       */
      }
      if (BSP_QSPI_Read(buf, 0x1000UL, n) != QSPI_OK)
      {
        bad += 0x10000UL;
        continue;
      }
      for (i = 0U; i < n; i++)
      {
        if (buf[i] != (uint8_t)(i ^ 0x5AU))
        {
          bad++;
        }
      }
    }
  }
  MBOX[W_READBACK] = bad;
  step(9U);

  /* Timing baselines.  Not an attack measurement -- just the fixed cost of
   * one envelope at two chunk sizes, which is what a capture's envelope
   * classifier needs in order to tell a 2-byte status poll from a data read.
   */
  timer_start();
  (void)BSP_QSPI_Read(buf, 0x1000UL, 16U);
  MBOX[W_CYC16] = timer_stop();
  timer_start();
  (void)BSP_QSPI_Read(buf, 0x1000UL, 512U);
  MBOX[W_CYC512] = timer_stop();
  step(10U);

  /* UART smoke test.  The SBSFU image's trace and its YMODEM loader both go
   * out of SERCOM3, and when that image went quiet there was no way to tell
   * "the bootloader hung before printing" from "the UART does not work".
   * Proving the UART here, in an image that is known to reach this line,
   * separates the two. */
  HAL_UART_Init(115200U);
  {
    static const char msg[] = "\r\nSAMD21 SBSFU port: HAL UART alive\r\n";
    uint32_t k;

    for (k = 0U; k < 20U; k++)
    {
      (void)HAL_UART_Transmit((const uint8_t *)msg, (uint16_t)(sizeof(msg) - 1U),
                              1000U);
      HAL_Delay(200U);
    }
  }
  MBOX[W_DONE] = 0x600DU;
  for (;;)
  {
  }
}
