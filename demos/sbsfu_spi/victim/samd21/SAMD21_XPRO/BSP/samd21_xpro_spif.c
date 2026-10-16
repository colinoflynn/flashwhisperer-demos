/**
  ******************************************************************************
  * @file    samd21_xpro_spif.c
  * @brief   AT25DF081A on SERCOM5, SAM D21 Xplained Pro.
  *
  * See samd21_xpro_spif.h for why these functions carry ST's BSP_QSPI_* names.
  *
  * WIRING, from the SAM D21 Xplained Pro user guide (Atmel-42220B, 04/2016)
  * Table 4-8, and re-confirmed on this board by reading the JEDEC ID through
  * these very pins:
  *
  *     PA13  GPIO, software-driven   -> #CS      (also EXT3 pin 8 once R313 is
  *                                                populated -- that is the
  *                                                attacker's tap, and it does
  *                                                not change this driver)
  *     PB22  SERCOM5 PAD[2], mux D   -> SI  (MOSI)
  *     PB23  SERCOM5 PAD[3], mux D   -> SCK
  *     PB16  SERCOM5 PAD[0], mux C   -> SO  (MISO)
  *
  * The pad assignment forces DOPO = 0x1 (DO on PAD[2], SCK on PAD[3]) and
  * DIPO = 0x0 (DI on PAD[0]).  SS would be PAD[1] under DOPO = 0x1, but
  * MSSEN stays 0 and chip-select is a plain GPIO -- which is not a
  * simplification, it is what the board requires, because #CS is on PA13 and
  * PA13 is not a SERCOM pad at all.
  *
  * THAT DETAIL IS THE WHOLE ATTACK.  Because chip-select is software-driven,
  * the envelope around each read is produced by THIS CODE, not by a
  * peripheral's automatic framing -- so CS falls when the driver says so and
  * rises when the driver says so, with the cipher running in between.  Both
  * delimiters the attacker times are edges the victim's own C produces.
  *
  * ONE CHIP-SELECT ENVELOPE PER READ.  BSP_QSPI_Read asserts CS, sends the
  * opcode and address, clocks out the whole Size, and releases CS.  It does
  * not split a long read, and it does not hold CS across reads.  Matching
  * shipped drivers -- wolfBoot src/spi_flash.c:259, Gecko
  * btl_storage_spiflash.c:482 -- is deliberate: a driver that framed
  * differently would make this rig measure something no product does.
  ******************************************************************************
  */
#include "samd21_xpro_spif.h"

#include "samd21.h"
#include "samd21_hal.h"

/* ------------------------------------------------------------------ pins -- */
#define SPIF_CS_GROUP     0U                 /* PORTA */
#define SPIF_CS_PIN       13U                /* PA13                          */
#define SPIF_MISO_PIN     16U                /* PB16, SERCOM5 PAD[0], mux C   */
#define SPIF_MOSI_PIN     22U                /* PB22, SERCOM5 PAD[2], mux D   */
#define SPIF_SCK_PIN      23U                /* PB23, SERCOM5 PAD[3], mux D   */
#define SPIF_PORTB        1U

#define MUX_C             2U
#define MUX_D             3U

#define SPIF_DOPO         1U                 /* DO=PAD[2], SCK=PAD[3]         */
#define SPIF_DIPO         0U                 /* DI=PAD[0]                     */

/* ------------------------------------------------------------- AT25DF081A -- */
#define CMD_READ_ARRAY_LF   0x03U   /* opcode + 24-bit address, no dummy byte  */
#define CMD_PAGE_PROGRAM    0x02U
#define CMD_BLOCK_ERASE_4K  0x20U
#define CMD_BLOCK_ERASE_64K 0xD8U
#define CMD_CHIP_ERASE      0x60U
#define CMD_WRITE_ENABLE    0x06U
#define CMD_READ_STATUS     0x05U
#define CMD_WRITE_STATUS    0x01U
#define CMD_READ_ID         0x9FU

#define STATUS_BUSY         0x01U   /* RDY/#BSY: 1 = an internal op is running */
#define STATUS_WEL          0x02U   /* write enable latch                      */
#define STATUS_SWP_MASK     0x0CU   /* software protection status              */

/* Erase and program are slow enough that a spin needs a bound.  AT25DF081A
 * datasheet worst cases: chip erase 24 s, 64 KB block erase 1.2 s, page
 * program 5 ms.  These are loop counts, not milliseconds -- the driver runs
 * before any tick source is guaranteed, so it cannot use one. */
#define SPIN_LIMIT_ERASE    (40000000UL)
#define SPIN_LIMIT_PROGRAM  (2000000UL)

static uint8_t spif_ready;

/* Bus-transaction counters.
 *
 * WIRING.md section 5 makes "count the envelopes" a precondition for
 * trusting a capture: a verify pass over S bytes at chunk K must produce
 * exactly ceil(S/K) data envelopes, and anything else means the capture
 * dropped edges or the image is not the length the host thinks.  These are
 * the target's side of that check -- the number the F303's edge count has to
 * agree with.
 *
 * They also answer a question that comes first: whether the decrypt loop
 * runs AT ALL.  SBSFU's install can fail for several reasons and the trace
 * does not say whether VerifyFwSignatureBeforeDecrypt completed before it
 * did.  A read count of ceil(FwSize/chunk) says it did.
 *
 * Separate counters for data reads and status polls, because they are
 * separate envelopes on the wire and the classifier has to tell them apart:
 * SFU_LL_FLASH_EXT_Read polls BSP_QSPI_GetStatus before EVERY data read, so
 * the bus carries twice as many envelopes as there are chunks.
 *
 * They live in .noinit, NOT in .bss, because SBSFU reboots when an install
 * fails and .bss is cleared on the way back in.  Counters that reset with
 * the thing they are counting report zero every time.  main() prints them
 * at the top of each boot -- so what you read is the PREVIOUS boot's pass --
 * and clears them afterwards. */
__attribute__((section(".noinit"))) volatile uint32_t g_spif_reads;
__attribute__((section(".noinit"))) volatile uint32_t g_spif_read_bytes;
__attribute__((section(".noinit"))) volatile uint32_t g_spif_status_polls;
__attribute__((section(".noinit"))) volatile uint32_t g_spif_writes;
__attribute__((section(".noinit"))) volatile uint32_t g_spif_erases;
__attribute__((section(".noinit"))) volatile uint32_t g_spif_reject;
__attribute__((section(".noinit"))) volatile uint32_t g_spif_reject_addr;
__attribute__((section(".noinit"))) volatile uint32_t g_spif_reject_size;

/* ------------------------------------------------------------- primitives -- */

static inline void cs_low(void)
{
  PORT->Group[SPIF_CS_GROUP].OUTCLR.reg = (1UL << SPIF_CS_PIN);
}

static inline void cs_high(void)
{
  PORT->Group[SPIF_CS_GROUP].OUTSET.reg = (1UL << SPIF_CS_PIN);
}

/** Full-duplex byte.  SPI has no half-duplex: every byte clocked out clocks
  * one in, so a "send" discards the input and a "read" sends a dummy. */
static uint8_t xfer(uint8_t out)
{
  while ((SERCOM5->SPI.INTFLAG.reg & SERCOM_SPI_INTFLAG_DRE) == 0U)
  {
  }
  SERCOM5->SPI.DATA.reg = out;
  while ((SERCOM5->SPI.INTFLAG.reg & SERCOM_SPI_INTFLAG_RXC) == 0U)
  {
  }
  return (uint8_t)SERCOM5->SPI.DATA.reg;
}

static void send_cmd_addr(uint8_t cmd, uint32_t addr)
{
  (void)xfer(cmd);
  (void)xfer((uint8_t)(addr >> 16));
  (void)xfer((uint8_t)(addr >> 8));
  (void)xfer((uint8_t)addr);
}

static uint8_t read_status(void)
{
  uint8_t s;
  g_spif_status_polls++;
  cs_low();
  (void)xfer(CMD_READ_STATUS);
  s = xfer(0xFFU);
  cs_high();
  return s;
}

static void write_enable(void)
{
  cs_low();
  (void)xfer(CMD_WRITE_ENABLE);
  cs_high();
}

static uint8_t wait_ready(uint32_t limit)
{
  while (limit-- != 0U)
  {
    if ((read_status() & STATUS_BUSY) == 0U)
    {
      return QSPI_OK;
    }
  }
  return QSPI_BUSY;
}

/* ------------------------------------------------------------------ init -- */

static void pins_init(void)
{
  PortGroup *pa = &PORT->Group[SPIF_CS_GROUP];
  PortGroup *pb = &PORT->Group[SPIF_PORTB];

  /* #CS first, and HIGH BEFORE it becomes an output.  Driving the pin as an
   * output while OUT still reads 0 would assert chip-select for as long as it
   * takes to set it, and a spurious falling edge here is a spurious envelope
   * in the attacker's capture -- and, worse, half a command to the flash. */
  pa->OUTSET.reg = (1UL << SPIF_CS_PIN);
  pa->PINCFG[SPIF_CS_PIN].reg = 0U;                 /* no pmux, no pull      */
  pa->DIRSET.reg = (1UL << SPIF_CS_PIN);

  /* SERCOM5 pads.  PMUXEN plus the per-pin nibble; odd pins take the high
   * nibble of PMUX[pin/2]. */
  pb->PINCFG[SPIF_MISO_PIN].reg = PORT_PINCFG_PMUXEN | PORT_PINCFG_INEN;
  pb->PMUX[SPIF_MISO_PIN / 2].bit.PMUXE = MUX_C;    /* PB16 is even          */
  pb->PINCFG[SPIF_MOSI_PIN].reg = PORT_PINCFG_PMUXEN;
  pb->PMUX[SPIF_MOSI_PIN / 2].bit.PMUXE = MUX_D;    /* PB22 is even          */
  pb->PINCFG[SPIF_SCK_PIN].reg = PORT_PINCFG_PMUXEN;
  pb->PMUX[SPIF_SCK_PIN / 2].bit.PMUXO = MUX_D;     /* PB23 is odd           */
}

static void sercom5_init(void)
{
  /* APB clock, then a generic clock on the core.  Both are required; with
   * only one the peripheral's registers read back as written and nothing
   * ever shifts, which is a particularly quiet way to fail. */
  PM->APBCMASK.reg |= PM_APBCMASK_SERCOM5;
  GCLK->CLKCTRL.reg = (uint16_t)(GCLK_CLKCTRL_ID_SERCOM5_CORE
                                 | GCLK_CLKCTRL_GEN(SPIF_GCLK_GEN)
                                 | GCLK_CLKCTRL_CLKEN);
  while ((GCLK->STATUS.reg & GCLK_STATUS_SYNCBUSY) != 0U)
  {
  }

  SERCOM5->SPI.CTRLA.reg = SERCOM_SPI_CTRLA_SWRST;
  while ((SERCOM5->SPI.SYNCBUSY.reg & SERCOM_SPI_SYNCBUSY_SWRST) != 0U)
  {
  }

  /* SPI mode 0 (CPOL = 0, CPHA = 0), MSB first, 8-bit.  CPOL/CPHA are left at
   * their reset zeroes rather than written, because the AT25DF081A supports
   * modes 0 and 3 only and mode 0 is what the reset state already is. */
  SERCOM5->SPI.CTRLA.reg = SERCOM_SPI_CTRLA_MODE_SPI_MASTER
                           | SERCOM_SPI_CTRLA_DOPO(SPIF_DOPO)
                           | SERCOM_SPI_CTRLA_DIPO(SPIF_DIPO);
  SERCOM5->SPI.CTRLB.reg = SERCOM_SPI_CTRLB_RXEN;
  while ((SERCOM5->SPI.SYNCBUSY.reg & SERCOM_SPI_SYNCBUSY_CTRLB) != 0U)
  {
  }

  /* f_SCK = f_ref / (2 * (BAUD + 1)).  SPIF_BAUD is computed in the header of
   * samd21_hal.h from the generic clock actually running, so changing the CPU
   * clock axis does not silently change the bus rate -- which would move the
   * fixed part of every interval the attacker measures. */
  SERCOM5->SPI.BAUD.reg = (uint8_t)SPIF_BAUD;

  SERCOM5->SPI.CTRLA.reg |= SERCOM_SPI_CTRLA_ENABLE;
  while ((SERCOM5->SPI.SYNCBUSY.reg & SERCOM_SPI_SYNCBUSY_ENABLE) != 0U)
  {
  }
}

uint8_t BSP_SPIF_ReadId(uint8_t id[3])
{
  cs_low();
  (void)xfer(CMD_READ_ID);
  id[0] = xfer(0xFFU);
  id[1] = xfer(0xFFU);
  id[2] = xfer(0xFFU);
  cs_high();
  return QSPI_OK;
}

uint8_t BSP_QSPI_Init(void)
{
  uint8_t id[3];

  pins_init();
  sercom5_init();

  /* Prove the chip is there before claiming success.  An all-zero or all-ones
   * ID is what an absent, unpowered or mis-wired part returns, and a
   * bootloader that reports a good init against a dead bus would go on to
   * "verify" a slot full of 0xFF. */
  (void)BSP_SPIF_ReadId(id);
  if ((id[0] == 0x00U) || (id[0] == 0xFFU))
  {
    spif_ready = 0U;
    return QSPI_ERROR;
  }

  /* The AT25DF081A powers up with every sector SOFTWARE PROTECTED -- section
   * "Protection Commands and Features" of the datasheet -- so a program or
   * erase issued now would be accepted, do nothing, and clear WEL.  Global
   * Unprotect is write-enable followed by writing 0x00 to status byte 1.
   *
   * This is needed for the loader path that STAGES an image.  The verify pass
   * the attack targets is read-only and would work without it; doing it here
   * keeps the failure at init rather than three minutes into a YMODEM
   * transfer. */
  write_enable();
  cs_low();
  (void)xfer(CMD_WRITE_STATUS);
  (void)xfer(0x00U);
  cs_high();
  if ((read_status() & STATUS_SWP_MASK) != 0U)
  {
    spif_ready = 0U;
    return QSPI_ERROR;
  }

  spif_ready = 1U;
  /* The reject record lives in .noinit so it survives the reset that
     a failed install causes -- which also means an UNSET one reads as
     whatever was in SRAM.  0x00000009 looked like a plausible reason
     code for a whole debugging round before the 0x80000000 marker
     showed it was never written at all.  Clear it once the driver is
     up, so "no reject recorded" is distinguishable from garbage. */
  g_spif_reject = 0U;
  g_spif_reject_addr = 0U;
  g_spif_reject_size = 0U;
  return QSPI_OK;
}

uint8_t BSP_QSPI_DeInit(void)
{
  SERCOM5->SPI.CTRLA.reg &= ~(uint32_t)SERCOM_SPI_CTRLA_ENABLE;
  while ((SERCOM5->SPI.SYNCBUSY.reg & SERCOM_SPI_SYNCBUSY_ENABLE) != 0U)
  {
  }
  spif_ready = 0U;
  return QSPI_OK;
}

/* ------------------------------------------------------------------ read -- */

uint8_t BSP_QSPI_Read(uint8_t *pData, uint32_t ReadAddr, uint32_t Size)
{
  uint32_t i;

  if ((spif_ready == 0U) || (pData == 0) ||
      ((ReadAddr + Size) > SPIF_FLASH_SIZE))
  {
    /* Record WHY, not just that.  A rejected read returns the same
     * QSPI_ERROR for three different reasons, and ST's caller turns all of
     * them into one SFU_ERROR, which its caller turns into "Fw signature
     * check error".  By the time it reaches the trace the cause is four
     * layers away from the symptom -- this port spent a long evening on
     * exactly that chain. */
    g_spif_reject = 0x80000000UL
                    | ((spif_ready == 0U) ? 1UL : 0UL)
                    | ((pData == 0) ? 2UL : 0UL)
                    | (((ReadAddr + Size) > SPIF_FLASH_SIZE) ? 4UL : 0UL);
    g_spif_reject_addr = ReadAddr;
    g_spif_reject_size = Size;
    return QSPI_ERROR;
  }

  g_spif_reads++;
  g_spif_read_bytes += Size;

  /* THE ENVELOPE THE ATTACK TIMES STARTS HERE AND ENDS AT cs_high(). */
  cs_low();
  send_cmd_addr(CMD_READ_ARRAY_LF, ReadAddr);
  for (i = 0U; i < Size; i++)
  {
    pData[i] = xfer(0xFFU);
  }
  cs_high();

  return QSPI_OK;
}

/* ----------------------------------------------------------------- write -- */

uint8_t BSP_QSPI_Write(uint8_t *pData, uint32_t WriteAddr, uint32_t Size)
{
  uint32_t done = 0U;

  if ((spif_ready == 0U) || (pData == 0) ||
      ((WriteAddr + Size) > SPIF_FLASH_SIZE))
  {
    return QSPI_ERROR;
  }

  while (done < Size)
  {
    /* A page program wraps at the 256-byte page boundary instead of carrying
     * into the next page, so the first chunk is short whenever WriteAddr is
     * not page-aligned.  Getting this wrong corrupts the START of the image
     * and shows up as an authentication failure a long way from the cause. */
    uint32_t addr = WriteAddr + done;
    uint32_t room = SPIF_PAGE_SIZE - (addr % SPIF_PAGE_SIZE);
    uint32_t n = Size - done;
    uint32_t i;

    if (n > room)
    {
      n = room;
    }

    g_spif_writes++;
    write_enable();
    cs_low();
    send_cmd_addr(CMD_PAGE_PROGRAM, addr);
    for (i = 0U; i < n; i++)
    {
      (void)xfer(pData[done + i]);
    }
    cs_high();

    if (wait_ready(SPIN_LIMIT_PROGRAM) != QSPI_OK)
    {
      return QSPI_BUSY;
    }
    done += n;
  }
  return QSPI_OK;
}

/* ----------------------------------------------------------------- erase -- */

static uint8_t erase(uint8_t cmd, uint32_t addr, uint32_t limit)
{
  if (spif_ready == 0U)
  {
    return QSPI_ERROR;
  }
  g_spif_erases++;
  write_enable();
  cs_low();
  send_cmd_addr(cmd, addr);
  cs_high();
  return wait_ready(limit);
}

uint8_t BSP_QSPI_Erase_Block(uint32_t BlockAddress)
{
  /* ST's sfu_low_level_flash_ext.c erases in 64 KB units (ERASE_BLOC_SIZE
   * 0x10000) and the AT25DF081A's 0xD8 is a 64 KB block erase, so the unit
   * matches and that file needs no change here either. */
  return erase(CMD_BLOCK_ERASE_64K, BlockAddress, SPIN_LIMIT_ERASE);
}

uint8_t BSP_QSPI_Erase_Sector(uint32_t Sector)
{
  return erase(CMD_BLOCK_ERASE_4K, Sector * SPIF_SECTOR_SIZE,
               SPIN_LIMIT_ERASE);
}

uint8_t BSP_QSPI_Erase_Chip(void)
{
  if (spif_ready == 0U)
  {
    return QSPI_ERROR;
  }
  write_enable();
  cs_low();
  (void)xfer(CMD_CHIP_ERASE);
  cs_high();
  return wait_ready(SPIN_LIMIT_ERASE);
}

/* ---------------------------------------------------------------- status -- */

uint8_t BSP_QSPI_GetStatus(void)
{
  if (spif_ready == 0U)
  {
    return QSPI_ERROR;
  }
  return ((read_status() & STATUS_BUSY) != 0U) ? QSPI_BUSY : QSPI_OK;
}

uint8_t BSP_QSPI_GetInfo(QSPI_Info *pInfo)
{
  if (pInfo == 0)
  {
    return QSPI_ERROR;
  }
  pInfo->FlashSize = SPIF_FLASH_SIZE;
  pInfo->EraseSectorSize = SPIF_SECTOR_SIZE;
  pInfo->EraseSectorsNumber = SPIF_FLASH_SIZE / SPIF_SECTOR_SIZE;
  pInfo->ProgPageSize = SPIF_PAGE_SIZE;
  pInfo->ProgPagesNumber = SPIF_FLASH_SIZE / SPIF_PAGE_SIZE;
  return QSPI_OK;
}

uint8_t BSP_QSPI_EnableMemoryMappedMode(void)
{
  /* There is no such mode on this part: the SAM D21 has no external memory
   * bus and SERCOM is not a memory controller.  ST's
   * SFU_LL_FLASH_EXT_Config_Exe does not call this -- the ExtFlash project
   * does not execute from external flash either -- so returning
   * NOT_SUPPORTED is honest rather than limiting. */
  return QSPI_NOT_SUPPORTED;
}
