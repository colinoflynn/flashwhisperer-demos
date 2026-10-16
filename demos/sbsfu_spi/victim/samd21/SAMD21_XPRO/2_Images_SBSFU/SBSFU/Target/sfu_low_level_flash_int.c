/**
  ******************************************************************************
  * @file    sfu_low_level_flash_int.c
  * @brief   Internal (on-chip NVM) flash interface, SAM D21 Xplained Pro.
  *
  * The SAM D21's NVM controller, in the shape ST's SFU_LL_FLASH_INT_* API
  * expects.  Three asymmetries drive everything here, and none of them is
  * shared with the STM32L4 this was ported from:
  *
  *   ERASE is a 256-byte ROW        (NVMCTRL_ROW_SIZE,  CMD_ER)
  *   WRITE is a  64-byte PAGE       (NVMCTRL_PAGE_SIZE, CMD_WP)
  *   the page buffer is loaded by 16- or 32-bit stores to the flash address
  *     itself -- an 8-bit store is DISCARDED by the controller, silently
  *
  * The last one is why every write path below works in 32-bit words and
  * handles unaligned head and tail bytes by read-modify-write of the
  * surrounding word rather than by storing bytes.  A byte-wise memcpy into
  * flash on this part compiles, runs, reports success and writes nothing.
  ******************************************************************************
  */
#include "sfu_low_level_flash_int.h"
#include "samd21_hal.h"
#include "samd21.h"

#define NVM_CMD(c)   ((uint16_t)(NVMCTRL_CTRLA_CMDEX_KEY | NVMCTRL_CTRLA_CMD(c)))

/* NVMCTRL.ADDR is a HALF-WORD address: bits 21:0 index 16-bit units, not
 * bytes.  Writing a byte address there erases something 2x further up the
 * array than intended, which on a bootloader means erasing the slot after the
 * one asked for. */
#define NVM_ADDR_OF(byte_addr)   ((uint32_t)(byte_addr) >> 1)

static void nvm_wait(void)
{
  while (NVMCTRL->INTFLAG.bit.READY == 0U)
  {
  }
}

/** Latch and clear the controller's sticky error bits.  Returns non-zero if
  * any error was pending, which is the only way this peripheral reports a
  * failed program or a write into a locked region -- the command itself
  * always "succeeds". */
static uint32_t nvm_take_error(void)
{
  uint32_t s = NVMCTRL->STATUS.reg;
  uint32_t bad = s & (NVMCTRL_STATUS_PROGE | NVMCTRL_STATUS_LOCKE
                      | NVMCTRL_STATUS_NVME);

  if (bad != 0U)
  {
    NVMCTRL->STATUS.reg = (uint16_t)bad;                 /* write-1-to-clear */
  }
  return bad;
}

SFU_ErrorStatus SFU_LL_FLASH_INT_Init(void)
{
  /* MANW = 1: a page is committed only by an explicit CMD_WP.  With MANW
   * clear the controller writes the page automatically as soon as the last
   * word of the buffer is loaded, which makes the commit point depend on
   * where in a page a transfer happens to end -- fine for a bulk copy, not
   * fine for a bootloader that must know exactly when a trailer tag becomes
   * visible. */
  NVMCTRL->CTRLB.reg |= NVMCTRL_CTRLB_MANW;
  nvm_wait();
  (void)nvm_take_error();
  return SFU_SUCCESS;
}

/* ----------------------------------------------------------------- erase -- */

SFU_ErrorStatus SFU_LL_FLASH_INT_Erase_Size(SFU_FLASH_StatusTypeDef *pFlashStatus,
                                            uint8_t *pStart, uint32_t Length)
{
  uint32_t addr = (uint32_t)pStart;
  uint32_t end;

  *pFlashStatus = SFU_FLASH_SUCCESS;

  if (Length == 0U)
  {
    return SFU_SUCCESS;
  }

  /* Refuse a misaligned start rather than rounding it down.  Rounding would
   * erase the row BELOW the caller's buffer -- 255 bytes of whatever lives
   * there -- and report success.  See the IS_ALIGNED note in the header:
   * ST's macro silently means the wrong size on this part, so this check is
   * duplicated here rather than left to callers. */
  if (!IS_ALIGNED(addr))
  {
    *pFlashStatus = SFU_FLASH_ERR_ERASE;
    return SFU_ERROR;
  }

  end = addr + Length;
  while (addr < end)
  {
    nvm_wait();
    NVMCTRL->ADDR.reg = NVM_ADDR_OF(addr);
    NVMCTRL->CTRLA.reg = NVM_CMD(NVMCTRL_CTRLA_CMD_ER_Val);
    nvm_wait();
    if (nvm_take_error() != 0U)
    {
      *pFlashStatus = SFU_FLASH_ERR_ERASE;
      return SFU_ERROR;
    }
    addr += SFU_SAMD21_ERASE_SIZE;

    HAL_WDT_Refresh();
  }
  return SFU_SUCCESS;
}

/* ----------------------------------------------------------------- write -- */

/** Load one 32-bit word into the page buffer at a word-aligned address. */
static void buf_word(uint32_t word_addr, uint32_t value)
{
  *(volatile uint32_t *)word_addr = value;
}

/** Commit whatever the page buffer holds to the page containing `addr`. */
static uint32_t commit_page(uint32_t addr)
{
  nvm_wait();
  NVMCTRL->ADDR.reg = NVM_ADDR_OF(addr);
  NVMCTRL->CTRLA.reg = NVM_CMD(NVMCTRL_CTRLA_CMD_WP_Val);
  nvm_wait();
  return nvm_take_error();
}

SFU_ErrorStatus SFU_LL_FLASH_INT_Write(SFU_FLASH_StatusTypeDef *pFlashStatus,
                                       uint8_t *pDestination,
                                       const uint8_t *pSource, uint32_t Length)
{
  uint32_t dst = (uint32_t)pDestination;
  uint32_t done = 0U;

  *pFlashStatus = SFU_FLASH_SUCCESS;

  if (Length == 0U)
  {
    return SFU_SUCCESS;
  }
  /* SBSFU always writes in SFU_LL_FLASH_write_t units -- AtomicWrite, the
   * trailer, and the header are all word-multiples -- so a misaligned or
   * odd-length request means a caller has gone wrong, not that this driver
   * should paper over it by read-modify-writing a word it was not asked to
   * touch. */
  if (((dst % sizeof(SFU_LL_FLASH_write_t)) != 0U)
      || ((Length % sizeof(SFU_LL_FLASH_write_t)) != 0U))
  {
    *pFlashStatus = SFU_FLASH_ERR_WRITING;
    return SFU_ERROR;
  }

  while (done < Length)
  {
    uint32_t addr = dst + done;
    uint32_t page_end = (addr | (SFU_SAMD21_WRITE_SIZE - 1U)) + 1U;
    uint32_t n = Length - done;

    if (n > (page_end - addr))
    {
      n = page_end - addr;              /* never straddle a page commit      */
    }

    /* Clear the buffer first: it holds the previous page's residue, and the
     * bytes of this page we are NOT writing must go in as 0xFF so that
     * programming leaves them alone. */
    nvm_wait();
    NVMCTRL->CTRLA.reg = NVM_CMD(NVMCTRL_CTRLA_CMD_PBC_Val);
    nvm_wait();

    {
      uint32_t i;

      for (i = 0U; i < n; i += 4U)
      {
        uint32_t w;

        /* pSource is a uint8_t* and SBSFU does pass odd alignments for it
         * (the header is memcpy'd out of a packed struct), so the word is
         * assembled byte-wise rather than dereferenced as a uint32_t*. */
        w = (uint32_t)pSource[done + i]
            | ((uint32_t)pSource[done + i + 1U] << 8)
            | ((uint32_t)pSource[done + i + 2U] << 16)
            | ((uint32_t)pSource[done + i + 3U] << 24);
        buf_word(addr + i, w);
      }
    }

    if (commit_page(addr) != 0U)
    {
      *pFlashStatus = SFU_FLASH_ERR_WRITING;
      return SFU_ERROR;
    }

    /* Read back.  The NVM controller reports a program error only for gross
     * failures -- a locked region, a bus fault -- and will happily "program"
     * a bit from 0 to 1 by doing nothing at all and raising no flag.  For a
     * bootloader writing its own slot metadata that is the difference
     * between a failed update and a bricked device. */
    {
      uint32_t i;

      for (i = 0U; i < n; i++)
      {
        if (*(volatile uint8_t *)(addr + i) != pSource[done + i])
        {
          *pFlashStatus = SFU_FLASH_ERR_WRITINGCTRL;
          return SFU_ERROR;
        }
      }
    }

    done += n;
    HAL_WDT_Refresh();
  }
  return SFU_SUCCESS;
}

/* ------------------------------------------------------------ read/compare -- */

SFU_ErrorStatus SFU_LL_FLASH_INT_Read(uint8_t *pDestination,
                                      const uint8_t *pSource, uint32_t Length)
{
  uint32_t i;

  /* The on-chip array is directly addressable, so this is a copy -- and it is
   * deliberately a byte loop rather than memcpy.  memcpy on this toolchain
   * widens to word accesses when it can prove alignment, and this project
   * cares about which flash rows a read touches: a widened copy changes the
   * access pattern the NVM cache sees.  Nothing here is timed, but the
   * habit is cheap and the surprise would not be. */
  for (i = 0U; i < Length; i++)
  {
    pDestination[i] = pSource[i];
  }
  return SFU_SUCCESS;
}

SFU_ErrorStatus SFU_LL_FLASH_INT_Compare(const uint8_t *pFlash,
                                         const uint32_t Pattern1,
                                         const uint32_t Pattern2,
                                         uint32_t Length)
{
  const uint32_t *p = (const uint32_t *)(const void *)pFlash;
  uint32_t i;

  for (i = 0U; i < (Length / 4U); i++)
  {
    if ((p[i] != Pattern1) && (p[i] != Pattern2))
    {
      return SFU_ERROR;
    }
  }
  return SFU_SUCCESS;
}

/* ------------------------------------------------------------- geometry -- */

uint32_t SFU_LL_FLASH_INT_GetPage(uint32_t Addr)
{
  /* "Page" in ST's sense is the ERASE unit, so this counts rows.  Returning
   * NVMCTRL pages here would give a number four times too large and ST's
   * callers use it for erase arithmetic. */
  if (Addr >= FLASH_SIZE)
  {
    return INVALID_PAGE;
  }
  return Addr / SFU_SAMD21_ERASE_SIZE;
}

uint32_t SFU_LL_FLASH_INT_GetBank(uint32_t Addr)
{
  /* One array, no dual-bank mode, no bank swap.  ST's L4 port uses this to
   * decide which bank an address lives in for dual-bank erase; there is
   * nothing to decide here. */
  if (Addr >= FLASH_SIZE)
  {
    return INVALID_BANK;
  }
  return 0U;
}
