/**
  ******************************************************************************
  * @file    sfu_low_level_flash_int.c
  * @brief   Internal flash interface, NUCLEO-L152RE.
  *
  * Ported from ST's
  * Projects/B-L475E-IOT01A/.../SBSFU/Target/sfu_low_level_flash_int.c.
  * The exported behaviour is the same; three things underneath are not, and
  * all three are the silicon rather than a choice.  See the header for the
  * atomic write size and the erase granularity; the third is here:
  *
  * ST'S BANK-SPLIT LOOP IS GONE, AND NOTHING REPLACES IT.
  * ST's Erase_Size has an outer do/while whose whole job is to notice that a
  * range straddles the boundary between the L4's two flash banks, erase the
  * part in bank 1, then go round again for bank 2 -- because the L4's
  * FLASH_EraseInitTypeDef carries a `Banks` field that the erase is
  * programmed with.  THE L1'S ERASE DESCRIPTOR HAS NO BANK FIELD.  It is
  * {TypeErase, PageAddress, NbPages} with FLASH_TYPEERASE_PAGES the only
  * legal type, and PageAddress is an absolute address, so an erase that
  * crosses from 0x0803FFFF to 0x08040000 needs no special handling at all.
  *
  * The L152RE does have two banks -- FLASH_BANK2_BASE is 0x08040000, and
  * the active slot in this port's map starts at 0x08030000 and therefore
  * spans both -- so this is a case that will actually be exercised, not a
  * hypothetical one.  SFU_LL_FLASH_INT_GetBank is kept because ST's header
  * exports it, and it answers correctly, but nothing in the erase path
  * consults it any more.
  ******************************************************************************
  */

/* Includes ------------------------------------------------------------------*/
#include "main.h"
#include "sfu_low_level_flash_int.h"
#include "sfu_low_level_security.h"
#include "se_interface_bootloader.h"
#include "string.h"
#include "sfu_fwimg_regions.h"

/* Private defines -----------------------------------------------------------*/
/* ST's value, and it means something different here.  On the L4 a "page" is
 * 2048 bytes, so two pages between watchdog refreshes is 4 KB of erase; on
 * this part a page is 256 bytes, so the same number is 512 bytes and the
 * watchdog is refreshed eight times as often for a given range.  That is
 * the safe direction, and the erase itself is not slower for it -- the L1
 * erases a page at a time either way. */
#define NB_PAGE_SECTOR_PER_ERASE  2U    /*!< Nb page erased per erase */

/* Private function prototypes -----------------------------------------------*/
static SFU_ErrorStatus SFU_LL_FLASH_INT_Clear_Error(void);

/* Functions Definition ------------------------------------------------------*/

SFU_ErrorStatus SFU_LL_FLASH_INT_Init(void)
{
  return SFU_SUCCESS;
}

/**
  * @brief  This function does an erase of n (depends on Length) pages in user
  *         flash area
  * @param  pFlashStatus: SFU_FLASH Status pointer
  * @param  pStart: flash address to be erased
  * @param  Length: number of bytes
  * @retval SFU_ErrorStatus SFU_SUCCESS if successful, SFU_ERROR otherwise.
  */
SFU_ErrorStatus SFU_LL_FLASH_INT_Erase_Size(SFU_FLASH_StatusTypeDef *pFlashStatus, uint8_t *pStart, uint32_t Length)
{
  uint32_t page_error = 0U;
  uint32_t start = (uint32_t)pStart;
  FLASH_EraseInitTypeDef p_erase_init;
  SFU_ErrorStatus e_ret_status;
  uint32_t address;
  uint32_t nb_pages;
  uint32_t chunk_nb_pages;

  if (pFlashStatus == NULL)
  {
    return SFU_ERROR;
  }

  *pFlashStatus = SFU_FLASH_SUCCESS;

  /* Clear error flags raised during a previous operation */
  e_ret_status = SFU_LL_FLASH_INT_Clear_Error();
  if (e_ret_status != SFU_SUCCESS)
  {
    return e_ret_status;
  }

  if (HAL_FLASH_Unlock() != HAL_OK)
  {
    *pFlashStatus = SFU_FLASH_ERR_HAL;
    return SFU_ERROR;
  }

  /* Round the start DOWN to a page boundary and the end UP to one.  ST
   * does this implicitly by converting both ends to page numbers; doing it
   * in addresses here is the same arithmetic against an erase descriptor
   * that wants an address.  A caller that asks to erase one byte in the
   * middle of a page gets the whole page erased either way -- which is
   * what an erase means on NOR and what ST's callers expect. */
  address  = start - (start % FLASH_PAGE_SIZE);
  nb_pages = (((start + Length - 1U) - address) / FLASH_PAGE_SIZE) + 1U;

  p_erase_init.TypeErase = FLASH_TYPEERASE_PAGES;

  /* Erase NB_PAGE_SECTOR_PER_ERASE at a time, refreshing the watchdog
   * between batches.  ST's reason, and it is a real one here: the active
   * slot is 320 KB, which is 1 280 pages of 256 bytes. */
  do
  {
    chunk_nb_pages = (nb_pages >= NB_PAGE_SECTOR_PER_ERASE) ? NB_PAGE_SECTOR_PER_ERASE : nb_pages;
    p_erase_init.PageAddress = address;
    p_erase_init.NbPages     = chunk_nb_pages;
    address  += chunk_nb_pages * FLASH_PAGE_SIZE;
    nb_pages -= chunk_nb_pages;
    if (HAL_FLASHEx_Erase(&p_erase_init, &page_error) != HAL_OK)
    {
      e_ret_status = SFU_ERROR;
      *pFlashStatus = SFU_FLASH_ERR_ERASE;
    }
    SFU_LL_SECU_IWDG_Refresh(); /* calling this function which checks the compiler switch */
  } while (nb_pages > 0U);

  if (HAL_FLASH_Lock() != HAL_OK)
  {
    e_ret_status = SFU_ERROR;
    *pFlashStatus = SFU_FLASH_ERR_HAL;
  }

  return e_ret_status;
}

/**
  * @brief  This function writes a data buffer in flash (data are 32-bit aligned).
  * @note   After writing data buffer, the flash content is checked.
  * @param  pFlashStatus: FLASH_StatusTypeDef
  * @param  pDestination: Start address for target location. It has to be
  *         4 bytes aligned on this part, not 8 -- see the header.
  * @param  pSource: pointer on buffer with data to write
  * @param  Length: Length of data buffer in bytes. It has to be 4 bytes
  *         aligned.
  * @retval SFU_ErrorStatus SFU_SUCCESS if successful, SFU_ERROR otherwise.
  */
SFU_ErrorStatus SFU_LL_FLASH_INT_Write(SFU_FLASH_StatusTypeDef *pFlashStatus, uint8_t *pDestination,
                                       const uint8_t *pSource, uint32_t Length)
{
  SFU_ErrorStatus e_ret_status = SFU_SUCCESS;
  uint32_t i;
  uint32_t destination = (uint32_t)pDestination;

  if (pFlashStatus == NULL)
  {
    return SFU_ERROR;
  }
  *pFlashStatus = SFU_FLASH_SUCCESS;

  /* The alignment ST checks for a double word, checked for a word.  A
   * misaligned program on this part does not fail cleanly -- HAL_FLASH_Program
   * asserts in a debug build and writes to the rounded-down address in a
   * release one -- so it is rejected here rather than discovered later as
   * an image that will not authenticate. */
  if (((destination % sizeof(SFU_LL_FLASH_write_t)) != 0U) ||
      ((Length % sizeof(SFU_LL_FLASH_write_t)) != 0U))
  {
    *pFlashStatus = SFU_FLASH_ERR_HAL;
    return SFU_ERROR;
  }

  e_ret_status = SFU_LL_FLASH_INT_Clear_Error();
  if (e_ret_status != SFU_SUCCESS)
  {
    return e_ret_status;
  }

  if (HAL_FLASH_Unlock() != HAL_OK)
  {
    *pFlashStatus = SFU_FLASH_ERR_HAL;
    return SFU_ERROR;
  }

  for (i = 0U; i < Length; i += sizeof(SFU_LL_FLASH_write_t))
  {
    SFU_LL_FLASH_write_t value;

    /* memcpy rather than a cast-and-dereference: pSource is a uint8_t* and
     * ST's callers do NOT guarantee it is word aligned.  On a Cortex-M3 an
     * unaligned 32-bit load from a cast pointer is undefined behaviour that
     * happens to work, until the compiler notices the alignment it is
     * allowed to assume and emits an LDM. */
    (void)memcpy(&value, pSource + i, sizeof(value));

    if (HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD, destination + i, value) != HAL_OK)
    {
      e_ret_status = SFU_ERROR;
      *pFlashStatus = SFU_FLASH_ERR_WRITING;
      break;
    }

    /* Check the write, as ST does: a program that reports success and did
     * not take leaves an image that fails authentication much later and
     * for no visible reason. */
    if (memcmp((void *)(destination + i), &value, sizeof(value)) != 0)
    {
      e_ret_status = SFU_ERROR;
      *pFlashStatus = SFU_FLASH_ERR_WRITINGCTRL;
      break;
    }

    /* 320 KB of active slot is 81 920 word programs, and the L1 takes
     * about 4 ms per 128-byte half page or ~4 ms per word without it.  The
     * watchdog has to be fed inside this loop, not only around it. */
    SFU_LL_SECU_IWDG_Refresh();
  }

  if (HAL_FLASH_Lock() != HAL_OK)
  {
    e_ret_status = SFU_ERROR;
    *pFlashStatus = SFU_FLASH_ERR_HAL;
  }

  return e_ret_status;
}

/**
  * @brief  This function reads flash
  * @param  pDestination: Start address for target location
  * @param  pSource: flash address to read
  * @param  Length: number of bytes
  * @retval SFU_ErrorStatus SFU_SUCCESS if successful, SFU_ERROR otherwise.
  */
SFU_ErrorStatus SFU_LL_FLASH_INT_Read(uint8_t *pDestination, const uint8_t *pSource, uint32_t Length)
{
  SFU_ErrorStatus e_ret_status = SFU_ERROR;
  SE_ErrorStatus se_ret_status;
  SE_StatusTypeDef se_status;
  uint32_t i;
  uint32_t inside_header = 0U;
  uint32_t source = (uint32_t)pSource;

  /* Is the source area inside one of the firmware image headers?  ST's
   * logic, kept exactly: a header lives in the protected region on a part
   * that has one, so reading it has to go through the Secure Engine. */
  for (i = 0U; i < SFU_NB_MAX_ACTIVE_IMAGE; i++)
  {
    if ((source >= SlotHeaderAdd[SLOT_ACTIVE_1 + i]) &&
        ((source + Length) <= (SlotHeaderAdd[SLOT_ACTIVE_1 + i] + SFU_IMG_IMAGE_OFFSET)))
    {
      inside_header = 1U;
    }
  }

  if (inside_header == 1U)
  {
    se_ret_status = SE_SFU_IMG_Read(&se_status, pDestination, (uint8_t *)source, Length);
    if (se_ret_status == SE_SUCCESS)
    {
      e_ret_status = SFU_SUCCESS;
    }
  }
  else
  {
    /* ST uses a hand-rolled byte loop here rather than memcpy, and
     * re-checks DoubleECC_Error_Counter on every iteration, because on the
     * L4 reading an erased double word raises a double-ECC NMI mid-copy.
     * THE L1 HAS NO ECC ON ITS PROGRAM MEMORY: an erased word reads
     * 0xFFFFFFFF and raises nothing, so there is no per-byte condition to
     * test and memcpy is both correct and faster.  This is the one place
     * where dropping ST's code is a simplification rather than a port, and
     * it is sound only because of that hardware difference. */
    (void)memcpy(pDestination, pSource, Length);
    e_ret_status = SFU_SUCCESS;
  }
  return e_ret_status;
}

/**
  * @brief  This function compares a flash area against two patterns
  * @note   The flash area should not be located inside the secure area
  * @param  pFlash: address of the flash area
  * @param  Pattern1: first 32 bits pattern to be compared
  * @param  Pattern2: second 32 bits pattern to be compared
  * @param  Length: number of bytes to be compared
  * @retval SFU_ErrorStatus SFU_SUCCESS if successful, SFU_ERROR otherwise.
  */
SFU_ErrorStatus SFU_LL_FLASH_INT_Compare(const uint8_t *pFlash, const uint32_t Pattern1, const uint32_t Pattern2,
                                         uint32_t Length)
{
  uint32_t flash = (uint32_t)pFlash;
  uint32_t i;

  for (i = 0U; i < Length; i += 4U)
  {
    if ((*(uint32_t *)(flash + i) != Pattern1) && (*(uint32_t *)(flash + i) != Pattern2))
    {
      return SFU_ERROR;
    }
  }
  /* ST verifies the loop exit as well as the loop body.  Kept: it is cheap,
   * and it is the kind of check that catches a Length the caller computed
   * wrongly rather than a flash that read wrongly. */
  if (i < Length)
  {
    return SFU_ERROR;
  }
  return SFU_SUCCESS;
}

/**
  * @brief  Gets the page of a given address
  * @param  Addr: flash address
  * @retval The page of a given address, counted within its bank
  */
uint32_t SFU_LL_FLASH_INT_GetPage(uint32_t Addr)
{
  uint32_t page;

  if (Addr < FLASH_BANK2_BASE)
  {
    page = (Addr - FLASH_BASE) / FLASH_PAGE_SIZE;
  }
  else
  {
    page = (Addr - FLASH_BANK2_BASE) / FLASH_PAGE_SIZE;
  }
  return page;
}

/**
  * @brief  Gets the bank of a given address
  * @param  Addr: flash address
  * @retval The bank of a given address
  *
  * NOT CONSULTED BY THE ERASE PATH, unlike ST's.  The L1's erase descriptor
  * takes an absolute page address and has no bank field, so a range that
  * crosses 0x08040000 needs no split.  Kept because ST's header exports it.
  *
  * There is also no bank-swap bit to read: SYSCFG_MEMRMP's FB_MODE, which
  * ST's version consults, is an L4 field.  The L1's boot-bank selection is
  * the nRST_BFB2 option byte and it does not remap the addresses this
  * function is asked about.
  */
uint32_t SFU_LL_FLASH_INT_GetBank(uint32_t Addr)
{
  return (Addr < FLASH_BANK2_BASE) ? 1U : 2U;
}

/**
  * @brief  Clear error flags raised during previous operation
  * @retval SFU_ErrorStatus SFU_SUCCESS if successful, SFU_ERROR otherwise.
  */
static SFU_ErrorStatus SFU_LL_FLASH_INT_Clear_Error(void)
{
  SFU_ErrorStatus e_ret_status = SFU_ERROR;

  if (HAL_FLASH_Unlock() == HAL_OK)
  {
    __HAL_FLASH_CLEAR_FLAG(FLASH_FLAG_EOP | FLASH_FLAG_WRPERR | FLASH_FLAG_PGAERR |
                           FLASH_FLAG_SIZERR | FLASH_FLAG_OPTVERR);
    if (HAL_FLASH_Lock() == HAL_OK)
    {
      e_ret_status = SFU_SUCCESS;
    }
  }
  return e_ret_status;
}
