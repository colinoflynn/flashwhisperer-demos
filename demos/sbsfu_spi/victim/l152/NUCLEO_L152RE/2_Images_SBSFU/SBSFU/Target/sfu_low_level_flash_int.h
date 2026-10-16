/**
  ******************************************************************************
  * @file    sfu_low_level_flash_int.h
  * @brief   Internal flash interface, NUCLEO-L152RE.
  *
  * The L152's copy of a per-board file.  Diffed against ST's
  * Projects/B-L475E-IOT01A/.../SBSFU/Target/sfu_low_level_flash_int.h, the
  * exported function list is identical and ONE TYPE CHANGES -- which is the
  * one ST's own comment says is the important one.
  *
  * THE ATOMIC WRITE IS A WORD HERE, NOT A DOUBLE WORD
  * ---------------------------------------------------
  * ST writes, above their typedef: "on L4, it is only possible to program
  * double word (2 x 32-bit data)", and `SFU_LL_FLASH_write_t` is uint64_t
  * for that reason.  The L1 is the other way round.  Its HAL offers exactly
  * one program type -- `FLASH_TYPEPROGRAM_WORD`, and
  * `IS_FLASH_TYPEPROGRAM` accepts nothing else -- so the smallest thing
  * this part can write atomically is 32 bits.
  *
  * This is not cosmetic.  sfu_fwimg_common.c:535 onwards CHECKS AT RUN TIME
  * that MAGIC_LENGTH, SE_FW_HEADER_TOT_LEN and SFU_IMG_CHUNK_SIZE are each
  * a multiple of `sizeof(SFU_LL_FLASH_write_t)`, and refuses to boot if any
  * is not; and in the swap configuration the type also sets the size of the
  * trailer area at the end of the download slot.  Going from 8 to 4 relaxes
  * all of those, so nothing that passed on ST's board can fail here for
  * this reason -- the change can only make the constraint easier, which is
  * why it is safe to make at all.
  *
  * ERASE GRANULARITY IS 256 BYTES
  * -------------------------------
  * `FLASH_PAGE_SIZE` is 256 on this part (stm32l1xx_hal_flash.h:128),
  * against 2048 on the L4, and the L1's erase descriptor is
  * {TypeErase, PageAddress, NbPages} with `FLASH_TYPEERASE_PAGES` the only
  * legal type -- there is no bank field and no sector concept to port.
  * `IS_ALIGNED` therefore tests against a much finer grid than ST's, which
  * again only relaxes things.
  *
  * NO ECC, SO NO NMI TRAP
  * -----------------------
  * ST's version carries a `DoubleECC_Error_Counter` and installs NMI and
  * HardFault handlers, because reading an ERASED double word on the L4
  * raises a double-ECC-error NMI and their Read has to survive it.  The L1
  * has no ECC on its program memory: an erased word reads 0xFFFFFFFF and
  * raises nothing.  The two handlers are still DECLARED here, because ST's
  * header declares them and this port keeps the interface identical, but
  * they are defined in Core/Src/stm32l1xx_it.c where a part without an ECC
  * trap naturally puts them.
  ******************************************************************************
  */
#ifndef SFU_LOW_LEVEL_FLASH_INT_H
#define SFU_LOW_LEVEL_FLASH_INT_H

#ifdef __cplusplus
extern "C" {
#endif

/* Includes ------------------------------------------------------------------*/
#include "sfu_low_level_flash.h"
#include "main.h"
#include "sfu_def.h"

/* Exported types ------------------------------------------------------------*/
/**
  * @brief Flash Write Access Constraints (size and alignment)
  *
  * On the STM32L1 it is only possible to program a WORD (32-bit data):
  * stm32l1xx_hal_flash.h defines FLASH_TYPEPROGRAM_WORD as the only value
  * IS_FLASH_TYPEPROGRAM accepts.  RM0038 rev 16, section 3.3.3.
  *
  * @note This type is very important for the FWIMG module (see @ref SFU_IMG).
  * \li This is the type to be used for an atomic write in FLASH.
  * \li The size of this type changes the size of the TRAILER area at the end
  *     of the dwl slot.  This port is SFU_NO_SWAP, so there is no trailer,
  *     but the alignment checks in sfu_fwimg_common.c still read it.
  */
typedef uint32_t SFU_LL_FLASH_write_t;

/* Exported constants --------------------------------------------------------*/
/**
  * Length of a MAGIC tag (32 bytes).
  * This must be a multiple of @ref SFU_LL_FLASH_write_t with a minimum value
  * of 32.  32 % 4 == 0, so ST's value carries over unchanged.
  */
#define MAGIC_LENGTH ((uint32_t)32U)

/* External variables --------------------------------------------------------*/
#define IS_ALIGNED(address) (0U == ((address) % FLASH_PAGE_SIZE))

/* Exported functions ------------------------------------------------------- */
SFU_ErrorStatus SFU_LL_FLASH_INT_Init(void);
SFU_ErrorStatus SFU_LL_FLASH_INT_Erase_Size(SFU_FLASH_StatusTypeDef *pxFlashStatus, uint8_t *pStart, uint32_t Length);
SFU_ErrorStatus SFU_LL_FLASH_INT_Write(SFU_FLASH_StatusTypeDef *pxFlashStatus, uint8_t *pDestination,
                                       const uint8_t *pSource, uint32_t Length);
SFU_ErrorStatus SFU_LL_FLASH_INT_Read(uint8_t *pDestination, const uint8_t *pSource, uint32_t Length);
SFU_ErrorStatus SFU_LL_FLASH_INT_Compare(const uint8_t *pFlash, const uint32_t Pattern1, const uint32_t Pattern2,
                                         uint32_t Length);
uint32_t SFU_LL_FLASH_INT_GetPage(uint32_t Addr);
uint32_t SFU_LL_FLASH_INT_GetBank(uint32_t Addr);
void NMI_Handler(void);
void HardFault_Handler(void);

#ifdef __cplusplus
}
#endif

#endif /* SFU_LOW_LEVEL_FLASH_INT_H */
