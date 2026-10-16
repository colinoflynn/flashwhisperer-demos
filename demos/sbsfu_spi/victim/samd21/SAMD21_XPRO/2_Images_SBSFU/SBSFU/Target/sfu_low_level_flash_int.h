/**
  ******************************************************************************
  * @file    sfu_low_level_flash_int.h
  * @brief   Internal (on-chip NVM) flash interface, SAM D21 Xplained Pro.
  ******************************************************************************
  */
#ifndef SFU_LOW_LEVEL_FLASH_INT_H
#define SFU_LOW_LEVEL_FLASH_INT_H

#ifdef __cplusplus
extern "C" {
#endif

#include "sfu_low_level_flash.h"
#include "main.h"
#include "sfu_def.h"

/**
  * @brief Flash write access constraints (size and alignment).
  *
  * ST's L4 port uses uint64_t because the STM32L4 can only program a double
  * word.  The SAM D21 is different in both directions and the type has to
  * follow the hardware, because SBSFU uses it for two things at once: the
  * unit of an ATOMIC write (see AtomicWrite in sfu_fwimg_common.c) and the
  * size of the TRAILER at the end of the download slot.
  *
  * On this part the page buffer is loaded by 16- or 32-bit writes -- an 8-bit
  * write to flash is silently ignored by the NVM controller -- and a write is
  * committed a 64-byte page at a time.  A 32-bit word is therefore the
  * smallest thing that can be placed in flash and observed as either present
  * or absent, which is what "atomic" has to mean here.
  *
  * Writing one word does not disturb the rest of its page: after a commit the
  * page buffer returns to all-ones, and programming can only clear bits, so
  * the untouched bytes are written 0xFF and keep their value.  That is what
  * makes several independent word-sized tags inside one page legal without an
  * erase between them, which the trailer relies on.
  */
typedef uint32_t SFU_LL_FLASH_write_t;

/**
  * Length of a MAGIC tag (32 bytes).  Must be a multiple of
  * SFU_LL_FLASH_write_t with a minimum of 32; 32 is a multiple of 4.
  */
#define MAGIC_LENGTH ((uint32_t)32U)

/*
 * !! NAME COLLISION, AND IT IS THE DANGEROUS KIND !!
 *
 * ST writes   #define IS_ALIGNED(address) (0U == ((address) % FLASH_PAGE_SIZE))
 * and means the ERASE granularity -- on an STM32L4 a "page" is what you
 * erase, 2 KB of it.
 *
 * Microchip's CMSIS already defines FLASH_PAGE_SIZE for this part, in
 * samd21j18a.h:546, as **64** -- and on the SAM D21 a "page" is what you
 * WRITE.  What you ERASE is a ROW, four pages, NVMCTRL_ROW_SIZE = 256
 * (instance/nvmctrl.h:70).
 *
 * So ST's macro compiles unchanged against Microchip's header, means
 * something different, and is wrong by a factor of four -- it would accept
 * slot boundaries that cannot be erased without destroying their neighbours.
 * Nothing warns: both symbols exist, both are integers, and the arithmetic is
 * valid.  This is the same shape as the repository's rule that a checker
 * which passes is not a checker which checks.
 *
 * IS_ALIGNED is therefore written against the erase unit explicitly, and
 * SFU_LL_FLASH_INT_Erase_Size asserts the same thing at run time rather than
 * trusting callers to have used the macro.
 */
#define SFU_SAMD21_ERASE_SIZE   ((uint32_t)NVMCTRL_ROW_SIZE)    /* 256 */
#define SFU_SAMD21_WRITE_SIZE   ((uint32_t)NVMCTRL_PAGE_SIZE)   /*  64 */

#undef IS_ALIGNED
#define IS_ALIGNED(address) (0U == ((address) % SFU_SAMD21_ERASE_SIZE))

SFU_ErrorStatus SFU_LL_FLASH_INT_Init(void);
SFU_ErrorStatus SFU_LL_FLASH_INT_Erase_Size(SFU_FLASH_StatusTypeDef *pxFlashStatus, uint8_t *pStart,
                                            uint32_t Length);
SFU_ErrorStatus SFU_LL_FLASH_INT_Write(SFU_FLASH_StatusTypeDef *pxFlashStatus, uint8_t *pDestination,
                                       const uint8_t *pSource, uint32_t Length);
SFU_ErrorStatus SFU_LL_FLASH_INT_Read(uint8_t *pDestination, const uint8_t *pSource, uint32_t Length);
SFU_ErrorStatus SFU_LL_FLASH_INT_Compare(const uint8_t *pFlash, const uint32_t Pattern1, const uint32_t Pattern2,
                                         uint32_t Length);
uint32_t SFU_LL_FLASH_INT_GetPage(uint32_t Addr);
uint32_t SFU_LL_FLASH_INT_GetBank(uint32_t Addr);

/* ST declares NMI_Handler and HardFault_Handler here because its
 * sfu_low_level_flash_int.c defines them, to catch the STM32's flash ECC
 * double-error NMI.  The SAM D21's NVM controller raises no NMI -- its error
 * reporting is NVMCTRL.STATUS, which the functions above read directly -- so
 * the handlers stay where they belong, in startup.c. */

#ifdef __cplusplus
}
#endif

#endif /* SFU_LOW_LEVEL_FLASH_INT_H */
