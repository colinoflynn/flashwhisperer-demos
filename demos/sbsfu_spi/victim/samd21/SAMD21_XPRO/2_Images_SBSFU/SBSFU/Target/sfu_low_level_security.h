/**
  ******************************************************************************
  * @file    sfu_low_level_security.h
  * @brief   Security services, SAM D21 Xplained Pro.
  *
  * ST's version of this file is ~300 lines, most of it MPU region tables and
  * STM32 option-byte constants.  Almost none of it survives the port, because
  * almost none of the hardware does -- and that is the honest outcome rather
  * than a gap: see the table in sfu_low_level_security.c, which says for each
  * of ST's protections whether this board can honour it, weaken it, or not
  * offer it at all.
  *
  * The enum and the protection bit masks are ST's, unchanged, because
  * sfu_boot.c and sfu_error.c consume them.
  ******************************************************************************
  */
#ifndef SFU_LOW_LEVEL_SECURITY_H
#define SFU_LOW_LEVEL_SECURITY_H

#ifdef __cplusplus
extern "C" {
#endif

#include "main.h"
#include "sfu_def.h"
#include "sfu_fwimg_regions.h"

/** Reset cause, as SBSFU classifies it.  ST's enum, unchanged.
  * SFU_RESET_FIREWALL can never be reported on this part -- see the .c. */
typedef enum
{
  SFU_RESET_UNKNOWN = 0x00U,
  SFU_RESET_FIREWALL,
  SFU_RESET_WDG_RESET,
  SFU_RESET_LOW_POWER,
  SFU_RESET_HW_RESET,
  SFU_RESET_BOR_RESET,
  SFU_RESET_SW_RESET,
  SFU_RESET_OB_LOADER,
} SFU_RESET_IdTypeDef;

/* ST's protection bit masks, unchanged. */
#define SFU_PROTECTIONS_NONE                 ((uint32_t)0x00000000U)
#define SFU_STATIC_PROTECTION_RDP            ((uint32_t)0x00000001U)
#define SFU_STATIC_PROTECTION_WRP            ((uint32_t)0x00000002U)
#define SFU_STATIC_PROTECTION_PCROP          ((uint32_t)0x00000004U)
#define SFU_STATIC_PROTECTION_FWALL          ((uint32_t)0x00000008U)
#define SFU_STATIC_PROTECTION_BFB2           ((uint32_t)0x00000010U)
#define SFU_RUNTIME_PROTECTION_IWDG          ((uint32_t)0x00000020U)
#define SFU_RUNTIME_PROTECTION_DAP           ((uint32_t)0x00000040U)
#define SFU_RUNTIME_PROTECTION_DMA           ((uint32_t)0x00000080U)
#define SFU_RUNTIME_PROTECTION_ANTI_TAMPER   ((uint32_t)0x00000100U)
#define SFU_RUNTIME_PROTECTION_MPU           ((uint32_t)0x00000200U)
#define SFU_RUNTIME_PROTECTION_GTZC          ((uint32_t)0x00000400U)

/* Steps at which runtime protections are (re)applied.  ST's values. */
#define SFU_INITIAL_CONFIGURATION            (0x00U)
#define SFU_SECOND_CONFIGURATION             (0x01U)
#define SFU_THIRD_CONFIGURATION              (0x02U)

/* ==========================================================================
 * CONSTANTS SFU_IMG_Init() CHECKS AGAINST, AND WHAT THEY MEAN HERE
 *
 * sfu_fwimg_common.c runs three sanity checks at boot using STM32 protection
 * geometry.  They are not debug-only and they are not optional -- failing one
 * sets SFU_IMG_INIT_FLASH_CONSTRAINTS_ERROR and stops the boot -- so the port
 * has to supply the constants.  Two of the three are meaningful on this part
 * and are given real values.  The third is not, and saying so is the point of
 * this block.
 * ========================================================================== */

/** STM32 HAL's name for the base of the internal array.  Microchip's CMSIS
  * calls it FLASH_ADDR.  Same number, different spelling. */
#ifndef FLASH_BASE
#define FLASH_BASE                           (FLASH_ADDR)
#endif

/** MEANINGFUL.  sfu_fwimg_common.c:586 and :607 check that neither the active
  * slot nor the download slot starts inside the write-protected bootloader
  * region.  That check is exactly as relevant here as on an STM32 -- the
  * region is NVMCTRL-locked by apply_wrp() -- only the protection mechanism
  * differs.
  *
  * UNITS ARE A TRAP.  ST's expression is
  *     (SlotStartAdd - FLASH_BASE) / FLASH_PAGE_SIZE <= SFU_PROTECT_WRP_PAGE_END_1
  * and FLASH_PAGE_SIZE here is Microchip's 64-byte WRITE page, not ST's erase
  * page -- see the longer note in sfu_low_level_flash_int.h.  So this constant
  * must be expressed in 64-byte units to match, and it is derived from the
  * linker symbol rather than written as a literal so it cannot drift when the
  * bootloader region moves. */
#define SFU_PROTECT_WRP_PAGE_END_1           (SB_REGION_ROM_END / FLASH_PAGE_SIZE)

/** THE FIREWALL CONSTANTS.  There is no firewall on this part, but these are
  * NOT free to invent: sfu_fwimg_common.c tests them twice, for two different
  * things, and the two tests together pin down a real region.
  *
  * The first attempt here set both segments to the SE code region so the
  * first test became a tautology.  That passed test one and FAILED test two,
  * and the failure was SFU_IMG_INIT_FLASH_CONSTRAINTS_ERROR at boot with no
  * trace -- because SFU_BOOT_Init's banner comes after the check.  Making one
  * assertion vacuous does not make the others go away; it just moves where
  * you find out.
  *
  * What the two tests actually require, with FLASH_BANK_SIZE 0 (single bank,
  * so ST's bank-offset arithmetic collapses):
  *
  *   sfu_fwimg_common.c:619  NVDATA must CONTAIN the firewall CODE segment
  *   sfu_fwimg_common.c:645  NVDATA must CONTAIN the active slot's HEADER
  *
  * So NVDATA is defined as exactly the span from the start of the Secure
  * Engine code to the end of the active slot's header, and CODE is the
  * Secure Engine code region inside it.  That is a coherent description of
  * "the memory a firewall would be protecting on this layout" -- the SE, its
  * keys, and the header that authorises the image -- rather than a pair of
  * numbers chosen to make an if-statement false.
  *
  * IT IS STILL NOT ENFORCED BY ANYTHING.  No hardware on this part can make
  * that span inaccessible.  The constants describe the region; they do not
  * protect it.  sfu_low_level_security.c's table is the place that says so.
  */
#define FLASH_BANK_SIZE                      (0U)
#define SFU_PROTECT_FWALL_CODE_ADDR_START    (SE_CODE_REGION_ROM_START)
#define SFU_PROTECT_FWALL_CODE_SIZE          (SE_CODE_REGION_ROM_END - SE_CODE_REGION_ROM_START + 1U)
#define SFU_PROTECT_FWALL_NVDATA_ADDR_START  (SE_CODE_REGION_ROM_START)
#define SFU_PROTECT_FWALL_NVDATA_SIZE        ((SLOT_ACTIVE_1_HEADER + SE_FW_HEADER_TOT_LEN) - SE_CODE_REGION_ROM_START)

SFU_ErrorStatus SFU_LL_SECU_IWDG_Refresh(void);
SFU_ErrorStatus SFU_LL_SECU_CheckApplyStaticProtections(void);
SFU_ErrorStatus SFU_LL_SECU_CheckApplyRuntimeProtections(uint8_t uStep);
void            SFU_LL_SECU_GetResetSources(SFU_RESET_IdTypeDef *peResetpSourceId);
void            SFU_LL_SECU_ClearResetSources(void);
SFU_ErrorStatus SFU_LL_SECU_SetProtectionMPU_UserApp(void);
SFU_ErrorStatus SFU_LL_SECU_SetProtectionMPU_StandaloneLoader(void);

#ifdef __cplusplus
}
#endif

#endif /* SFU_LOW_LEVEL_SECURITY_H */
