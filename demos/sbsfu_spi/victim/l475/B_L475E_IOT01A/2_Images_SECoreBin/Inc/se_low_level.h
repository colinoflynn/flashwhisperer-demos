/**
  ******************************************************************************
  * @file    se_low_level.h
  * @author  MCD Application Team
  * @brief   This file contains definitions for Secure Engine low level interface
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2017 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file in
  * the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */

/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef SE_LOW_LEVEL_H
#define SE_LOW_LEVEL_H

#ifdef __cplusplus
extern "C" {
#endif

/* Includes ------------------------------------------------------------------*/
#include "se_def.h"

/* Secure Engine needs to know the slots configuration for the Read/Write services in protected area
   (see @ref SE_IMG_Write, see @ref SE_IMG_Read) */
#include "sfu_fwimg_regions.h"

#include "stm32l4xx_hal.h"

/** @addtogroup SE
  * @{
  */

/** @addtogroup SE_HARDWARE
  * @{
  */

/** @defgroup SE_HARDWARE_Exported_Constants Exported Constants
  * @{
  */
/**
  * @brief flash handling constants: these constants are used in se_fwimg.c
  */

/**
  * @}
  */

/** @defgroup SE_HARDWARE_Exported_Macros Exported Macros
  * @{
  */

/** @defgroup SE_HARDWARE_Exported_Macros_CRC CRC Settings
  * @{
  */

/**
  * @brief Set CRC 32 of the BootInfoTypeDef pointer passed as parameter
  * The CRC is computed with the structure without its CRC field and the length is provided to SE_CRC_Calculate in
  * 32-bit word.
  * Please note that this works only if the CRC field is kept as the last uint32_t of the SE_BootInfoTypeDef structure.
  */
#define SE_BOOT_CONFIG_SET_CRC_32(x)    \
  do{                                  \
    (x)->CRC32 = SE_CRC_Calculate ((uint32_t*)(x), (sizeof(SE_BootInfoTypeDef)-sizeof(uint32_t))/sizeof(uint32_t));\
  }while(0)

/**
  * @brief Set CRC of the BootInfoTypeDef pointer passed as parameter
  */
#define SE_BOOT_CONFIG_SET_CRC(x)      SE_BOOT_CONFIG_SET_CRC_32(x)

/**
  * @}
  */

/** @defgroup SE_HARDWARE_Exported_Macros_CodeIsolation Code Isolation Settings
  * @brief These settings configure the way the Secure Engine is isolated from the rest of the code.
  * @{
  */

/**
  * Code isolation based on Firewall
  */
/* L475 PORT: TURNED OFF, AND THIS IS THE PORT'S STRUCTURAL LIMIT.
 *
 * ST defines this unconditionally for this board -- note it is NOT gated on
 * app_sfu.h's SFU_FWALL_PROTECT_ENABLE, so SECBOOT_DISABLE_SECURITY_IPS does
 * not reach it.  The L475 really does have the Firewall peripheral, so
 * unlike the L152 port this is not "the part lacks the hardware".
 *
 * It is off because this rig links ONE ELF, and firewall isolation is what
 * makes that impossible:
 *
 *   * Behind the firewall the Secure Engine cannot call out of its own
 *     segment, so ST's se_utils.c supplies the SE its own HAL_GetTick and
 *     HAL_Delay.  In one address space those are duplicate definitions of
 *     symbols stm32l4xx_hal.c already provides.  ST avoids that by building
 *     SECoreBin as a SEPARATE binary and linking the bootloader against its
 *     exported symbols; reproducing that two-binary flow in this Makefile is
 *     work this rig has not done.
 *   * The call gate would then drive FIREWALL->CR on a peripheral this build
 *     never configures.
 *
 * WHAT IT COSTS THE MEASUREMENT, stated so the next reader does not have to
 * guess: with isolation on, each chunk's two SE calls (SE_Decrypt_Append and
 * SE_AuthenticateFW_Append) go through the call gate's firewall open/close.
 * That is a fixed instruction sequence with no dependence on the chunk's
 * contents, so it adds a CONSTANT to every interval this rig records -- the
 * same shape of offset as the head and tail in Instr/sfu_instr.h.  The AES
 * runs out of the same flash through the same accelerator either way, so the
 * channel itself should not move.  SHOULD NOT is a prediction, not a
 * measurement: it is in this rig's README under what is not settled. */
/* #define SFU_ISOLATE_SE_WITH_FIREWALL */

/**
  * @brief Set the FIREWALL pre arm bit to avoid reset when fetching non protected
  * code after exiting from protected code execution area
  */
#define ENTER_PROTECTED_AREA()   CLEAR_BIT(FIREWALL->CR, FW_CR_FPA)

/**
  * @brief Set FPA bit for a proper closure of the Firewall when exiting the protected function
  */
#define EXIT_PROTECTED_AREA() __HAL_FIREWALL_PREARM_ENABLE()


/** @addtogroup SE_LOW_LEVEL_Exported_Functions
  * @{
  */
void SE_LL_CORE_Cleanup(void);

/**
  * @}
  */

/**
  * @}
  */

/** @addtogroup SE_HARDWARE_Exported_Functions
  * @{
  */

/** @addtogroup SE_HARDWARE_Exported_CRC_Functions
  * @{
  */
SE_ErrorStatus SE_LL_CRC_Config(void);
SE_ErrorStatus SE_LL_CRC_Init(void);
SE_ErrorStatus SE_LL_CRC_DeInit(void);
uint32_t SE_LL_CRC_Calculate(uint32_t pBuffer[], uint32_t uBufferLength);

/**
  * @}
  */

/** @addtogroup SE_HARDWARE_Exported_FLASH_Functions
  * @{
  */
SE_ErrorStatus SE_LL_FLASH_Erase(uint8_t *pStart, uint32_t Length);
SE_ErrorStatus SE_LL_FLASH_Write(uint8_t *pDestination, const uint8_t *pSource, uint32_t Length);
SE_ErrorStatus SE_LL_FLASH_Read(uint8_t *pDestination, const uint8_t *pSource, uint32_t Length);

void NMI_Handler(void);
void HardFault_Handler(void);
/**
  * @}
  */

/** @addtogroup SE_HARDWARE_Exported_FLASH_EXT_Functions
  * @{
  */
SE_ErrorStatus SE_LL_FLASH_EXT_Decrypt_Init(SE_FwRawHeaderTypeDef *pxSE_Metadata);
/**
  * @}
  */

/** @addtogroup SE_BUFFER_CHECK_Exported_RAM_Functions
  * @{
  */

SE_ErrorStatus SE_LL_Buffer_in_ram(void *pBuff, uint32_t Length);
SE_ErrorStatus SE_LL_Buffer_in_SBSFU_ram(const void *pBuff, uint32_t Length);
SE_ErrorStatus SE_LL_Buffer_part_of_SE_ram(const void *pBuff, uint32_t Length);
SE_ErrorStatus SE_LL_Buffer_part_of_SE_rom(const void *pBuff, uint32_t Length);
/**
  * @}
  */

/** @addtogroup SE_LOCK_KEYS_Exported_Functions
  * @{
  */
SE_ErrorStatus SE_LL_Lock_Keys(void);
/**
  * @}
  */

/**
  * @}
  */

/**
  * @}
  */

/**
  * @}
  */

#ifdef __cplusplus
}
#endif

#endif /* SE_LOW_LEVEL_H */
