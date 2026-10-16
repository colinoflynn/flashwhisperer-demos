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

/* L152 port: ST's HAL for this family.  One line, and it is the whole
   STM32 dependency of this header -- which is the point of porting to an
   ST part.  The SAM D21's copy needed three includes and a compatibility
   shim here. */
#include "stm32l1xx_hal.h"

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
  * L152 PORT: THE SECURE ENGINE RUNS WITH NO HARDWARE ISOLATION, AND THIS
  * IS THE MOST SIGNIFICANT WAY THIS PORT IS WEAKER THAN ST'S.
  *
  * Every project in ST's tree defines one of SFU_ISOLATE_SE_WITH_FIREWALL
  * or SFU_ISOLATE_SE_WITH_MPU.  The firewall is an L0/L4 peripheral and
  * this part does not have one.  It DOES have an MPU -- MPU_TYPE reads
  * 0x00000800 on this die, eight regions, measured by
  * rigs/fw_l152_sbsfu/bringup, which is a real difference from the SAM D21
  * port where there was no MPU at all.
  *
  * SFU_ISOLATE_SE_WITH_MPU is nonetheless left off, and the reason is in
  * sfu_low_level_security.c: ST's MPU isolation assumes a privilege
  * boundary, and this port has none.  Everything runs privileged in one
  * address space, SE_CallGate is an ordinary function call, and an MPU
  * region around the Secure Engine would be programmed by the same
  * unprivileged-in-name-only code it is meant to exclude -- which can
  * reprogram it.  Turning it on would produce a protection that reads as
  * enabled and is not one.  That is worse than none, because the next
  * reader believes it.
  *
  * So: the firmware encryption key sits in ordinary readable flash, and a
  * compromised SBSFU could read it directly.  The guards in se_callgate.c
  * compile the isolation paths out cleanly when neither symbol is defined,
  * which is what makes this configuration buildable -- but it is NOT a
  * configuration ST ships or tests, and it must not be described as one.
  *
  * WHAT IT DOES NOT CHANGE is the thing this demo measures.  The timing
  * channel is in the AES table lookups, which execute identically whether
  * or not an MPU is standing around them; it is observed from outside the
  * chip, on the SPI bus, by an attacker who never executes any code on the
  * target at all.  Isolation protects the key from software on the device.
  * This attack is not software on the device.
  */
/* #define SFU_ISOLATE_SE_WITH_FIREWALL */
/* #define SFU_ISOLATE_SE_WITH_MPU */

/**
  * @brief No isolation boundary to cross, so entering and leaving the
  *        "protected" area is a no-op.  se_callgate.c calls these
  *        unconditionally, so they must exist even when nothing is
  *        isolated.
  */
#define ENTER_PROTECTED_AREA()   do { } while (0)
#define EXIT_PROTECTED_AREA()    do { } while (0)


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
