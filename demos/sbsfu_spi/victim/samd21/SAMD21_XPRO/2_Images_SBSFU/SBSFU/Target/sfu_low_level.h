/**
  ******************************************************************************
  * @file    sfu_low_level.h
  * @brief   SFU low-level interface, SAM D21 Xplained Pro.
  *
  * This is the SAM D21's copy of a file every board in X-CUBE-SBSFU's
  * Projects/ tree has its own version of.  It is not a modification of ST's
  * product; writing it is what porting to a board means.
  *
  * Diffed against
  * Projects/B-L475E-IOT01A/Applications/2_Images_ExtFlash/2_Images_SBSFU/SBSFU/Target/sfu_low_level.h,
  * the function list is IDENTICAL except for three removals, each with a
  * reason that is about the hardware and not about convenience:
  *
  *   SFU_LL_RTC_Init / SFU_LL_RTC_DeInit
  *       ST needs an RTC because its tamper detection is an RTC peripheral
  *       function (RTC_TAMPER).  Its only caller anywhere in the tree is
  *       sfu_low_level_security.c, which is itself a per-board file.  The
  *       SAM D21 Xplained Pro exposes no tamper input, SFU_TAMPER_PROTECT_ENABLE
  *       is therefore off, and carrying an RTC nothing calls would be dead
  *       code claiming a protection the board does not have.
  *
  *   SFU_LL_RTC_MspInit / MspDeInit, SFU_LL_UART_MspInit / MspDeInit
  *       STM32Cube's Msp callback convention, and their signatures take
  *       RTC_HandleTypeDef / UART_HandleTypeDef.  Nothing outside ST's own
  *       sfu_low_level.c calls them; this port does its pin and clock setup
  *       inline in samd21_hal.c, which is where a non-Cube port naturally
  *       puts it.
  *
  *   SFU_LL_DummyAccess
  *       kept, because sfu_boot.c uses it, and kept as the same empty macro
  *       ST already defines it as for this product.
  *
  * The CRC configuration enum is ST's, unchanged, because sfu_com_loader.c
  * switches on it.
  ******************************************************************************
  */
#ifndef SFU_LOW_LEVEL_H
#define SFU_LOW_LEVEL_H

#ifdef __cplusplus
extern "C" {
#endif

#include "main.h"
#include "sfu_def.h"

/**
  * @brief  SFU CRC Configuration definition.  ST's enum, unchanged.
  */
typedef enum
{
  SFU_CRC_CONFIG_NONE = 0U,   /*!< None */
  SFU_CRC_CONFIG_DEFAULT,     /*!< Default configuration */
  SFU_CRC_CONFIG_16BIT        /*!< 16 bit configuration */
} SFU_CRC_ConfigTypeDef;

#define IS_SFU_CRC_CONF(CONF) (((CONF) == SFU_CRC_CONFIG_NONE) || \
                               ((CONF) == SFU_CRC_CONFIG_DEFAULT) || \
                               ((CONF) == SFU_CRC_CONFIG_16BIT))

/* Dummy memory access: avoids a compilation issue with the STM32_Secure_Engine
   middleware, and is not meaningful for this product.  ST's comment and ST's
   empty body, carried over verbatim. */
#define SFU_LL_DummyAccess() \
  do{ \
  }while(0)

SFU_ErrorStatus    SFU_LL_Init(void);
SFU_ErrorStatus    SFU_LL_DeInit(void);

SFU_ErrorStatus    SFU_LL_CRC_Init(void);
SFU_ErrorStatus    SFU_LL_CRC_Config(SFU_CRC_ConfigTypeDef eCRCConfg);
uint32_t           SFU_LL_CRC_Calculate(uint32_t pBuffer[], uint32_t BufferLength);

SFU_ErrorStatus    SFU_LL_UART_Init(void);
SFU_ErrorStatus    SFU_LL_UART_DeInit(void);
SFU_ErrorStatus    SFU_LL_UART_Transmit(uint8_t *pData, uint16_t DataLength, uint32_t Timeout);
SFU_ErrorStatus    SFU_LL_UART_Receive(uint8_t *pData, uint16_t DataLength, uint32_t Timeout);
SFU_ErrorStatus    SFU_LL_UART_Flush(void);

#ifdef __cplusplus
}
#endif

#endif /* SFU_LOW_LEVEL_H */
