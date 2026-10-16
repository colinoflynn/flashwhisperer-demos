/**
  ******************************************************************************
  * @file    sfu_low_level.h
  * @brief   SFU low-level interface, NUCLEO-L152RE.
  *
  * This is the L152's copy of a file every board in X-CUBE-SBSFU's Projects/
  * tree has its own version of.  It is not a modification of ST's product;
  * writing it is what porting to a board means.
  *
  * Diffed against
  * Projects/B-L475E-IOT01A/Applications/2_Images_ExtFlash/2_Images_SBSFU/SBSFU/Target/sfu_low_level.h,
  * the EXPORTED FUNCTION LIST IS IDENTICAL.  That is the payoff for picking
  * an ST part for the second board: the SAM D21's copy of this header had to
  * drop five declarations because there was no Cube HAL underneath to give
  * them a meaning, and here there is.  What changes is the board's wiring:
  *
  *   the UART   ST uses USART1 on PB6/PB7, which is the B-L475E-IOT01A's
  *              ST-LINK VCP.  On a NUCLEO-64 the VCP is USART2 on PA2/PA3,
  *              and rigs/fw_l1_aes/main.c already drives it there.  Same
  *              alternate function (AF7), different pins.
  *
  *   the RTC    kept, with ST's LSI prediv values.  ST needs it because its
  *              tamper detection is an RTC peripheral function; this board
  *              exposes no tamper input, so SFU_TAMPER_PROTECT_ENABLE is off
  *              and the declarations sit behind ST's own #ifndef exactly as
  *              they do in ST's copy.
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

/* The ST-LINK virtual COM port on a NUCLEO-64: USART2, PA2 TX, PA3 RX, AF7.
 * UM1724 and the solder bridges SB13/SB14 as shipped.  An image is staged
 * over the same USB cable that programs and debugs the board, and the trace
 * comes back the same way. */
#define SFU_UART                                USART2
#define SFU_UART_CLK_ENABLE()                   __HAL_RCC_USART2_CLK_ENABLE()
#define SFU_UART_CLK_DISABLE()                  __HAL_RCC_USART2_CLK_DISABLE()

#define SFU_UART_TX_AF                          GPIO_AF7_USART2
#define SFU_UART_TX_GPIO_PORT                   GPIOA
#define SFU_UART_TX_PIN                         GPIO_PIN_2
#define SFU_UART_TX_GPIO_CLK_ENABLE()           __HAL_RCC_GPIOA_CLK_ENABLE()
#define SFU_UART_TX_GPIO_CLK_DISABLE()          __HAL_RCC_GPIOA_CLK_DISABLE()

#define SFU_UART_RX_AF                          GPIO_AF7_USART2
#define SFU_UART_RX_GPIO_PORT                   GPIOA
#define SFU_UART_RX_PIN                         GPIO_PIN_3
#define SFU_UART_RX_GPIO_CLK_ENABLE()           __HAL_RCC_GPIOA_CLK_ENABLE()
#define SFU_UART_RX_GPIO_CLK_DISABLE()          __HAL_RCC_GPIOA_CLK_DISABLE()

/* ST's values, for the LSI source ST also selects. */
#define RTC_CLOCK_SOURCE_LSI
#ifdef RTC_CLOCK_SOURCE_LSI
#define RTC_ASYNCH_PREDIV    0x7FU
#define RTC_SYNCH_PREDIV     0xF9
#endif /* RTC_CLOCK_SOURCE_LSI */

/* External variables --------------------------------------------------------*/
extern __IO uint32_t  DummyMemAccess;
#if defined(SFU_LOW_LEVEL_C)
#if defined(IT_MANAGEMENT)
/* Dummy memory access : avoid compilation issue with STM32_Secure_Engine
   middleware but not meaningful for this product */
__IO uint32_t DummyMemAccess;
#endif /* defined(IT_MANAGEMENT) */
#endif /* defined(SFU_LOW_LEVEL_C) */

#define IS_SFU_CRC_CONF(CONF) (((CONF) == SFU_CRC_CONFIG_NONE) || \
                               ((CONF) == SFU_CRC_CONFIG_DEFAULT) || \
                               ((CONF) == SFU_CRC_CONFIG_16BIT))

/* Dummy memory access: avoids a compilation issue with the
   STM32_Secure_Engine middleware, and is not meaningful for this product.
   ST's comment and ST's empty body, carried over verbatim. */
#define SFU_LL_DummyAccess() \
  do{ \
  }while(0)

/* Exported functions ------------------------------------------------------- */
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

#ifndef SFU_TAMPER_PROTECT_ENABLE
SFU_ErrorStatus SFU_LL_RTC_Init(void);
SFU_ErrorStatus SFU_LL_RTC_DeInit(void);
#endif /*SFU_TAMPER_PROTECT_ENABLE*/

void  SFU_LL_RTC_MspInit(RTC_HandleTypeDef *hrtc);
void  SFU_LL_RTC_MspDeInit(RTC_HandleTypeDef *hrtc);
void  SFU_LL_UART_MspInit(UART_HandleTypeDef *huart);
void  SFU_LL_UART_MspDeInit(UART_HandleTypeDef *huart);

#ifdef __cplusplus
}
#endif

#endif /* SFU_LOW_LEVEL_H */
