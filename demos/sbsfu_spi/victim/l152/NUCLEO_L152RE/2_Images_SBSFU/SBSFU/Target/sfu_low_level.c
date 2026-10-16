/**
  ******************************************************************************
  * @file    sfu_low_level.c
  * @brief   SFU low-level interface, NUCLEO-L152RE.
  *          The UART the local YMODEM loader and the trace share, the CRC the
  *          YMODEM packet check needs, and the RTC ST's tamper path expects.
  *
  * Structure and function bodies follow ST's
  * Projects/B-L475E-IOT01A/.../SBSFU/Target/sfu_low_level.c closely, because
  * on an ST part most of it is HAL calls that need no porting at all.  Two
  * things genuinely differ and both are about the silicon, not about taste:
  * the CRC peripheral, and which USART reaches the VCP.
  ******************************************************************************
  */
#define SFU_LOW_LEVEL_C

#include "sfu_low_level.h"

/* THE 16-BIT CRC IS IN SOFTWARE, AND IT HAS TO BE
 * ------------------------------------------------
 * ST programs the STM32 CRC peripheral for both of its configurations.  On
 * the L4 that works because the L4's CRC unit has a settable polynomial, a
 * settable initial value, a byte/halfword/word input format and input and
 * output reflection.  THE L1'S CRC UNIT HAS NONE OF THOSE.  Its whole
 * programming model is a 32-bit data register and a reset bit: fixed poly
 * 0x04C11DB7, fixed init 0xFFFFFFFF, 32-bit words, no reflection.  The L1
 * HAL's CRC_HandleTypeDef is three fields -- Instance, Lock, State -- and
 * every `CrcHandle.Init.*` line in ST's version refers to a field that does
 * not exist here.
 *
 * So the two configurations split:
 *
 *   SFU_CRC_CONFIG_DEFAULT  the peripheral, through HAL_CRC_Calculate.  The
 *                           L1's fixed behaviour IS what ST's default
 *                           configuration programs on the L4, so this one
 *                           ports exactly and stays in hardware.
 *
 *   SFU_CRC_CONFIG_16BIT    software.  This needs CRC-16/CCITT -- poly
 *                           0x1021, init 0, no reflection, fed a byte at a
 *                           time -- and the L1's unit cannot be made to do
 *                           16 bits at all.  The choice is between a correct
 *                           software CRC-16 and a wrong hardware CRC-32.
 *
 * The 16-bit one is the only one that matters: across the whole SBSFU tree
 * there is exactly ONE caller of SFU_LL_CRC_Calculate, sfu_com_loader.c:473,
 * checking a YMODEM packet, and it selects SFU_CRC_CONFIG_16BIT first.
 * SFU_CRC_CONFIG_DEFAULT is selected by SFU_LL_CRC_Init() and nothing ever
 * calculates with it.
 *
 * This is the shape of bug that ruins a bootloader port quietly: a CRC that
 * is self-consistent on the target and disagrees with the host, so every
 * transfer NAKs and the cause looks like a serial problem.
 */

/* Private variables ---------------------------------------------------------*/
static UART_HandleTypeDef   UartHandle;
static CRC_HandleTypeDef    CrcHandle;
static SFU_CRC_ConfigTypeDef CrcConfig = SFU_CRC_CONFIG_NONE;

/* Private function prototypes -----------------------------------------------*/
static void     SFU_LL_Error_Handler(void);

/* Functions Definition ------------------------------------------------------*/

/**
  * @brief  Initialize SFU Interface.
  * @retval SFU_ErrorStatus SFU_SUCCESS if successful, SFU_ERROR otherwise.
  */
SFU_ErrorStatus SFU_LL_Init(void)
{
  return SFU_LL_CRC_Init();
}

/**
  * @brief  DeInitialize SFU Interface.
  * @retval SFU_ErrorStatus SFU_SUCCESS if successful, SFU_ERROR otherwise.
  */
SFU_ErrorStatus SFU_LL_DeInit(void)
{
  /* ST's body here is an empty "ADD SRC CODE HERE" that returns SFU_ERROR.
   * Kept returning SFU_SUCCESS instead, because on this port there is
   * genuinely nothing to tear down and a bootloader that reports failure
   * from a no-op sends sfu_boot.c down an error path for no reason.  ST's
   * callers of SFU_LL_DeInit are all on exit paths where the difference is
   * invisible on the L4 and would not be here. */
  return SFU_SUCCESS;
}

/* ------------------------------------------------------------------- CRC -- */

SFU_ErrorStatus SFU_LL_CRC_Init(void)
{
  __HAL_RCC_CRC_CLK_ENABLE();

  CrcHandle.Instance = CRC;
  if (HAL_CRC_Init(&CrcHandle) != HAL_OK)
  {
    return SFU_ERROR;
  }
  return SFU_LL_CRC_Config(SFU_CRC_CONFIG_DEFAULT);
}

SFU_ErrorStatus SFU_LL_CRC_Config(SFU_CRC_ConfigTypeDef eCRCConfg)
{
  assert_param(IS_SFU_CRC_CONF(eCRCConfg));

  if (!IS_SFU_CRC_CONF(eCRCConfg))
  {
    return SFU_ERROR;
  }
  /* Nothing to program: the L1's unit has no configuration.  The selection
   * is remembered and acted on in SFU_LL_CRC_Calculate. */
  CrcConfig = eCRCConfg;
  return SFU_SUCCESS;
}

uint32_t SFU_LL_CRC_Calculate(uint32_t pBuffer[], uint32_t BufferLength)
{
  if (CrcConfig == SFU_CRC_CONFIG_16BIT)
  {
    /* CRC-16/CCITT ("XMODEM"): poly 0x1021, init 0x0000, not reflected, no
     * final XOR.  BufferLength is a BYTE count in this configuration --
     * sfu_com_loader.c passes packet_size -- which is why the cast below is
     * to uint8_t despite the uint32_t* parameter.  ST's prototype takes
     * uint32_t* because the L4 peripheral's 32-bit configuration wants one;
     * the caller already casts a uint8_t* into it. */
    const uint8_t *p = (const uint8_t *)(const void *)pBuffer;
    uint32_t crc = 0U;
    uint32_t i;
    uint32_t j;

    for (i = 0U; i < BufferLength; i++)
    {
      crc ^= (uint32_t)p[i] << 8;
      for (j = 0U; j < 8U; j++)
      {
        crc = ((crc & 0x8000U) != 0U) ? (((crc << 1) ^ 0x1021U) & 0xFFFFU)
                                      : ((crc << 1) & 0xFFFFU);
      }
    }
    return crc;
  }

  /* SFU_CRC_CONFIG_DEFAULT, in hardware.  UNEXERCISED -- nothing in the
   * tree calculates with this configuration -- so it is implemented for
   * completeness and its result has not been checked against anything. */
  return HAL_CRC_Calculate(&CrcHandle, pBuffer, BufferLength);
}

/* ------------------------------------------------------------------ UART -- */

SFU_ErrorStatus SFU_LL_UART_Init(void)
{
  UartHandle.Instance        = SFU_UART;
  UartHandle.Init.BaudRate   = 115200U;
  UartHandle.Init.WordLength = UART_WORDLENGTH_8B;
  UartHandle.Init.StopBits   = UART_STOPBITS_1;
  UartHandle.Init.Parity     = UART_PARITY_NONE;
  UartHandle.Init.Mode       = UART_MODE_TX_RX;
  UartHandle.Init.HwFlowCtl  = UART_HWCONTROL_NONE;
  UartHandle.Init.OverSampling = UART_OVERSAMPLING_16;

  SFU_LL_UART_MspInit(&UartHandle);

  if (HAL_UART_Init(&UartHandle) != HAL_OK)
  {
    return SFU_ERROR;
  }
  return SFU_SUCCESS;
}

SFU_ErrorStatus SFU_LL_UART_DeInit(void)
{
  /* Left enabled on purpose, departing from ST.  ST's DeInit exists so the
   * user application can take the peripheral over; here the loader and the
   * trace share one UART, and tearing it down mid-boot would silence the
   * error reporting on precisely the paths that call DeInit. */
  return SFU_SUCCESS;
}

SFU_ErrorStatus SFU_LL_UART_Transmit(uint8_t *pData, uint16_t DataLength,
                                     uint32_t Timeout)
{
  return (HAL_UART_Transmit(&UartHandle, pData, DataLength, Timeout) == HAL_OK)
         ? SFU_SUCCESS : SFU_ERROR;
}

SFU_ErrorStatus SFU_LL_UART_Receive(uint8_t *pData, uint16_t DataLength,
                                    uint32_t Timeout)
{
  /* A timeout here is ORDINARY, not an error: YMODEM's whole flow control
   * is the sender and receiver timing each other out.  It still maps to
   * SFU_ERROR because that is what ST's callers expect of any non-success
   * -- sfu_com_loader.c distinguishes the cases by its own state machine,
   * not by the return code. */
  return (HAL_UART_Receive(&UartHandle, pData, DataLength, Timeout) == HAL_OK)
         ? SFU_SUCCESS : SFU_ERROR;
}

SFU_ErrorStatus SFU_LL_UART_Flush(void)
{
  __HAL_UART_CLEAR_FLAG(&UartHandle, UART_FLAG_RXNE);
  (void)UartHandle.Instance->DR;
  return SFU_SUCCESS;
}

void SFU_LL_UART_MspInit(UART_HandleTypeDef *huart)
{
  GPIO_InitTypeDef GPIO_InitStruct;

  if (huart->Instance != SFU_UART)
  {
    return;
  }

  SFU_UART_TX_GPIO_CLK_ENABLE();
  SFU_UART_RX_GPIO_CLK_ENABLE();
  SFU_UART_CLK_ENABLE();

  GPIO_InitStruct.Pin       = SFU_UART_TX_PIN;
  GPIO_InitStruct.Mode      = GPIO_MODE_AF_PP;
  GPIO_InitStruct.Pull      = GPIO_PULLUP;
  GPIO_InitStruct.Speed     = GPIO_SPEED_HIGH;
  GPIO_InitStruct.Alternate = SFU_UART_TX_AF;
  HAL_GPIO_Init(SFU_UART_TX_GPIO_PORT, &GPIO_InitStruct);

  GPIO_InitStruct.Pin       = SFU_UART_RX_PIN;
  GPIO_InitStruct.Alternate = SFU_UART_RX_AF;
  HAL_GPIO_Init(SFU_UART_RX_GPIO_PORT, &GPIO_InitStruct);
}

void SFU_LL_UART_MspDeInit(UART_HandleTypeDef *huart)
{
  if (huart->Instance != SFU_UART)
  {
    return;
  }
  SFU_UART_CLK_DISABLE();
  HAL_GPIO_DeInit(SFU_UART_TX_GPIO_PORT, SFU_UART_TX_PIN);
  HAL_GPIO_DeInit(SFU_UART_RX_GPIO_PORT, SFU_UART_RX_PIN);
}

/* ------------------------------------------------------------------- RTC -- */
/*
 * ST needs an RTC because its tamper detection is an RTC peripheral
 * function.  This board exposes no tamper input, so SFU_TAMPER_PROTECT_ENABLE
 * is off and these are compiled in but unreached -- which is exactly the
 * state ST's own #ifndef puts them in on a board without tamper.  Kept
 * rather than deleted so sfu_low_level_security.c can turn tamper on later
 * without this file needing to grow the support back.
 */
#ifndef SFU_TAMPER_PROTECT_ENABLE

static RTC_HandleTypeDef RtcHandle;

SFU_ErrorStatus SFU_LL_RTC_Init(void)
{
  RtcHandle.Instance            = RTC;
  RtcHandle.Init.HourFormat     = RTC_HOURFORMAT_24;
  RtcHandle.Init.AsynchPrediv   = RTC_ASYNCH_PREDIV;
  RtcHandle.Init.SynchPrediv    = RTC_SYNCH_PREDIV;
  RtcHandle.Init.OutPut         = RTC_OUTPUT_DISABLE;
  RtcHandle.Init.OutPutPolarity = RTC_OUTPUT_POLARITY_HIGH;
  RtcHandle.Init.OutPutType     = RTC_OUTPUT_TYPE_OPENDRAIN;

  SFU_LL_RTC_MspInit(&RtcHandle);

  if (HAL_RTC_Init(&RtcHandle) != HAL_OK)
  {
    return SFU_ERROR;
  }
  return SFU_SUCCESS;
}

SFU_ErrorStatus SFU_LL_RTC_DeInit(void)
{
  if (HAL_RTC_DeInit(&RtcHandle) != HAL_OK)
  {
    return SFU_ERROR;
  }
  return SFU_SUCCESS;
}

#endif /* SFU_TAMPER_PROTECT_ENABLE */

void SFU_LL_RTC_MspInit(RTC_HandleTypeDef *hrtc)
{
  RCC_OscInitTypeDef        RCC_OscInitStruct;
  RCC_PeriphCLKInitTypeDef  PeriphClkInitStruct;

  (void)hrtc;

  /* The LSI, as ST selects.  On this part it is also the IWDG's clock, and
   * sfu_low_level_security.c starts the watchdog, so it is on either way. */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_LSI;
  RCC_OscInitStruct.PLL.PLLState   = RCC_PLL_NONE;
  RCC_OscInitStruct.LSIState       = RCC_LSI_ON;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    SFU_LL_Error_Handler();
  }

  PeriphClkInitStruct.PeriphClockSelection = RCC_PERIPHCLK_RTC;
  PeriphClkInitStruct.RTCClockSelection    = RCC_RTCCLKSOURCE_LSI;
  if (HAL_RCCEx_PeriphCLKConfig(&PeriphClkInitStruct) != HAL_OK)
  {
    SFU_LL_Error_Handler();
  }

  __HAL_RCC_RTC_ENABLE();
}

void SFU_LL_RTC_MspDeInit(RTC_HandleTypeDef *hrtc)
{
  (void)hrtc;
  __HAL_RCC_RTC_DISABLE();
}

/* ----------------------------------------------------------------- error -- */

static void SFU_LL_Error_Handler(void)
{
  /* ST spins here.  So does this: a low-level failure before the boot state
   * machine exists has nowhere to report to, and continuing would run the
   * bootloader with a peripheral it believes is configured and is not. */
  while (1 == 1)
  {
    ;
  }
}
