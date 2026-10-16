/**
  ******************************************************************************
  * @file    sfu_low_level.c
  * @brief   SFU low-level interface, SAM D21 Xplained Pro.
  *          UART for the local YMODEM loader and the trace output, and the
  *          CRC the YMODEM packet check needs.
  ******************************************************************************
  */
#define SFU_LOW_LEVEL_C

#include "sfu_low_level.h"
#include "samd21_hal.h"

/* THE CRC IS IN SOFTWARE, AND THAT IS NOT A SHORTCUT
 * ---------------------------------------------------
 * ST configures the STM32 CRC peripheral, and the SAM D21 does have a
 * hardware CRC -- DSU.CRC32 -- so the obvious port is to use it.  It is the
 * wrong answer, for a reason that only shows up if you look at what the CRC
 * is actually FOR.
 *
 * Across the whole SBSFU tree there is exactly ONE caller of
 * SFU_LL_CRC_Calculate: sfu_com_loader.c:473, checking a YMODEM packet.  That
 * needs CRC-16/CCITT -- poly 0x1021, init 0, no input or output inversion,
 * fed a byte at a time -- which is what ST's SFU_CRC_CONFIG_16BIT programs.
 * The DSU unit does CRC-32 with a fixed polynomial and cannot be made to do
 * CRC-16 at all.  So the hardware is not an option, and the choice is between
 * a correct software CRC-16 and a wrong hardware CRC-32.
 *
 * SFU_CRC_CONFIG_DEFAULT is the STM32 peripheral's default CRC-32 fed 32-bit
 * words.  SFU_LL_CRC_Init() selects it and nothing ever calculates with it,
 * so it is implemented for completeness and marked here as unexercised --
 * if a future caller appears, its result has not been checked against
 * anything.
 *
 * This is the shape of bug that ruins a bootloader port quietly: a CRC that
 * is self-consistent on the target and disagrees with the host, so every
 * transfer NAKs and the cause looks like a serial problem.
 */

static SFU_CRC_ConfigTypeDef crc_config = SFU_CRC_CONFIG_NONE;

SFU_ErrorStatus SFU_LL_Init(void)
{
  if (SFU_LL_CRC_Init() != SFU_SUCCESS)
  {
    return SFU_ERROR;
  }
  return SFU_LL_UART_Init();
}

SFU_ErrorStatus SFU_LL_DeInit(void)
{
  return SFU_LL_UART_DeInit();
}

/* ------------------------------------------------------------------- CRC -- */

SFU_ErrorStatus SFU_LL_CRC_Init(void)
{
  return SFU_LL_CRC_Config(SFU_CRC_CONFIG_DEFAULT);
}

SFU_ErrorStatus SFU_LL_CRC_Config(SFU_CRC_ConfigTypeDef eCRCConfg)
{
  if (!IS_SFU_CRC_CONF(eCRCConfg))
  {
    return SFU_ERROR;
  }
  crc_config = eCRCConfg;
  return SFU_SUCCESS;
}

uint32_t SFU_LL_CRC_Calculate(uint32_t pBuffer[], uint32_t BufferLength)
{
  const uint8_t *p = (const uint8_t *)(const void *)pBuffer;
  uint32_t i;
  uint32_t j;

  if (crc_config == SFU_CRC_CONFIG_16BIT)
  {
    /* CRC-16/CCITT ("XMODEM"): poly 0x1021, init 0x0000, not reflected, no
     * final XOR.  BufferLength is a BYTE count in this configuration --
     * sfu_com_loader.c passes packet_size -- which is why the cast above is
     * to uint8_t despite the uint32_t* parameter.  ST's prototype takes
     * uint32_t* because the peripheral's 32-bit configuration wants one; the
     * caller already casts a uint8_t* into it. */
    uint32_t crc = 0U;

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

  /* SFU_CRC_CONFIG_DEFAULT: the STM32 peripheral's CRC-32, poly 0x04C11DB7,
   * init 0xFFFFFFFF, MSB-first over 32-bit words with no reflection and no
   * final XOR.  UNEXERCISED -- nothing in the tree calculates with this
   * configuration.  See the note at the top of this file. */
  {
    uint32_t crc = 0xFFFFFFFFUL;

    for (i = 0U; i < BufferLength; i++)
    {
      crc ^= pBuffer[i];
      for (j = 0U; j < 32U; j++)
      {
        crc = ((crc & 0x80000000UL) != 0U) ? ((crc << 1) ^ 0x04C11DB7UL)
                                           : (crc << 1);
      }
    }
    return crc;
  }
}

/* ------------------------------------------------------------------ UART -- */
/*
 * SERCOM3 on PA22/PA23 -- the EDBG virtual COM port (user guide Table 4-10),
 * so an image is staged over the same USB cable that programs and debugs the
 * board.  115200 8N1 matches what ST's projects use and what the YMODEM
 * senders on the host side default to.
 */
#define SFU_UART_BAUD   (115200UL)

SFU_ErrorStatus SFU_LL_UART_Init(void)
{
  HAL_UART_Init(SFU_UART_BAUD);
  return SFU_SUCCESS;
}

SFU_ErrorStatus SFU_LL_UART_DeInit(void)
{
  /* Left enabled on purpose.  ST's DeInit exists so the user application can
   * take the peripheral over; here the loader and the trace share one UART
   * and tearing it down mid-boot would silence the error reporting on
   * precisely the paths that call DeInit. */
  return SFU_SUCCESS;
}

SFU_ErrorStatus SFU_LL_UART_Transmit(uint8_t *pData, uint16_t DataLength,
                                     uint32_t Timeout)
{
  return (HAL_UART_Transmit(pData, DataLength, Timeout) == HAL_OK)
         ? SFU_SUCCESS : SFU_ERROR;
}

SFU_ErrorStatus SFU_LL_UART_Receive(uint8_t *pData, uint16_t DataLength,
                                    uint32_t Timeout)
{
  /* A timeout here is ORDINARY, not an error: YMODEM's whole flow control is
   * the sender and receiver timing each other out.  It still maps to
   * SFU_ERROR because that is what ST's callers expect of any non-success --
   * sfu_com_loader.c distinguishes the cases by its own state machine, not by
   * the return code. */
  return (HAL_UART_Receive(pData, DataLength, Timeout) == HAL_OK)
         ? SFU_SUCCESS : SFU_ERROR;
}

SFU_ErrorStatus SFU_LL_UART_Flush(void)
{
  HAL_UART_Flush();
  return SFU_SUCCESS;
}
