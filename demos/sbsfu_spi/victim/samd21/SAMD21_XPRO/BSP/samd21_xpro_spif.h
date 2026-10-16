/**
  ******************************************************************************
  * @file    samd21_xpro_spif.h
  * @brief   SAM D21 Xplained Pro on-board serial flash, behind the exact API
  *          X-CUBE-SBSFU's external-flash layer already calls.
  *
  * WHY THE FUNCTIONS ARE CALLED BSP_QSPI_* ON A PART WITH NO QSPI
  * --------------------------------------------------------------
  * ST's `sfu_low_level_flash_ext.c` calls `BSP_QSPI_Init`, `BSP_QSPI_Read`,
  * `BSP_QSPI_Write`, `BSP_QSPI_Erase_Block` and `BSP_QSPI_GetStatus`, and
  * compares against `QSPI_OK`.  Keeping those names means that file is ported
  * by changing ONE LINE -- its `#include "stm32l475e_iot01_qspi.h"` becomes
  * `#include "samd21_xpro_spif.h"` -- and every other line, including the
  * chip-select behaviour the whole timing attack depends on, stays ST's.
  *
  * That is worth more than a tidier name.  The point of this port is to be a
  * fielded bootloader, not a rewrite of one, and a reviewer can diff our copy
  * of that file against ST's and see a single changed line.
  *
  * The signatures are byte-for-byte ST's, from
  * Drivers/BSP/B-L475E-IOT01/stm32l475e_iot01_qspi.h in X-CUBE-SBSFU v2.7.0.
  * The functions this port does not implement return QSPI_NOT_SUPPORTED
  * rather than being absent, so a caller that grows a dependency on one fails
  * at run time with a distinguishable code instead of at link time with a
  * mangled name.
  *
  * THE MEMORY IS SINGLE-BIT SPI, NOT QUAD, AND THAT IS THE POINT
  * -------------------------------------------------------------
  * An AT25DF081A on SERCOM5 in single-bit mode.  There is no memory-mapped
  * window and no XIP: every read is an explicit bus transaction inside one
  * chip-select envelope, which is exactly the geometry
  * research/exposure/BOOTLOADER_SPI_ORACLE.md section 1 describes and the
  * reason this board is the target.  ST's own external path on the L475 is
  * also indirect-mode QSPI for the same reason.
  ******************************************************************************
  */
#ifndef SAMD21_XPRO_SPIF_H
#define SAMD21_XPRO_SPIF_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/* Return codes -- ST's values, so `!= QSPI_OK` keeps meaning what it meant. */
#define QSPI_OK            ((uint8_t)0x00)
#define QSPI_ERROR         ((uint8_t)0x01)
#define QSPI_BUSY          ((uint8_t)0x02)
#define QSPI_NOT_SUPPORTED ((uint8_t)0x04)

/* AT25DF081A geometry, confirmed on this board by JEDEC ID 1F 45 01
 * (rigs/host/spitimer_wiring.py section C).  1 MB of ciphertext is 65 536
 * AES-CBC blocks, which is what puts this target above the 16 384-observation
 * threshold BOOTLOADER_SPI_ORACLE.md section 4C measures -- in ONE boot pass,
 * and with a fresh set on every re-image because CBC's AES input is the
 * ciphertext block itself. */
#define SPIF_FLASH_SIZE          (1024U * 1024U)   /* 8 Mbit                 */
#define SPIF_PAGE_SIZE           (256U)            /* program granularity    */
#define SPIF_SECTOR_SIZE         (4096U)           /* 0x20 erase             */
#define SPIF_BLOCK_SIZE          (65536U)          /* 0xD8 erase, ST's unit  */

typedef struct
{
  uint32_t FlashSize;
  uint32_t EraseSectorSize;
  uint32_t EraseSectorsNumber;
  uint32_t ProgPageSize;
  uint32_t ProgPagesNumber;
} QSPI_Info;

uint8_t BSP_QSPI_Init(void);
uint8_t BSP_QSPI_DeInit(void);
uint8_t BSP_QSPI_Read(uint8_t *pData, uint32_t ReadAddr, uint32_t Size);
uint8_t BSP_QSPI_Write(uint8_t *pData, uint32_t WriteAddr, uint32_t Size);
uint8_t BSP_QSPI_Erase_Block(uint32_t BlockAddress);
uint8_t BSP_QSPI_Erase_Sector(uint32_t Sector);
uint8_t BSP_QSPI_Erase_Chip(void);
uint8_t BSP_QSPI_GetStatus(void);
uint8_t BSP_QSPI_GetInfo(QSPI_Info *pInfo);
uint8_t BSP_QSPI_EnableMemoryMappedMode(void);

/* Not part of ST's API.  Used by the bring-up path to prove the driver is
 * talking to the chip before anything trusts a capture taken through it --
 * MEASURING_CHANNELS.md's rule that a statistic from a rig you have not
 * verified is not evidence.  Returns the three JEDEC bytes. */
uint8_t BSP_SPIF_ReadId(uint8_t id[3]);

/** Bus-transaction counters, for the envelope-count control in
  * rigs/fw_f303_spitimer/WIRING.md section 5 -- and, before that, to say
  * whether the decrypt loop ran at all.  Data reads and status polls are
  * counted apart because they are separate chip-select envelopes and the
  * capture has to tell them apart. */
extern volatile uint32_t g_spif_reads;
extern volatile uint32_t g_spif_read_bytes;
extern volatile uint32_t g_spif_status_polls;
extern volatile uint32_t g_spif_writes;
extern volatile uint32_t g_spif_erases;

/** Why the last BSP_QSPI_Read was rejected, if one was: bit31 set means a
  * rejection happened, bit0 = driver not ready, bit1 = null buffer,
  * bit2 = past the end of the chip.  Three causes share one QSPI_ERROR and
  * ST's callers collapse them further, so the reason is recorded where it
  * is known. */
extern volatile uint32_t g_spif_reject;
extern volatile uint32_t g_spif_reject_addr;
extern volatile uint32_t g_spif_reject_size;

#ifdef __cplusplus
}
#endif

#endif /* SAMD21_XPRO_SPIF_H */
