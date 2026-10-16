/**
  ******************************************************************************
  * @file    l152_nucleo_spif.h
  * @brief   Serial NOR flash on SPI2 of a NUCLEO-L152RE, behind the exact API
  *          X-CUBE-SBSFU's external-flash layer already calls.
  *
  * WHY THE FUNCTIONS ARE CALLED BSP_QSPI_* ON A PART WITH NO QSPI
  * --------------------------------------------------------------
  * ST's `sfu_low_level_flash_ext.c` calls `BSP_QSPI_Init`, `BSP_QSPI_Read`,
  * `BSP_QSPI_Write`, `BSP_QSPI_Erase_Block` and `BSP_QSPI_GetStatus`, and
  * compares against `QSPI_OK`.  Keeping those names means that file is ported
  * by changing ONE LINE -- its `#include "stm32l475e_iot01_qspi.h"` becomes
  * `#include "l152_nucleo_spif.h"` -- and every other line, including the
  * chip-select behaviour the whole timing attack depends on, stays ST's.
  *
  * The signatures are byte-for-byte ST's, from
  * Drivers/BSP/B-L475E-IOT01/stm32l475e_iot01_qspi.h in X-CUBE-SBSFU v2.7.0,
  * and identical to the SAM D21 port's BSP next door
  * (rigs/fw_samd21_sbsfu/SAMD21_XPRO/BSP/samd21_xpro_spif.h), deliberately:
  * two boards behind one API is what makes the two captures comparable.
  *
  * WIRING, as fitted on this bench
  * -------------------------------
  *     PB13  SPI2_SCK   (AF5)   -> SCK   CN10 pin 30
  *     PB14  SPI2_MISO  (AF5)   -> SO    CN10 pin 28
  *     PB15  SPI2_MOSI  (AF5)   -> SI    CN10 pin 26
  *     PA8   GPIO out, software -> /CS   CN9  pin 8  (Arduino D7)
  *
  * CHIP-SELECT IS A PLAIN GPIO, NOT SPI2_NSS, AND THAT IS THE WHOLE ATTACK.
  * PA8 is not an NSS pin for SPI2 (that would be PB12), so hardware framing
  * is not even available here and `SPI_NSS_SOFT` is forced.  The envelope
  * around each read is therefore produced by THIS CODE: CS falls when the
  * driver says so and rises when the driver says so, with the cipher running
  * in between, so both delimiters the attacker times are edges the victim's
  * own C produces.  Shipped drivers frame the same way -- wolfBoot
  * src/spi_flash.c:259, Gecko btl_storage_spiflash.c:482 -- which is why a
  * rig that framed differently would be measuring something no product does.
  *
  * ONE CHIP-SELECT ENVELOPE PER READ.  BSP_QSPI_Read asserts CS, sends the
  * opcode and the 24-bit address, clocks out the whole Size, and releases CS.
  * It does not split a long read and it does not hold CS across reads.
  *
  * The memory is single-bit SPI with no memory-mapped window and no XIP, so
  * every read is an explicit bus transaction inside one chip-select envelope
  * -- the geometry research/exposure/BOOTLOADER_SPI_ORACLE.md section 1
  * describes.  ST's own external path on the L475 is indirect-mode QSPI for
  * the same reason.
  ******************************************************************************
  */
#ifndef L152_NUCLEO_SPIF_H
#define L152_NUCLEO_SPIF_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/* Return codes -- ST's values, so `!= QSPI_OK` keeps meaning what it meant. */
#define QSPI_OK            ((uint8_t)0x00)
#define QSPI_ERROR         ((uint8_t)0x01)
#define QSPI_BUSY          ((uint8_t)0x02)
#define QSPI_NOT_SUPPORTED ((uint8_t)0x04)

/* Geometry is READ OFF THE PART at init, not compiled in.
 *
 * The SAM D21 port hardcoded an AT25DF081A because that chip is soldered to
 * that board.  Here the memory is on flying leads and can be changed between
 * sessions, so a hardcoded size would silently mean "the write ran off the
 * end and the driver did not say so".  BSP_QSPI_GetInfo reports what the
 * JEDEC ID resolved to, and BSP_QSPI_Init FAILS on an ID it does not know
 * rather than guessing a size.
 *
 * Page and sector sizes are 256 and 4096 on every part in the table, which
 * is close enough to universal among serial NOR that they stay constants;
 * the capacity is the byte that actually differs. */
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
 * verified is not evidence.  Returns the three JEDEC bytes.
 *
 * It works BEFORE BSP_QSPI_Init has succeeded -- it only needs the pins and
 * the peripheral, not a recognised part -- which is the point: when the ID
 * is the thing that failed, the caller still needs to see what came back. */
uint8_t BSP_SPIF_ReadId(uint8_t id[3]);

/** Bring-up only: change the bus rate, and probe the four lines as GPIO.
  * Neither is called from the bootloader path -- a capture runs at one
  * fixed rate, and that rate is part of what is being measured.
  *
  * BSP_SPIF_ProbeWiring returns bit0 "MISO floats high under a pull-up",
  * bit1 "MISO follows a pull-down", and bits 4..19 a short matrix of four
  * bits per driven pin in the order CS, SCK, MISO, MOSI: bit (4 + 4i + j)
  * means pin j went low while only pin i was driven low. */
uint8_t BSP_SPIF_SetBaudPrescaler(uint32_t prescaler);
uint32_t BSP_SPIF_ProbeWiring(void);

/** Bit-banged JEDEC ID, all four lines driven as GPIO, with `swap_data`
  * exchanging the roles of PB14 and PB15.  SI and SO crossed is the
  * commonest four-lead mistake and no other test here can see it: SPI2's
  * alternate functions are fixed in silicon, so asking the question at all
  * means clocking the transaction by hand. */
uint8_t BSP_SPIF_BitbangId(uint8_t id[3], int swap_data);

/** Bring-up only: hand ONE line to the caller as a plain GPIO output so it
  * can be driven slowly enough to find with a meter, leaving the other
  * three as unpulled inputs so nothing else on the harness is driven.
  * Index order matches the short matrix: 0 CS, 1 SCK, 2 MISO, 3 MOSI.
  * BSP_SPIF_PinRestore puts the peripheral back. */
/** Bring-up only: how many core cycles each line takes to be dragged up by
  * its own pull-up, which is a capacitance measurement in disguise and the
  * only probe here that answers "is there a wire on this pin".  Six
  * readings: CS, SCK, MISO, MOSI, then PA9 and PB12 as bare references on
  * the same two connectors.  A bus line that matches its reference has
  * nothing hanging off it. Requires DWT->CYCCNT to be running. */
void BSP_SPIF_ProbeLoad(uint32_t out[6]);

uint8_t BSP_SPIF_PinGpioMode(int idx);
void BSP_SPIF_PinWrite(int idx, int level);
void BSP_SPIF_PinRestore(void);

/** Status register 1, raw.  The block-protection bits live here and an
  * unexpected value is the usual reason a program or erase "succeeds" and
  * changes nothing; see the unprotect step in BSP_QSPI_Init. */
uint8_t BSP_SPIF_ReadStatus(uint8_t *sr1);

/** The JEDEC ID the last BSP_QSPI_Init read, packed MFR<<16 | TYPE<<8 | CAP,
  * and a short name for it.  Valid after Init whether or not it succeeded. */
extern volatile uint32_t g_spif_jedec;
const char *BSP_SPIF_PartName(void);

/** Nonzero when the part is BIGGER than this driver's 24-bit addresses can
  * reach, so BSP_QSPI_GetInfo reports 16 MB for a 32 MB chip.  Everything
  * above that would alias to the start of the array with no error, which
  * is the one failure a bootloader must not have. */
int BSP_SPIF_SizeClamped(void);

/** Zero the bus counters unless they survived a warm reset.  Returns 1 if
  * they CARRIED OVER (so what they hold is the previous boot's pass), 0 if
  * they were just zeroed.  Must be called once, early: `.noinit` means
  * nothing else ever initialises them, and uninitialised SRAM printed as a
  * total looks exactly like a measurement. */
int BSP_SPIF_CountersInit(void);

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

#endif /* L152_NUCLEO_SPIF_H */
