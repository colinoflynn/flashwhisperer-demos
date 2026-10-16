/**
  ******************************************************************************
  * @file    samd21_hal.h
  * @brief   The SAM D21 "HAL" this SBSFU port adds, in place of STM32Cube's.
  *
  * WHAT THIS IS, AND WHY IT IS THIS SMALL
  * ---------------------------------------
  * X-CUBE-SBSFU is written against STM32Cube HAL, so porting it to another
  * vendor sounds like it means reimplementing STM32Cube.  It does not.  The
  * SBSFU application layer -- Projects/<board>/Applications/.../SBSFU/App/ --
  * barely touches the HAL at all, because ST already factored the
  * chip-specific work out into SBSFU/Target/ and SECoreBin/, which every board
  * port is EXPECTED to rewrite.  That is the seam this port uses.
  *
  * Across the files this port compiles, the complete set of STM32Cube symbols
  * referenced is:
  *
  *     HAL_Delay                 sfu_boot.c, sfu_loader.c, sfu_error.c
  *     HAL_SuspendTick           sfu_boot.c, sfu_fwimg_common.c
  *     HAL_MPU_Disable           sfu_fwimg_common.c
  *     __HAL_FIREWALL_IS_ENABLED sfu_boot.c
  *     HAL_StatusTypeDef and
  *       HAL_OK/HAL_ERROR/HAL_BUSY    sfu_com_loader.c (YMODEM return type)
  *
  * and that is all of it.  sfu_fwimg_no_swap.c -- the read/decrypt/hash loop
  * this whole campaign targets -- references NONE of them.  So this header is
  * five declarations and an enum rather than a port of STM32Cube, and ST's
  * application files compile unmodified against it.
  *
  * The rest of the file is the part that IS real work: clocks, the flash read
  * path, the UART the YMODEM loader needs, and the watchdog.  Those are
  * declared here and implemented in samd21_hal.c, and they are called from
  * SBSFU/Target/sfu_low_level*.c, which is a file ST expects a port to write.
  ******************************************************************************
  */
#ifndef SAMD21_HAL_H
#define SAMD21_HAL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/* ------------------------------------------------- STM32Cube compatibility -- */

typedef enum
{
  HAL_OK      = 0x00U,
  HAL_ERROR   = 0x01U,
  HAL_BUSY    = 0x02U,
  HAL_TIMEOUT = 0x03U
} HAL_StatusTypeDef;

#ifndef RESET
#define RESET   (0U)
#define SET     (1U)
#endif

/** The SAM D21 has no Cortex-M0+ MPU option fitted -- checked on this die, not
  * assumed: MPU_TYPE at 0xE000ED90 reads 0, which HAL_MPU_Disable() asserts at
  * run time rather than trusting this comment.  ST calls this immediately
  * before jumping to the user application to drop the bootloader's own MPU
  * regions; with no MPU there are none to drop. */
void HAL_MPU_Disable(void);

/** No firewall peripheral exists on this part.  ST's sfu_boot.c uses this to
  * decide whether the Secure Engine is already isolated; answering RESET puts
  * the port on the same path ST's own G0/L0 projects take, which are also
  * firewall-less. */
#define __HAL_FIREWALL_IS_ENABLED()   (RESET)

void     HAL_Init(void);
uint32_t HAL_GetTick(void);
void     HAL_Delay(uint32_t Delay);
void     HAL_SuspendTick(void);
void     HAL_ResumeTick(void);

/* ------------------------------------------------------------- clock tree -- */
/*
 * The bootloader runs the part at its rated maximum, which is both what a
 * shipped product does and -- not by coincidence -- the configuration
 * research/targets/samd21j18a.md measured the channel in: DFLL48M open loop,
 * CPUSEL = /1, RWS = 1, READMODE = NO_MISS_PENALTY, cache enabled.  The last
 * three are the NVMCTRL reset state apart from RWS, which 48 MHz requires.
 */
#define SAMD21_CPU_HZ        (48000000UL)

/** Generic clock generator feeding SERCOM3 (UART) and SERCOM5 (SPI flash).
  * Generator 0 is the CPU's, so the SPI rate tracks SAMD21_CPU_HZ. */
#define SPIF_GCLK_GEN        (0U)

/** SERCOM SPI: f_SCK = f_ref / (2 * (BAUD + 1)).  48 MHz / (2 * 3) = 8 MHz,
  * the rate BOOTLOADER_SPI_ORACLE.md section 1 costs its bus-time estimates
  * at.  Derived from SAMD21_CPU_HZ rather than written as a literal, so
  * moving the clock axis cannot silently move the bus rate -- which would
  * change the fixed part of every interval the attacker measures and make two
  * captures incomparable without anything in the build saying so. */
#define SPIF_TARGET_SCK_HZ   (8000000UL)
#define SPIF_BAUD            ((SAMD21_CPU_HZ / (2UL * SPIF_TARGET_SCK_HZ)) - 1UL)

/** Bring the core to SAMD21_CPU_HZ with wait states set safely on the way.
  * Must be the first thing main() calls. */
void HAL_ClockInit(void);

/* --------------------------------------------------------- flash read path -- */
/*
 * NVMCTRL.CTRLB is the entire flash read-acceleration configuration on this
 * part, and it is the demo's mitigation axis.  The dossier attacked all four
 * settings rather than assuming them:
 *
 *   READMODE = NO_MISS_PENALTY (0), cache on   -- ships this way; 15/16 key
 *                                                 bytes at 400 000 traces
 *   READMODE = LOW_POWER       (1)             -- WORSE: 16/16 at 100 000,
 *                                                 and at RWS = 0
 *   READMODE = DETERMINISTIC   (2)             -- holds: 0/16, 1.60x runtime
 *   CACHEDIS = 1                               -- holds: 0/16, 1.21x runtime
 *
 * Exposed as a build-time configuration so the demo can be flashed in the
 * shipped configuration or in either mitigated one without editing source.
 */
#define SAMD21_READMODE_NO_MISS_PENALTY  (0U)
#define SAMD21_READMODE_LOW_POWER        (1U)
#define SAMD21_READMODE_DETERMINISTIC    (2U)

/* The configuration the image is built for.  Defaults are the SHIPPED state:
 * the NVMCTRL reset values for READMODE and CACHEDIS, and the one wait state
 * that 48 MHz requires.  Override from the Makefile (MITIGATE=deterministic
 * or MITIGATE=cachedis) to build the same bootloader with the mitigation the
 * dossier proved, so the two can be attacked back to back. */
#ifndef SBSFU_NVM_RWS
#define SBSFU_NVM_RWS        (1U)
#endif
#ifndef SBSFU_NVM_READMODE
#define SBSFU_NVM_READMODE   SAMD21_READMODE_NO_MISS_PENALTY
#endif
#ifndef SBSFU_NVM_CACHEDIS
#define SBSFU_NVM_CACHEDIS   (0U)
#endif

void HAL_FlashReadPathConfig(uint32_t rws, uint32_t readmode, uint32_t cachedis);

/** Invalidate every cache line (NVMCTRL CMD = INVALL).  _PROCEDURE.md section
  * 3 asks for caches to be RESET rather than merely disabled; on this part
  * that is a real command rather than a bit-toggling dance. */
void HAL_FlashCacheInvalidate(void);

/* -------------------------------------------------------------------- UART -- */
/*
 * SERCOM3 on PA22 (TXD) / PA23 (RXD), mux C -- the EDBG virtual COM port, per
 * the user guide's Table 4-10.  This is the transport SBSFU's local YMODEM
 * loader and its trace output both use, so on this board an image is staged
 * over the same USB cable that programs and debugs it.
 */
void              HAL_UART_Init(uint32_t baud);
HAL_StatusTypeDef HAL_UART_Transmit(const uint8_t *pData, uint16_t Size,
                                    uint32_t Timeout);
HAL_StatusTypeDef HAL_UART_Receive(uint8_t *pData, uint16_t Size,
                                   uint32_t Timeout);
void              HAL_UART_Flush(void);

/* ---------------------------------------------------------------- watchdog -- */
/*
 * Backs SFU_IWDG_PROTECT_ENABLE.  The SAM D21 WDT is an early-warning-capable
 * window watchdog clocked from a generic clock; the port runs it in normal
 * mode off the ultra-low-power 32 kHz oscillator so its timeout does not move
 * when the CPU clock axis does.
 */
void HAL_WDT_Init(uint32_t timeout_s);
void HAL_WDT_Refresh(void);

/** 0 once the watchdog is armed; non-zero says which step of HAL_WDT_Init
  * gave up.  A watchdog that silently failed to start is a protection the
  * device does not have, so the state is readable rather than assumed. */
uint8_t HAL_WDT_Status(void);

#ifdef __cplusplus
}
#endif

#endif /* SAMD21_HAL_H */
