/**
  ******************************************************************************
  * @file    se_low_level.c
  * @brief   Secure Engine low-level interface, SAM D21 Xplained Pro.
  *
  * The Secure Engine's own view of the hardware: flash access for the key and
  * image regions, a CRC, and the buffer-location checks that are the Secure
  * Engine's main defence against being asked to write its own memory.
  *
  * See se_low_level.h for why this port has NO hardware isolation, and what
  * that does and does not change.
  ******************************************************************************
  */
/* SE_LOW_LEVEL_C IS DELIBERATELY NOT DEFINED, though ST's version of this
 * file defines it.
 *
 * sfu_fwimg_regions.h DEFINES the SlotHeaderAdd / SlotStartAdd / SlotEndAdd
 * tables -- not just declares them -- when SFU_FWIMG_COMMON_C,
 * SE_LOW_LEVEL_C or TEST_PROTECTIONS_C is set.  In ST's build that is safe
 * because sfu_fwimg_common.c and se_low_level.c end up in two SEPARATE
 * BINARIES, each needing its own copy.
 *
 * This port links one image, so defining it here gives the linker two
 * definitions of all three tables.  The declarations in that header are
 * always visible, so dropping the define just means this file uses the
 * copies sfu_fwimg_common.c owns -- which is what a single image should do.
 * Nothing in this file reads them anyway.
 */

#include "se_low_level.h"
#include "sfu_low_level_flash_int.h"
#include "samd21_hal.h"
#include "samd21.h"

/* SAM D21 memory map, from samd21j18a.h.  Named here rather than used inline
 * so the bounds checks below read as assertions about this part instead of as
 * magic numbers -- ST's version has 0x20017FFF and 0x10007FFF written out,
 * which are an L4's and mean nothing here. */
#define SAMD21_SRAM_START    (HMCRAMC0_ADDR)
#define SAMD21_SRAM_END      (HMCRAMC0_ADDR + HMCRAMC0_SIZE - 1UL)
#define SAMD21_FLASH_START   (FLASH_ADDR)
#define SAMD21_FLASH_END     (FLASH_ADDR + FLASH_SIZE - 1UL)

/* ------------------------------------------------------------- cleanup -- */

void SE_LL_CORE_Cleanup(void)
{
  /* ST scrubs the registers that could carry a secret out of the protected
   * area when the firewall closes.  With no firewall there is no transition
   * to scrub at, but the scrub itself is still worth doing: the Secure
   * Engine has just had round keys in registers, and the caller is ordinary
   * bootloader code in the same address space.
   *
   * ARMv6-M has no high-register bulk moves, so this is written as an
   * explicit clear of the low registers the compiler may have spilled
   * through, plus a memory barrier.  It is weaker than ST's, and it is
   * weaker for a reason that cannot be engineered away here: without
   * isolation, "outside the Secure Engine" and "inside" are the same
   * privilege level and the same stack. */
  __asm volatile(
      "movs r0, #0 \n"
      "movs r1, #0 \n"
      "movs r2, #0 \n"
      "movs r3, #0 \n"
      ::: "r0", "r1", "r2", "r3", "memory");
  __DSB();
}

/* ------------------------------------------------------------------- CRC -- */
/*
 * Same reasoning as sfu_low_level.c: the DSU's hardware CRC is CRC-32 with a
 * fixed polynomial, and what the Secure Engine's callers need is the STM32
 * peripheral's default CRC-32 over 32-bit words.  Those are NOT the same
 * function -- the DSU reflects input and output and applies a final XOR,
 * the STM32 default does neither -- so the hardware cannot stand in, and a
 * software implementation that matches ST's definition is the only correct
 * answer.
 */

SE_ErrorStatus SE_LL_CRC_Init(void)
{
  return SE_SUCCESS;
}

SE_ErrorStatus SE_LL_CRC_Config(void)
{
  return SE_SUCCESS;
}

SE_ErrorStatus SE_LL_CRC_DeInit(void)
{
  return SE_SUCCESS;
}

uint32_t SE_LL_CRC_Calculate(uint32_t pBuffer[], uint32_t uBufferLength)
{
  uint32_t crc = 0xFFFFFFFFUL;
  uint32_t i;
  uint32_t j;

  for (i = 0U; i < uBufferLength; i++)
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

/* ----------------------------------------------------------------- flash -- */

SE_ErrorStatus SE_LL_FLASH_Erase(uint8_t *pStart, uint32_t Length)
{
  SFU_FLASH_StatusTypeDef st;

  return (SFU_LL_FLASH_INT_Erase_Size(&st, pStart, Length) == SFU_SUCCESS)
         ? SE_SUCCESS : SE_ERROR;
}

SE_ErrorStatus SE_LL_FLASH_Write(uint8_t *pDestination, const uint8_t *pSource,
                                 uint32_t Length)
{
  SFU_FLASH_StatusTypeDef st;

  return (SFU_LL_FLASH_INT_Write(&st, pDestination, pSource, Length) == SFU_SUCCESS)
         ? SE_SUCCESS : SE_ERROR;
}

SE_ErrorStatus SE_LL_FLASH_Read(uint8_t *pDestination, const uint8_t *pSource,
                                uint32_t Length)
{
  return (SFU_LL_FLASH_INT_Read(pDestination, pSource, Length) == SFU_SUCCESS)
         ? SE_SUCCESS : SE_ERROR;
}

SE_ErrorStatus SE_LL_FLASH_EXT_Decrypt_Init(SE_FwRawHeaderTypeDef *pxSE_Metadata)
{
  /* ST uses this on parts where the external flash controller can decrypt on
   * the fly (OTFDEC on the H7), so that execute-in-place from encrypted
   * external flash works.  SERCOM is a serial port, not a memory controller,
   * and there is no such engine on this part -- which is exactly why the
   * decryption happens in software where it can be timed, and therefore why
   * this board is the target.  Nothing to configure. */
  (void)pxSE_Metadata;
  return SE_SUCCESS;
}

/* A security reset must still be diagnosable.
 *
 * ST resets the part when a caller hands the Secure Engine a pointer outside
 * the region it claims, on the grounds that a bad pointer there is an attack
 * rather than a bug.  That is right, and it is kept.  But an unexplained
 * reset is indistinguishable from a watchdog, a brown-out or a hard fault,
 * and during bring-up this port spent a while rebooting in a loop with no
 * output at all because of exactly this call.
 *
 * So the reason is written to the same .noinit record startup.c uses for
 * faults, and main() prints it on the next boot.  It costs three stores on a
 * path that ends in a reset anyway, and it turns "the board restarts" into
 * "SE_LL_Buffer_in_ram rejected 0x........".
 */
extern volatile uint32_t g_fault[4];

#define SE_RESET_BUFFER_IN_RAM        (0x5E000001UL)
#define SE_RESET_BUFFER_IN_SBSFU_RAM  (0x5E000002UL)

static void se_security_reset(uint32_t reason, uint32_t addr, uint32_t len)
{
  g_fault[0] = 0xFA017000UL;
  g_fault[1] = reason;
  g_fault[2] = addr;
  g_fault[3] = len;
  __DSB();
  NVIC_SystemReset();
}

/* ------------------------------------------------------ buffer location -- */
/*
 * These are the Secure Engine's boundary checks: before acting on a pointer
 * the caller handed in, confirm it points where it claims to.  Without them
 * SBSFU could ask the Secure Engine to write a decrypted buffer over the
 * Secure Engine's own key.
 *
 * ST resets the part on a violation rather than returning an error, on the
 * grounds that a bad pointer here is an attack rather than a bug.  That is
 * kept: it is the right call, and it is MORE important on this port, not
 * less, because with no isolation these checks are the only thing standing
 * where the firewall would be.
 */

SE_ErrorStatus SE_LL_Buffer_in_ram(void *pBuff, uint32_t Length)
{
  uint32_t addr_start = (uint32_t)pBuff;
  uint32_t addr_end;

  /* Length 0 and address overflow are both rejected before the range test,
   * because addr_start + Length - 1 wraps and would otherwise let a
   * crafted length pass a range check it should fail. */
  if ((Length == 0U) || ((0xFFFFFFFFUL - addr_start) < Length))
  {
    se_security_reset(SE_RESET_BUFFER_IN_RAM, addr_start, Length);
  }
  addr_end = addr_start + Length - 1U;

  if ((addr_start >= SAMD21_SRAM_START) && (addr_end <= SAMD21_SRAM_END))
  {
    return SE_SUCCESS;
  }
  se_security_reset(SE_RESET_BUFFER_IN_RAM, addr_start, Length);
  return SE_ERROR;                      /* not reached */
}

SE_ErrorStatus SE_LL_Buffer_in_SBSFU_ram(const void *pBuff, uint32_t Length)
{
  uint32_t addr_start = (uint32_t)pBuff;
  uint32_t addr_end;

  if ((Length == 0U) || ((0xFFFFFFFFUL - addr_start) < Length))
  {
    se_security_reset(SE_RESET_BUFFER_IN_SBSFU_RAM, addr_start, Length);
  }
  addr_end = addr_start + Length - 1U;

  if ((addr_start >= SB_REGION_RAM_START) && (addr_end <= SB_REGION_RAM_END))
  {
    return SE_SUCCESS;
  }
  se_security_reset(SE_RESET_BUFFER_IN_SBSFU_RAM, addr_start, Length);
  return SE_ERROR;
}

SE_ErrorStatus SE_LL_Buffer_part_of_SE_ram(const void *pBuff, uint32_t Length)
{
  uint32_t addr_start = (uint32_t)pBuff;
  uint32_t addr_end;

  if ((Length == 0U) || ((0xFFFFFFFFUL - addr_start) < Length))
  {
    return SE_ERROR;
  }
  addr_end = addr_start + Length - 1U;

  /* Note the inverted sense: this one REPORTS overlap rather than demanding
   * containment, and callers use it to refuse a request.  So it must not
   * reset on a "bad" answer -- the bad answer IS the answer. */
  if ((addr_end >= SE_REGION_RAM_START) && (addr_start <= SE_REGION_RAM_END))
  {
    return SE_SUCCESS;                  /* it does overlap SE RAM */
  }
  return SE_ERROR;
}

SE_ErrorStatus SE_LL_Buffer_part_of_SE_rom(const void *pBuff, uint32_t Length)
{
  uint32_t addr_start = (uint32_t)pBuff;
  uint32_t addr_end;

  if ((Length == 0U) || ((0xFFFFFFFFUL - addr_start) < Length))
  {
    return SE_ERROR;
  }
  addr_end = addr_start + Length - 1U;

  if ((addr_end >= SE_CODE_REGION_ROM_START) && (addr_start <= SE_CODE_REGION_ROM_END))
  {
    return SE_SUCCESS;                  /* it does overlap SE ROM */
  }
  return SE_ERROR;
}

/* ------------------------------------------------------------ key lock -- */

SE_ErrorStatus SE_LL_Lock_Keys(void)
{
  /* ST locks the key region behind the firewall or an MPU region so that
   * nothing after this point can read it.  NEITHER EXISTS HERE, and there is
   * no NVMCTRL facility that makes flash unreadable to the CPU -- its LOCK
   * bits stop programming and erase, not reads.
   *
   * Returning SE_ERROR would be the literal truth but would abort the boot.
   * Returning SE_SUCCESS silently would misreport the device's posture.  The
   * resolution is to return success -- the boot must proceed for the demo to
   * be a demo -- and to have said, loudly and in three places (here,
   * se_low_level.h, and the port README), that on this part the firmware
   * encryption key remains readable by any code running on the device after
   * this call.
   *
   * That is a real and material weakness relative to ST's configuration. It
   * is also orthogonal to what this demo measures: the attack recovers the
   * key from outside the chip without executing anything on it, so a working
   * key lock would not have stopped it. */
  return SE_SUCCESS;
}
