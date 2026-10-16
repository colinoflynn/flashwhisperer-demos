/**
  ******************************************************************************
  * @file    se_low_level.c
  * @brief   Secure Engine low-level services, NUCLEO-L152RE.
  *
  * Ported from ST's
  * Projects/B-L475E-IOT01A/.../2_Images_SECoreBin/Src/se_low_level.c.
  * On an ST part most of this is HAL calls or pointer arithmetic against
  * linker symbols, so what follows is close to ST's.  Three things differ,
  * and each is noted where it happens: the CRC, the register scrub, and
  * SE_LL_Lock_Keys.
  ******************************************************************************
  */
#include "se_low_level.h"
#include "sfu_low_level_flash_int.h"
#include "string.h"

/* The part's own memory map, from stm32l152xe.h.  Named here rather than
 * written inline so the bounds checks below read as assertions about this
 * part -- ST's version has 0x20017FFF and 0x10007FFF spelled out, which are
 * an L4's numbers and would be silently wrong here. */
#define L152_SRAM_START    (SRAM_BASE)
#define L152_SRAM_END      (SRAM_BASE + (80U * 1024U) - 1UL)
#define L152_FLASH_START   (FLASH_BASE)
#define L152_FLASH_END     (FLASH_END)

static CRC_HandleTypeDef CrcHandle;

/* ------------------------------------------------------------- cleanup -- */

void SE_LL_CORE_Cleanup(void)
{
  /* ST scrubs the registers that could carry a secret out of the protected
   * area as the firewall closes.  With no isolation there is no transition
   * to scrub at, but the scrub is still worth doing: the Secure Engine has
   * just had round keys in registers and the caller is ordinary bootloader
   * code in the same address space.
   *
   * This is ARMv7-M, so unlike the SAM D21's copy the high registers are
   * reachable directly and the scrub can cover r4-r11 as well.  It is
   * still WEAKER THAN ST'S, for a reason that cannot be engineered away
   * here: without isolation, "outside the Secure Engine" and "inside" are
   * the same privilege level and the same stack, so anything spilled to
   * that stack is still there.
   *
   * r0-r3 and r12 are caller-saved and the compiler may use them after
   * this; r4-r11 are callee-saved, so they are listed as clobbers and GCC
   * restores them. */
  __asm volatile(
      "mov r0, #0  \n"
      "mov r1, #0  \n"
      "mov r2, #0  \n"
      "mov r3, #0  \n"
      "mov r4, #0  \n"
      "mov r5, #0  \n"
      "mov r6, #0  \n"
      "mov r7, #0  \n"
      "mov r8, #0  \n"
      "mov r9, #0  \n"
      "mov r10, #0 \n"
      "mov r11, #0 \n"
      "mov r12, #0 \n"
      ::: "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
          "r8", "r9", "r10", "r11", "r12", "memory");
  __DSB();
}

/* ------------------------------------------------------------------- CRC -- */
/*
 * IN HARDWARE, unlike sfu_low_level.c's 16-bit CRC and unlike the SAM D21's
 * copy of this file.  What the Secure Engine's callers need here is the
 * STM32 peripheral's default CRC-32 over 32-bit words -- poly 0x04C11DB7,
 * init 0xFFFFFFFF, no reflection, no final XOR -- and that is EXACTLY what
 * the L1's fixed-function unit computes.  No configuration is needed
 * because none is possible, which for once makes the port shorter than
 * ST's rather than longer.
 */

SE_ErrorStatus SE_LL_CRC_Config(void)
{
  /* ST programs polynomial, init value and input format here.  The L1's
   * CRC_HandleTypeDef has no Init member at all -- it is {Instance, Lock,
   * State} -- so there is nothing to configure and nothing that can be
   * configured wrongly. */
  return SE_SUCCESS;
}

SE_ErrorStatus SE_LL_CRC_Init(void)
{
  __HAL_RCC_CRC_CLK_ENABLE();

  CrcHandle.Instance = CRC;
  if (HAL_CRC_Init(&CrcHandle) != HAL_OK)
  {
    return SE_ERROR;
  }
  return SE_LL_CRC_Config();
}

SE_ErrorStatus SE_LL_CRC_DeInit(void)
{
  if (HAL_CRC_DeInit(&CrcHandle) != HAL_OK)
  {
    return SE_ERROR;
  }
  return SE_SUCCESS;
}

uint32_t SE_LL_CRC_Calculate(uint32_t pBuffer[], uint32_t uBufferLength)
{
  return HAL_CRC_Calculate(&CrcHandle, pBuffer, uBufferLength);
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
  /* READS DIRECTLY.  IT MUST NOT CALL SFU_LL_FLASH_INT_Read, AND THAT IS
   * A CORRECTNESS REQUIREMENT, NOT A SHORTCUT.
   *
   * SFU_LL_FLASH_INT_Read asks whether the address lies inside a firmware
   * image header, and if it does it routes the read through the Secure
   * Engine -- SE_SFU_IMG_Read, which enters the call gate with
   * SE_IMG_READ.  The call gate dispatches that to se_fwimg.c, which
   * calls THIS function.  Delegating back to SFU_LL_FLASH_INT_Read closes
   * the loop: every header read recurses until the stack runs out.
   *
   * In ST's design the loop cannot form, because SECoreBin is a SEPARATE
   * BINARY: the SE's copy of SE_LL_FLASH_Read reads flash itself and has
   * no way to reach SBSFU's layer at all.  Collapsing the two images into
   * one -- which this port does, having no isolation to express with the
   * split -- is what makes the two names resolve to each other.
   *
   * MEASURED, on this board: the trace showed the call gate entered with
   * eID 0x92 over and over, the status pointer walking down the stack
   * 0x90 bytes at a time, from 0x2000b8ec and falling, until the fault.
   *
   * It applies to the SAM D21 port next door as well -- that port's
   * se_low_level.c delegates the same way, and its install is recorded as
   * "does not finalise" with VerifySlot suspected.  Worth checking there
   * against this.
   *
   * There is nothing for the SE to add on this part anyway: with no
   * isolation the header is ordinary readable flash, and the indirection
   * exists on ST's silicon to cross a firewall that is not here. */
  (void)memcpy(pDestination, pSource, Length);
  return SE_SUCCESS;
}

SE_ErrorStatus SE_LL_FLASH_EXT_Decrypt_Init(SE_FwRawHeaderTypeDef *pxSE_Metadata)
{
  /* ST uses this on parts where the external memory controller can decrypt
   * on the fly (OTFDEC on the H7), so execute-in-place from encrypted
   * external flash works.  SPI2 is a serial port, not a memory controller,
   * and there is no such engine on this part -- which is exactly why the
   * decryption happens in software where it can be timed, and therefore
   * why this board is a target at all.  Nothing to configure. */
  (void)pxSE_Metadata;
  return SE_SUCCESS;
}

/* ------------------------------------------------------- security reset -- */
/*
 * A security reset must still be diagnosable.
 *
 * ST resets the part when a caller hands the Secure Engine a pointer
 * outside the region it claims, on the grounds that a bad pointer there is
 * an attack rather than a bug.  That is right, and it is kept.  But an
 * unexplained reset is indistinguishable from a watchdog, a brown-out or a
 * hard fault, and the SAM D21 bring-up spent a long time rebooting in a
 * loop with no output at all because of exactly this call.
 *
 * So the reason is written to a .noinit record that main() prints on the
 * next boot.  It costs three stores on a path that ends in a reset anyway,
 * and it turns "the board restarts" into "SE_LL_Buffer_in_ram rejected
 * 0x........".
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
 * ST resets the part on a violation rather than returning an error.  That
 * is kept: it is the right call, and it is MORE important on this port, not
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

  if ((addr_start >= L152_SRAM_START) && (addr_end <= L152_SRAM_END))
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
   * containment, and se_callgate.c uses it to REFUSE a request.  So it must
   * not reset on a "bad" answer -- the bad answer IS the answer.
   *
   * This is the function that cost the SAM D21 port a day.  With the stack
   * placed in SE RAM, every SE call passed a status pointer that lives on
   * the stack, this returned SE_SUCCESS, and se_callgate.c:236 reset the
   * board -- silently, before anything printed.  mapping_sbsfu.ld puts the
   * stack in SBSFU RAM for that reason and says so at length. */
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

/* ------------------------------------------------------------- key lock -- */

SE_ErrorStatus SE_LL_Lock_Keys(void)
{
  /* ST locks the key region behind the firewall so that nothing after this
   * point can read it.  THERE IS NO FIREWALL HERE.
   *
   * The MPU this die does have cannot stand in.  An MPU region made
   * inaccessible is inaccessible to unprivileged code; everything in this
   * port runs privileged, and privileged code can reprogram MPU_RASR and
   * read the key anyway.  Making the region privileged-only would stop
   * nothing, because there is nothing unprivileged to stop.
   *
   * Returning SE_ERROR would be the literal truth but would abort the
   * boot.  Returning SE_SUCCESS silently would misreport the device's
   * posture.  The resolution is to return success -- the boot must proceed
   * for the demo to be a demo -- and to have said, loudly and in three
   * places (here, se_low_level.h, and the port README), that on this
   * configuration the firmware encryption key remains readable by any code
   * running on the device after this call.
   *
   * That is a real and material weakness relative to ST's reference
   * configuration.  It is also orthogonal to what this demo measures: the
   * attack recovers the key from outside the chip without executing
   * anything on it, so a working key lock would not have stopped it. */
  return SE_SUCCESS;
}
