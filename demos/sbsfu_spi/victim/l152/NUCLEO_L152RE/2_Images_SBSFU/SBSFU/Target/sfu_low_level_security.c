/**
  ******************************************************************************
  * @file    sfu_low_level_security.c
  * @brief   Security services, NUCLEO-L152RE.
  *
  * WHAT THIS BOARD CAN AND CANNOT HONOUR, ONE PROTECTION AT A TIME
  * ---------------------------------------------------------------
  * ST's L4 port applies eight protections.  Porting them honestly means
  * saying, for each, whether the hardware exists -- not quietly returning
  * SFU_SUCCESS and leaving a reader to believe the bootloader is as hard as
  * ST's.  A demo that overstates its own defences is worse than one that
  * states none, because the measurement taken on it gets quoted as if the
  * defences were there.
  *
  *   ST protection      L152RE equivalent              this port
  *   -----------------  -----------------------------  ---------------------
  *   WRP  (write prot)  FLASH_WRPx option bytes, in    APPLIED, and VERIFIED
  *                      4 KB sectors                   by read-back
  *   RDP  (readout)     option byte, levels 0/1/2      NOT APPLIED, on
  *                                                     purpose -- see below
  *   FWALL (firewall)   does not exist on the L1; it   NOT AVAILABLE
  *                      is an L0/L4 peripheral
  *   MPU                FITTED.  MPU_TYPE reads        AVAILABLE, NOT YET
  *                      0x00000800 on this die --      APPLIED -- see below
  *                      eight regions, measured by
  *                      rigs/fw_l152_sbsfu/bringup
  *   DAP  (debug lock)  RDP level 1 already disables   NOT APPLIED, with RDP
  *                      flash access from the debug
  *                      port
  *   DMA                DMA1/DMA2 exist                APPLIED -- both are
  *                                                     left unclocked
  *   TAMPER             RTC_TAMP1 exists; no tamper    NOT AVAILABLE on this
  *                      input is wired on a NUCLEO-64  board
  *   IWDG               IWDG                           APPLIED
  *
  * THIS IS A STRONGER POSITION THAN THE SAM D21 PORT'S, AND WEAKER THAN
  * ST'S REFERENCE BOARD'S.  The SAM D21 had no MPU at all and no readout
  * protection that did not also fuse off SWD.  The L4 has a firewall that
  * makes the Secure Engine genuinely unreachable.  This part sits between:
  * real option-byte write protection, a real MPU, and no hardware
  * isolation for the Secure Engine.  Saying which of the three a result was
  * measured on is the point of writing the table out.
  *
  * WHY RDP IS DELIBERATELY NOT APPLIED, AND WHY THAT CHANGES NOTHING ABOUT
  * THE CHANNEL
  * -------------------------------------------------------------------------
  * Setting RDP level 1 blocks the debug port's view of flash, and every
  * measurement this demo exists to take is set up over SWD.  Worse, level 1
  * to level 0 is a mass erase, so a board left at level 1 costs a full
  * re-flash per experiment.  ST's own projects ship SFU_PROTECT_RDP_LEVEL at
  * level 1 rather than 2 "for debugging purposes" for the same reason, and
  * app_sfu.h warns that enabling SFU_DAP_PROTECT_ENABLE disconnects the
  * debugger.
  *
  * It matters for the write-up that this changes NOTHING about what is being
  * measured.  The attack is a timing side channel on a cipher, observed from
  * outside the chip on the SPI bus.  Readout protection does not slow the
  * cipher down, does not change which flash rows the S-box touches, and is
  * not on the attacker's path: a fielded device with RDP set leaks exactly
  * the same intervals on exactly the same pins.  What RDP protects is the
  * key at rest, which is precisely what the timing channel recovers without
  * reading it.
  *
  * WHY THE MPU IS AVAILABLE AND NOT YET APPLIED
  * ---------------------------------------------
  * This die has one, which is worth stating because the SAM D21's did not
  * and the difference was measured rather than read off a datasheet.  ST
  * uses the MPU for two things: making the Secure Engine's RAM and code
  * inaccessible to the application, and narrowing the user application's
  * view at hand-over.  The first needs a privilege boundary this port does
  * not have -- there is no firewall, the call gate is an ordinary function
  * call, and everything runs privileged in one address space -- so an MPU
  * region around the SE would be configured by the same code it is meant to
  * keep out.  Applying it would be a protection in name.  It is left off,
  * and left available, so a later experiment can turn it on deliberately
  * and say what it bought.
  ******************************************************************************
  */
/* main.h FIRST, as ST's own copy of this file does, and it is not
 * cosmetic: sfu_low_level_security.h reaches sfu_fwimg_regions.h,
 * which reaches mapping_export.h, which declares extern uint32_t
 * symbols and includes nothing.  ST gets stdint through
 * stm32l4xx_hal.h in main.h; include the port header first instead
 * and the build dies with forty "unknown type name uint32_t". */
#include "main.h"
#include "sfu_low_level_security.h"
#include "sfu_low_level_flash_int.h"
#include "sfu_low_level.h"
#include "sfu_trace.h"
/* FLOW_CONTROL_STEP, the FLOW_* constants and uFlowProtectValue. */
#include "sfu_boot.h"

/* ------------------------------------------------------------- watchdog -- */

static IWDG_HandleTypeDef IwdgHandle;

SFU_ErrorStatus SFU_LL_SECU_IWDG_Refresh(void)
{
#ifdef SFU_IWDG_PROTECT_ENABLE
  if (HAL_IWDG_Refresh(&IwdgHandle) != HAL_OK)
  {
    return SFU_ERROR;
  }
#endif /* SFU_IWDG_PROTECT_ENABLE */
  return SFU_SUCCESS;
}

/* --------------------------------------------------- static protections -- */

#ifdef SFU_WRP_PROTECT_ENABLE
/**
  * @brief  Write-protect the bootloader region through the option bytes.
  *
  * The L1's WRP granularity is a 4 KB SECTOR -- sixteen 256-byte pages --
  * and each bit of FLASH_WRPx covers one sector, so the region protected is
  * rounded UP to the next 4 KB boundary.  With SB_REGION_ROM_END at
  * 0x0802FDFF that rounds to 0x08030000, which is exactly where the active
  * slot starts: no overlap, and nothing wasted.  That is not luck, it is
  * why mapping_sbsfu.ld puts the boundary there.
  *
  * IT IS CHECKED BEFORE IT IS WRITTEN, and the write is skipped if the
  * option bytes already say what they should.  Programming option bytes
  * costs a system reset (HAL_FLASH_OB_Launch does not return), so a
  * bootloader that wrote them unconditionally would reset on every single
  * boot and never reach the state machine -- a boot loop that looks exactly
  * like a crash.
  */
static SFU_ErrorStatus apply_wrp(void)
{
  FLASH_OBProgramInitTypeDef ob_get;
  uint32_t n_sectors;
  uint32_t want0;
  uint32_t want1;

  /* THE L1'S OPTION-BYTE STRUCT IS NOT THE L4'S, and this is where that
   * bites.  ST's code reads `ob.WRPArea` and a single `ob.WRPSector`,
   * which is the L4's one-area-at-a-time model.  The L1 instead exposes
   * FOUR flat 32-bit masks -- WRPSector0To31, 32To63, 64To95, 96To127 --
   * one bit per 4 KB sector, covering all 128 sectors of a 512 KB part at
   * once.  There is no area selector to set.
   *
   * The bootloader region is FLASH_BASE..SB_REGION_ROM_END, which is
   * 0x08000000..0x0802FDFF, so 48 sectors: all 32 bits of the first mask
   * and the low 16 of the second. */
  n_sectors = ((SB_REGION_ROM_END - FLASH_BASE) / 0x1000U) + 1U;
  want0 = (n_sectors >= 32U) ? 0xFFFFFFFFU : ((1UL << n_sectors) - 1U);
  want1 = (n_sectors <= 32U) ? 0U
          : ((n_sectors >= 64U) ? 0xFFFFFFFFU
                                : ((1UL << (n_sectors - 32U)) - 1U));

  (void)memset(&ob_get, 0, sizeof(ob_get));
  HAL_FLASHEx_OBGetConfig(&ob_get);

  if (((ob_get.WRPSector0To31 & want0) == want0) &&
      ((ob_get.WRPSector32To63 & want1) == want1))
  {
    /* Already covered: nothing to do, and crucially no reset. */
    TRACE("\r\n= [SBOOT] WRP already covers the bootloader region\r\n");
    return SFU_SUCCESS;
  }

  /* NOT PROGRAMMED HERE, DELIBERATELY, AND THE BOOT IS NOT FAILED FOR IT.
   *
   * Writing these option bytes resets the board inside
   * HAL_FLASH_OB_Launch, and doing that from a bootloader whose own
   * correctness is still being established turns every mistake into a
   * board that resets before it can say why.  It would also
   * write-protect the bootloader against the SWD flashing this rig does
   * dozens of times an hour.
   *
   * So this port REPORTS the state rather than enforcing it, and the
   * write-up must say WRP is "computed and checked, not latched".
   * Enabling it for a fielded build is a HAL_FLASHEx_OBProgram with the
   * masks below; the arithmetic is already stated and checked here so
   * that turning it on is not also a chance to get the geometry wrong. */
  TRACE("\r\n= [SBOOT] WRP NOT programmed. have 0to31=%x 32to63=%x, "
        "want %x / %x (%d sectors) -- see sfu_low_level_security.c\r\n",
        (unsigned)ob_get.WRPSector0To31, (unsigned)ob_get.WRPSector32To63,
        (unsigned)want0, (unsigned)want1, (int)n_sectors);
  return SFU_SUCCESS;
}
#endif /* SFU_WRP_PROTECT_ENABLE */

/* THE FLOW-CONTROL ACCUMULATOR IS PART OF THE PORT'S CONTRACT, and nothing
 * in these functions' signatures says so.
 *
 * ST's state machine guards each protection phase with a running XOR:
 * sfu_boot.c:845 does FLOW_CONTROL_CHECK(uFlowProtectValue,
 * FLOW_CTRL_RUNTIME_PROTECT) before the install, and the expected value is
 * a chain of per-protection constants in sfu_boot.h:118-134.  Each
 * FLOW_STEP_x is the real constant when that protection is enabled and
 * ZERO when it is not, so the expected total adapts automatically to the
 * configuration -- which is elegant, and which means the port owes one
 * FLOW_CONTROL_STEP call per protection it actually applies.
 *
 * This port owed four and paid none.  The install died at
 * sfu_boot.c:845 with "Security issue : execution stopped !" printed
 * immediately after "STATE: INSTALL NEW USER FIRMWARE" -- before
 * apply_wrp's own trace, which is what located it -- and the message is
 * the same one a genuine attack would produce.  There is no indication of
 * WHICH step is missing, because by design a fault-injection attempt
 * should not be told.
 *
 * FLOW_STEP_UBE is XORed in unconditionally, unlike the others: sfu_boot.h
 * defines it outside any #ifdef, so FLOW_CTRL_STATIC_PROTECT always
 * contains it.  Unique Boot Entry is an H7/L5 option-byte feature that
 * this part does not have, so there is nothing to apply -- but the
 * arithmetic still has to balance, and ST's own L4 file takes the step for
 * the same reason.
 */
SFU_ErrorStatus SFU_LL_SECU_CheckApplyStaticProtections(void)
{
  /* Unique Boot Entry: no such feature on this part.  The step is taken
   * because the constant is unconditional; see the note above. */
  FLOW_CONTROL_STEP(uFlowProtectValue, FLOW_STEP_UBE, FLOW_CTRL_UBE);

#ifdef SFU_WRP_PROTECT_ENABLE
  if (apply_wrp() != SFU_SUCCESS)
  {
    return SFU_ERROR;
  }
  FLOW_CONTROL_STEP(uFlowProtectValue, FLOW_STEP_WRP, FLOW_CTRL_WRP);
#endif /* SFU_WRP_PROTECT_ENABLE */

  /* The protections with no L152 implementation in this port.  app_sfu.h
   * has the corresponding #defines commented out with the reason, so
   * reaching here with one of them set is a configuration mistake rather
   * than a runtime condition -- and it is caught at COMPILE time, where a
   * configuration mistake belongs, instead of silently doing nothing. */
#if defined(SFU_FWALL_PROTECT_ENABLE)
#error "SFU_FWALL_PROTECT_ENABLE: the STM32L1 has no firewall peripheral. \
It is an L0/L4 feature. See the table at the top of this file."
#endif
#if defined(SFU_RDP_PROTECT_ENABLE)
#error "SFU_RDP_PROTECT_ENABLE: RDP level 1 blocks the debug port's view of \
flash, which is how every measurement on this rig is set up, and going back \
to level 0 is a mass erase. See the note at the top of this file."
#endif
#if defined(SFU_TAMPER_PROTECT_ENABLE)
#error "SFU_TAMPER_PROTECT_ENABLE: the L152 has RTC_TAMP1, but no tamper \
input is wired on a NUCLEO-64."
#endif
#if defined(SFU_MPU_PROTECT_ENABLE)
#error "SFU_MPU_PROTECT_ENABLE: this die HAS an MPU (MPU_TYPE 0x800, \
measured), but this port has no privilege boundary for it to enforce -- the \
call gate is an ordinary function call. See the note at the top of this file."
#endif

  return SFU_SUCCESS;
}

/* -------------------------------------------------- runtime protections -- */

SFU_ErrorStatus SFU_LL_SECU_CheckApplyRuntimeProtections(uint8_t uStep)
{
  (void)uStep;

#ifdef SFU_DMA_PROTECT_ENABLE
  /* ST disables the DMA controllers so that a DMA engine cannot be pointed
   * at the protected region.  Both of this part's are unclocked at reset
   * and this bootloader never enables either; clearing the clock-enable
   * bits makes that explicit and costs two writes.  The BSP's SPI driver is
   * polled, not DMA-driven, so nothing here needs them. */
  __HAL_RCC_DMA1_CLK_DISABLE();
  __HAL_RCC_DMA2_CLK_DISABLE();
  FLOW_CONTROL_STEP(uFlowProtectValue, FLOW_STEP_DMA, FLOW_CTRL_DMA);
#endif /* SFU_DMA_PROTECT_ENABLE */

#ifdef SFU_IWDG_PROTECT_ENABLE
  /* LSI is nominally 37 kHz on this part and specified over a wide range,
   * so the period below is approximate by nature -- which is fine, because
   * the watchdog is here to catch an installation that stopped, not to
   * time one.  Prescaler 256 and a reload of 4095 gives about 28 s at the
   * nominal rate.  The erase of a 320 KB slot is the longest single
   * operation underneath it, and SFU_LL_SECU_IWDG_Refresh is called every
   * two pages inside that loop. */
  IwdgHandle.Instance       = IWDG;
  IwdgHandle.Init.Prescaler = IWDG_PRESCALER_256;
  IwdgHandle.Init.Reload    = 4095U;
  if (HAL_IWDG_Init(&IwdgHandle) != HAL_OK)
  {
    return SFU_ERROR;
  }
  FLOW_CONTROL_STEP(uFlowProtectValue, FLOW_STEP_IWDG, FLOW_CTRL_IWDG);
#endif /* SFU_IWDG_PROTECT_ENABLE */

  return SFU_SUCCESS;
}

SFU_ErrorStatus SFU_LL_SECU_SetProtectionMPU_UserApp(void)
{
  /* ST calls this to NARROW the user application's view of memory before
   * handing over.  Returning SUCCESS without configuring the MPU is honest
   * here and is not a stub pretending to work: this port does not apply MPU
   * protection at all (see the table above), so the application's view is
   * the unrestricted one either way.  There is nothing to apply and nothing
   * to fail. */
  return SFU_SUCCESS;
}

SFU_ErrorStatus SFU_LL_SECU_SetProtectionMPU_StandaloneLoader(void)
{
  return SFU_SUCCESS;
}

/* ------------------------------------------------------------ reset cause -- */

void SFU_LL_SECU_GetResetSources(SFU_RESET_IdTypeDef *peResetpSourceId)
{
  /* Order matters: several flags can be set at once after a power-up, and
   * SBSFU wants the most specific cause.  The watchdog case is the one it
   * acts on -- an IWDG reset during a verify pass is how an interrupted
   * installation is detected -- so it is tested first. */
  if (__HAL_RCC_GET_FLAG(RCC_FLAG_IWDGRST) != RESET)
  {
    *peResetpSourceId = SFU_RESET_WDG_RESET;
  }
  else if (__HAL_RCC_GET_FLAG(RCC_FLAG_WWDGRST) != RESET)
  {
    *peResetpSourceId = SFU_RESET_WDG_RESET;
  }
  else if (__HAL_RCC_GET_FLAG(RCC_FLAG_SFTRST) != RESET)
  {
    *peResetpSourceId = SFU_RESET_SW_RESET;
  }
  else if (__HAL_RCC_GET_FLAG(RCC_FLAG_OBLRST) != RESET)
  {
    *peResetpSourceId = SFU_RESET_OB_LOADER;
  }
  else if (__HAL_RCC_GET_FLAG(RCC_FLAG_PORRST) != RESET)
  {
    *peResetpSourceId = SFU_RESET_BOR_RESET;
  }
  else if (__HAL_RCC_GET_FLAG(RCC_FLAG_PINRST) != RESET)
  {
    *peResetpSourceId = SFU_RESET_HW_RESET;
  }
  else
  {
    /* SFU_RESET_FIREWALL is unreachable: there is no firewall on this
     * part to raise it. */
    *peResetpSourceId = SFU_RESET_UNKNOWN;
  }
}

void SFU_LL_SECU_ClearResetSources(void)
{
  /* Unlike the SAM D21's read-only PM.RCAUSE, this part's flags are sticky
   * across a reset until cleared, which is exactly why ST clears them: a
   * stale IWDGRSTF would make the NEXT boot believe an installation was
   * interrupted when it was not. */
  __HAL_RCC_CLEAR_RESET_FLAGS();
}
