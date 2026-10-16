/**
  ******************************************************************************
  * @file    sfu_low_level_security.c
  * @brief   Security services, SAM D21 Xplained Pro.
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
  *   ST protection      SAM D21 equivalent            this port
  *   -----------------  ----------------------------  ----------------------
  *   WRP  (write prot)  NVMCTRL region LOCK bits and  APPLIED (LOCK), and
  *                      the BOOTPROT fuse             BOOTPROT left alone
  *   RDP  (readout)     the DSU security bit          NOT APPLIED, on purpose
  *   FWALL (firewall)   does not exist                NOT AVAILABLE
  *   MPU                not fitted (MPU_TYPE == 0,    NOT AVAILABLE
  *                      measured)
  *   DAP  (debug lock)  the same security bit as RDP  NOT APPLIED, on purpose
  *   DMA                DMAC exists; SBSFU's concern  NOT APPLIED -- the DMAC
  *                      is a DMA engine reading the   is left disabled, which
  *                      protected region              is its reset state
  *   TAMPER             no tamper input on this board NOT AVAILABLE
  *   IWDG               WDT                           APPLIED
  *
  * WHY RDP AND DAP ARE DELIBERATELY NOT APPLIED, AND WHY THAT IS NOT A
  * WEAKENING OF THE THING UNDER TEST
  * -------------------------------------------------------------------------
  * On this part both are the same fuse, and setting it disables SWD.  The
  * board would then be recoverable only by a full chip erase -- and every
  * measurement this demo exists to take is made over SWD.  ST's own projects
  * ship with SFU_PROTECT_RDP_LEVEL at level 1 rather than 2 "for debugging
  * purposes" for the same reason, and warn in app_sfu.h that enabling
  * SFU_DAP_PROTECT_ENABLE disconnects the debugger.
  *
  * It matters for the write-up that this changes NOTHING about the channel.
  * The attack is a timing side channel on a cipher, measured from outside the
  * chip on the SPI bus.  Readout protection does not slow the cipher down,
  * does not change which flash rows the S-box touches, and is not on the
  * attacker's path: a fielded device with RDP set and the debugger fused off
  * leaks exactly the same intervals on exactly the same pins.  What RDP would
  * protect is the key at rest, which is precisely what the timing channel
  * recovers without reading it.
  ******************************************************************************
  */
#include "sfu_low_level_security.h"
#include "sfu_low_level_flash_int.h"
#include "samd21_hal.h"
#include "samd21.h"

/* ------------------------------------------------------------- watchdog -- */

SFU_ErrorStatus SFU_LL_SECU_IWDG_Refresh(void)
{
  HAL_WDT_Refresh();
  return SFU_SUCCESS;
}

/* ------------------------------------------------- static protections ---- */

/**
  * @brief  Lock the bootloader region against programming and erase.
  *
  * NVMCTRL divides the array into 16 equal regions -- 16 KB each on a 256 KB
  * part -- and NVMCTRL.LOCK has one bit per region, 0 meaning locked.  CMD_LR
  * locks the region containing NVMCTRL.ADDR; the effect is volatile and has
  * to be re-applied after every reset, which is exactly what this function
  * being called at every boot provides.
  *
  * WHAT THIS IS NOT.  The permanent version is the BOOTPROT fuse in the NVM
  * user row, which protects a boot region from the moment of reset and
  * survives power cycles.  This port does NOT write it, because a wrong
  * BOOTPROT value on a 256 KB part can lock out the region the debugger needs
  * in order to fix it, and the user row is written by a different mechanism
  * (auxiliary space, its own erase row).  The volatile LOCK is the honest
  * subset: it stops the running firmware, including a compromised user
  * application, from erasing the bootloader; it does not stop an attacker
  * with a debug probe.
  */
static SFU_ErrorStatus apply_wrp(void)
{
  uint32_t region_size = FLASH_SIZE / 16U;
  uint32_t last = (uint32_t)SB_REGION_ROM_END;
  uint32_t addr;

  for (addr = 0U; addr <= last; addr += region_size)
  {
    while (NVMCTRL->INTFLAG.bit.READY == 0U)
    {
    }
    NVMCTRL->ADDR.reg = addr >> 1;      /* half-word address, see flash_int */
    NVMCTRL->CTRLA.reg = (uint16_t)(NVMCTRL_CTRLA_CMDEX_KEY
                                    | NVMCTRL_CTRLA_CMD_LR);
    while (NVMCTRL->INTFLAG.bit.READY == 0U)
    {
    }
  }

  /* Read back.  A lock that did not take is worse than no lock, because the
   * boot log would report the protection as applied. */
  {
    uint32_t nregions = (last / region_size) + 1U;
    uint32_t mask = (nregions >= 16U) ? 0xFFFFU
                                      : (uint32_t)((1UL << nregions) - 1UL);

    if ((NVMCTRL->LOCK.reg & mask) != 0U)
    {
      return SFU_ERROR;                 /* a 1 bit means UNlocked            */
    }
  }
  return SFU_SUCCESS;
}

SFU_ErrorStatus SFU_LL_SECU_CheckApplyStaticProtections(void)
{
#ifdef SFU_WRP_PROTECT_ENABLE
  if (apply_wrp() != SFU_SUCCESS)
  {
    return SFU_ERROR;
  }
#endif /* SFU_WRP_PROTECT_ENABLE */

  /* RDP, PCROP, FWALL and BFB2 have no SAM D21 equivalent this port applies.
   * app_sfu.h has the corresponding #defines commented out with the reason,
   * so reaching here with one of them set is a configuration mistake rather
   * than a runtime condition -- caught at compile time. */
#if defined(SFU_RDP_PROTECT_ENABLE)
#error "SFU_RDP_PROTECT_ENABLE: on the SAM D21 this is the DSU security bit, \
which also disables SWD and makes the board recoverable only by chip erase. \
See the note at the top of sfu_low_level_security.c."
#endif
#if defined(SFU_FWALL_PROTECT_ENABLE)
#error "SFU_FWALL_PROTECT_ENABLE: the SAM D21 has no firewall peripheral."
#endif
#if defined(SFU_MPU_PROTECT_ENABLE)
#error "SFU_MPU_PROTECT_ENABLE: no MPU is fitted on this part -- MPU_TYPE \
reads 0, which samd21j18a.h:223 agrees with (__MPU_PRESENT 0)."
#endif
#if defined(SFU_TAMPER_PROTECT_ENABLE)
#error "SFU_TAMPER_PROTECT_ENABLE: the SAM D21 Xplained Pro exposes no \
tamper input."
#endif

  return SFU_SUCCESS;
}

/* ------------------------------------------------ runtime protections ---- */

SFU_ErrorStatus SFU_LL_SECU_CheckApplyRuntimeProtections(uint8_t uStep)
{
  (void)uStep;

#ifdef SFU_DMA_PROTECT_ENABLE
  /* ST disables the DMA controllers so that a DMA engine cannot be used to
   * read the protected region.  The SAM D21's DMAC is DISABLED AT RESET and
   * this bootloader never enables it, so the protection is already in force;
   * clearing DMAC.CTRL.DMAENABLE makes that explicit and costs one write. */
  PM->AHBMASK.reg |= PM_AHBMASK_DMAC;
  PM->APBBMASK.reg |= PM_APBBMASK_DMAC;
  DMAC->CTRL.reg = 0U;
#endif /* SFU_DMA_PROTECT_ENABLE */

#ifdef SFU_IWDG_PROTECT_ENABLE
  HAL_WDT_Init(SFU_IWDG_TIMEOUT);
#endif /* SFU_IWDG_PROTECT_ENABLE */

  return SFU_SUCCESS;
}

SFU_ErrorStatus SFU_LL_SECU_SetProtectionMPU_UserApp(void)
{
  /* No MPU is fitted.  Returning SUCCESS is correct here and is not a stub
   * pretending to work: ST calls this to NARROW the user application's view
   * of memory, and on a part with no MPU the application already has the
   * unrestricted view.  There is nothing to apply and nothing to fail. */
  return SFU_SUCCESS;
}

SFU_ErrorStatus SFU_LL_SECU_SetProtectionMPU_StandaloneLoader(void)
{
  return SFU_SUCCESS;
}

/* ---------------------------------------------------------- reset cause -- */

void SFU_LL_SECU_GetResetSources(SFU_RESET_IdTypeDef *peResetpSourceId)
{
  uint8_t rcause = PM->RCAUSE.reg;

  /* Order matters: several bits can be set at once after a power-up, and
   * SBSFU wants the most specific cause.  The watchdog case is the one it
   * acts on -- a WDT reset during a verify pass is how an interrupted
   * installation is detected. */
  if ((rcause & PM_RCAUSE_WDT) != 0U)
  {
    *peResetpSourceId = SFU_RESET_WDG_RESET;
  }
  else if ((rcause & PM_RCAUSE_SYST) != 0U)
  {
    *peResetpSourceId = SFU_RESET_SW_RESET;
  }
  else if ((rcause & PM_RCAUSE_EXT) != 0U)
  {
    *peResetpSourceId = SFU_RESET_HW_RESET;
  }
  else if ((rcause & PM_RCAUSE_BOD33) != 0U)
  {
    *peResetpSourceId = SFU_RESET_BOR_RESET;
  }
  else if ((rcause & PM_RCAUSE_BOD12) != 0U)
  {
    *peResetpSourceId = SFU_RESET_BOR_RESET;
  }
  else if ((rcause & PM_RCAUSE_POR) != 0U)
  {
    *peResetpSourceId = SFU_RESET_HW_RESET;
  }
  else
  {
    /* SFU_RESET_FIREWALL is unreachable on this part and SFU_RESET_OB_LOADER
     * has no analogue -- there are no option bytes to reload. */
    *peResetpSourceId = SFU_RESET_UNKNOWN;
  }
}

void SFU_LL_SECU_ClearResetSources(void)
{
  /* PM.RCAUSE IS READ-ONLY ON THIS PART, and that is a real behavioural
   * difference rather than an omission.  On the STM32 this clears RCC flags
   * so the NEXT boot's reading is unambiguous; here the register is cleared
   * by hardware at each reset and holds only the current cause, so there is
   * nothing to clear and no stale bit to mislead the next boot.
   *
   * Consequence worth knowing: on this part a reset cause cannot be
   * "remembered across" a reset the way ST's code can accidentally do it, so
   * the ambiguity ST's clear exists to remove does not arise. */
}
