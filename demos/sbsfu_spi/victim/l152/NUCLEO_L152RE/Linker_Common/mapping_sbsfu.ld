/*
 * Bootloader region layout, NUCLEO-L152RE.
 *
 * The L152 counterpart of ST's
 * Projects/B-L475E-IOT01A/.../Linker_Common/STM32CubeIDE/mapping_sbsfu.ld.
 * Same symbol names and the same order of regions, because mapping_export.h
 * declares them and SBSFU's security and boot code reads them.
 *
 * WHAT "PROTECTED BY FIREWALL" MEANS ON A PART WITH NO FIREWALL
 * -------------------------------------------------------------
 * ST's comments say the Secure Engine regions are protected by the STM32
 * firewall.  The firewall is an L0/L4 peripheral; the L152 does not have
 * one, so on this part the Secure Engine boundary is a LAYOUT rather than
 * an isolation boundary, and the call gate is an ordinary function call.
 *
 * That is NOT the same position the SAM D21 port is in, and the difference
 * is worth stating rather than glossing.  This part does have RDP, WRP and
 * PCROP in its option bytes, and it may have an MPU -- sfu_low_level_security.c
 * says which of those this port turns on, one by one, and the bring-up image
 * reads MPU_TYPE off the die rather than trusting a header.  So the isolation
 * here is weaker than ST's reference board and stronger than the SAM D21's.
 *
 * None of it changes what the demo measures.  The attack is a timing channel
 * in the cipher, and the cipher runs inside the Secure Engine whether or not
 * anything is keeping the rest of the firmware out of it.
 */

/* Vector table. */
VECTOR_SIZE = 0x200;

/* SE code region. */
__ICFEDIT_SE_Code_region_ROM_start__       = 0x08000000 + VECTOR_SIZE;
__ICFEDIT_SE_CallGate_region_ROM_start__   = __ICFEDIT_SE_Code_region_ROM_start__;
__ICFEDIT_SE_CallGate_region_ROM_end__     = __ICFEDIT_SE_Code_region_ROM_start__ + 0x1FF;

/* SE key region. */
__ICFEDIT_SE_Key_region_ROM_start__        = __ICFEDIT_SE_CallGate_region_ROM_end__ + 0x1;
__ICFEDIT_SE_Key_region_ROM_end__          = __ICFEDIT_SE_Key_region_ROM_start__ + 0x1FF;

/* SE startup: runs before any protection is applied. */
__ICFEDIT_SE_Startup_region_ROM_start__    = __ICFEDIT_SE_Key_region_ROM_end__ + 0x1;
__ICFEDIT_SE_Code_nokey_region_ROM_start__ = __ICFEDIT_SE_Startup_region_ROM_start__ + 0x100;

/* 80 KB for the Secure Engine.  ST's L475 script gives it 36 KB (0x9000)
   and that is not enough here, for the same reason it was not enough on the
   SAM D21: the mbedTLS subset this scheme pulls in measured 78 KB of .text
   there --
        ecp        13.8 KB
        bignum     10.0 KB
        aes         6.5 KB
        sha256      4.1 KB
        (+ bignum_core, ecp_curves, cipher, asn1, oid ...)
   with only secp256r1 enabled, so there is no fat left to trim by
   configuration.  The difference from ST is the toolchain and options, not
   the algorithm set.

   80 KB rather than 78 because this is a Cortex-M3 rather than an M0+ and
   the two instruction sets do not produce the same code size; the number is
   provisional until this port links, and the linker is what settles it.
   Unlike the SAM D21, there is room here to be generous without taking it
   out of the active slot. */
__ICFEDIT_SE_Code_region_ROM_end__         = __ICFEDIT_SE_Startup_region_ROM_start__ + 0x13FFF;

/* SE interface: the trampolines, outside the (notional) protected region. */
__ICFEDIT_SE_IF_region_ROM_start__         = __ICFEDIT_SE_Code_region_ROM_end__ + 0x1;
__ICFEDIT_SE_IF_region_ROM_end__           = __ICFEDIT_SE_IF_region_ROM_start__ + 0x5FF;

/* SBSFU itself, up to the active slot's header: the boot state machine, the
   YMODEM local loader and the serial-flash driver.  ST's L475 gives the
   same code 56 KB; this is more, because the boundary is rounded up to put
   the active slot on 0x08030000 and there is spare flash to round with.
   If it overflows the linker says so. */
__ICFEDIT_SB_region_ROM_start__            = __ICFEDIT_SE_IF_region_ROM_end__ + 0x1;
__ICFEDIT_SB_region_ROM_end__              = 0x0802FDFF;

SE_Entry_Secure_ROM_Region_Length = __ICFEDIT_SE_CallGate_region_ROM_end__ - __ICFEDIT_SE_CallGate_region_ROM_start__ + 1;
SE_Key_region_ROM_Length          = __ICFEDIT_SE_Key_region_ROM_end__ - __ICFEDIT_SE_Key_region_ROM_start__ + 1;
SE_Startup_region_ROM_Length      = __ICFEDIT_SE_Code_nokey_region_ROM_start__ - __ICFEDIT_SE_Startup_region_ROM_start__;
SE_ROM_region_Length              = __ICFEDIT_SE_Code_region_ROM_end__ - __ICFEDIT_SE_Code_nokey_region_ROM_start__ + 1;
SE_IF_region_ROM_Length           = __ICFEDIT_SE_IF_region_ROM_end__ - __ICFEDIT_SE_IF_region_ROM_start__ + 1;
SB_ROM_region_Length              = __ICFEDIT_SB_region_ROM_end__ - __ICFEDIT_SB_region_ROM_start__ + 1;

/* --- RAM: 80 KB at 0x20000000 --------------------------------------------- */
__ICFEDIT_SE_region_RAM_start__     = 0x20000000;
__ICFEDIT_SE_region_RAM_stack_top__ = 0x20000000;
__ICFEDIT_SE_region_RAM_end__       = 0x200003FF;   /* 1 KB, reserved      */

__ICFEDIT_SB_region_RAM_start__     = 0x20000400;
__ICFEDIT_SB_region_RAM_end__       = 0x20013FFF;   /* 79 KB               */

SE_RAM_region_Length = __ICFEDIT_SE_region_RAM_end__ - __ICFEDIT_SE_region_RAM_start__ + 1;
SB_RAM_region_Length = __ICFEDIT_SB_region_RAM_end__ - __ICFEDIT_SB_region_RAM_start__ + 1;

/* THE STACK IS IN SBSFU RAM, NOT IN SE RAM, AND THAT IS A CORRECTNESS
 * REQUIREMENT RATHER THAN A PREFERENCE.
 *
 * ST puts the stack at the bottom of SRAM inside the SE region, so that an
 * overflow runs off the end of the address space instead of into SBSFU's
 * variables.  On a part with isolation that is right, because ST's call gate
 * SWITCHES to the SE stack on entry (se_stack_smuggler_*.s) and SBSFU's own
 * locals are elsewhere.
 *
 * This port has no firewall and does not switch stacks, so SBSFU's locals
 * live wherever the single stack is.  And se_callgate.c:236 does:
 *
 *     if (SE_LL_Buffer_part_of_SE_ram(peSE_Status, ...) == SE_SUCCESS)
 *         NVIC_SystemReset();
 *
 * -- the Secure Engine REFUSES a status pointer that lives in its own RAM,
 * because on ST's design that could only come from something trying to make
 * the SE write inside the protected region.  With the stack in SE RAM, every
 * SE call passes a stack pointer that fails that test, and the very first
 * one (SE_Init) resets the board.  Silently: the reset is deliberate, so
 * there is no fault to record, and it happens before the state machine
 * prints anything.  That cost the SAM D21 port a day; it is written down
 * here so this port does not pay for it twice.
 *
 * So the stack goes at the top of SBSFU RAM and grows down.  The SE region
 * stays reserved and unused -- 1 KB, kept only so that
 * SE_LL_Buffer_part_of_SE_ram has a range to answer about.
 */
_estack = __ICFEDIT_SB_region_RAM_end__ + 1;

/* The three SFU_IMG_CHUNK_SIZE buffers in VerifyFwSignatureBeforeDecrypt are
   stack-allocated, so the chunk size feeds straight into SBSFU's stack
   requirement: 3 x 512 = 1536 B at ST's default, 3 x 64 = 192 B at the value
   this port uses.  The assertion is here so that raising CHUNK past what
   this region can hold fails at link time rather than as a stack overflow
   in the middle of a verify pass. */
ASSERT(SB_RAM_region_Length > 3 * 2048 + 4096,
       "SBSFU RAM region too small for three chunk buffers plus working set")
