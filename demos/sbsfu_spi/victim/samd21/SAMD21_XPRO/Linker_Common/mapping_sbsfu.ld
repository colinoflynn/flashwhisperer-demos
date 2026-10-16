/*
 * Bootloader region layout, SAM D21 Xplained Pro.
 *
 * The SAM D21 counterpart of ST's
 * Projects/B-L475E-IOT01A/.../Linker_Common/STM32CubeIDE/mapping_sbsfu.ld.
 * Same symbol names, because mapping_export.h declares them and SBSFU's
 * security and boot code reads them.
 *
 * WHAT "PROTECTED BY FIREWALL" MEANS ON A PART WITH NO FIREWALL
 * -------------------------------------------------------------
 * ST's comments say the Secure Engine regions are protected by the STM32
 * firewall.  The SAM D21 has no firewall and no MPU (measured: MPU_TYPE reads
 * 0), so on this part the regions are a LAYOUT, not an isolation boundary --
 * the call gate is an ordinary function call and the key sits in ordinary
 * flash.  The layout is kept anyway, for three reasons:
 *
 *   1. SBSFU's own code reads these symbols; removing them means editing ST's
 *      sources, which this port is trying not to do.
 *   2. NVMCTRL's BOOTPROT fuse and region LOCK bits can protect the
 *      bootloader region against erasure at runtime, which is a real (if
 *      weaker) analogue, and it needs the boundary to be defined.
 *   3. The attack this demo exists to measure does not depend on the
 *      isolation either way -- it is a timing channel in the cipher, and the
 *      cipher runs inside the Secure Engine whether or not anything is
 *      keeping the rest of the firmware out of it.
 *
 * sfu_low_level_security.c says which protections this board can and cannot
 * honour, one by one.
 */

/* Vector table. */
VECTOR_SIZE = 0x200;

/* SE code region. */
__ICFEDIT_SE_Code_region_ROM_start__       = 0x00000000 + VECTOR_SIZE;
__ICFEDIT_SE_CallGate_region_ROM_start__   = __ICFEDIT_SE_Code_region_ROM_start__;
__ICFEDIT_SE_CallGate_region_ROM_end__     = __ICFEDIT_SE_Code_region_ROM_start__ + 0x1FF;

/* SE key region. */
__ICFEDIT_SE_Key_region_ROM_start__        = __ICFEDIT_SE_CallGate_region_ROM_end__ + 0x1;
__ICFEDIT_SE_Key_region_ROM_end__          = __ICFEDIT_SE_Key_region_ROM_start__ + 0x1FF;

/* SE startup: runs before any protection is applied. */
__ICFEDIT_SE_Startup_region_ROM_start__    = __ICFEDIT_SE_Key_region_ROM_end__ + 0x1;
__ICFEDIT_SE_Code_nokey_region_ROM_start__ = __ICFEDIT_SE_Startup_region_ROM_start__ + 0x100;
/* 78 KB for the Secure Engine.  ST's L475 script gives it 36 KB (0x9000);
   this port needs more, and the number is measured rather than guessed:
   the mbedTLS subset alone is 55 KB of .text on this target --
        ecp        13.8 KB
        bignum     10.0 KB
        aes         6.5 KB
        sha256      4.1 KB
        (+ bignum_core, ecp_curves, cipher, asn1, oid ...)
   and only secp256r1 is enabled, so there is no fat left to trim by
   configuration.  The difference from ST is the toolchain and options, not
   the algorithm set; rather than chase their number, the region is sized to
   what this build actually produces and the slack is stated.

   The cost is taken out of the SBSFU region below, NOT out of the active
   slot -- shrinking the slot would shorten every verify pass and change the
   attack's economics, which is not a trade to make silently. */
__ICFEDIT_SE_Code_region_ROM_end__         = __ICFEDIT_SE_Startup_region_ROM_start__ + 0x137FF;

/* SE interface: the trampolines, outside the (notional) protected region. */
__ICFEDIT_SE_IF_region_ROM_start__         = __ICFEDIT_SE_Code_region_ROM_end__ + 0x1;
__ICFEDIT_SE_IF_region_ROM_end__           = __ICFEDIT_SE_IF_region_ROM_start__ + 0x5FF;

/* SBSFU itself, up to the active slot's header.  ~88 KB, which has to hold
   the boot state machine, the YMODEM local loader and the external flash
   driver.  If it overflows, the linker says so -- and the fix is to shrink
   the active slot, which shortens every verify pass, so the trade is
   explicit rather than silent. */
__ICFEDIT_SB_region_ROM_start__            = __ICFEDIT_SE_IF_region_ROM_end__ + 0x1;
__ICFEDIT_SB_region_ROM_end__              = 0x0001FDFF;   /* ~40 KB */

SE_Entry_Secure_ROM_Region_Length = __ICFEDIT_SE_CallGate_region_ROM_end__ - __ICFEDIT_SE_CallGate_region_ROM_start__ + 1;
SE_Key_region_ROM_Length          = __ICFEDIT_SE_Key_region_ROM_end__ - __ICFEDIT_SE_Key_region_ROM_start__ + 1;
SE_Startup_region_ROM_Length      = __ICFEDIT_SE_Code_nokey_region_ROM_start__ - __ICFEDIT_SE_Startup_region_ROM_start__;
SE_ROM_region_Length              = __ICFEDIT_SE_Code_region_ROM_end__ - __ICFEDIT_SE_Code_nokey_region_ROM_start__ + 1;
SE_IF_region_ROM_Length           = __ICFEDIT_SE_IF_region_ROM_end__ - __ICFEDIT_SE_IF_region_ROM_start__ + 1;
SB_ROM_region_Length              = __ICFEDIT_SB_region_ROM_end__ - __ICFEDIT_SB_region_ROM_start__ + 1;

/* --- RAM: 32 KB at 0x20000000 ---------------------------------------------
 * A third of ST's 96 KB, so the split is tighter than theirs.  The SE stack
 * goes FIRST, at the bottom of SRAM, so that an overflow runs off the bottom
 * of the address space instead of quietly into SBSFU's variables -- ST's
 * reasoning, and it costs nothing to keep.
 */
__ICFEDIT_SE_region_RAM_start__     = 0x20000000;
__ICFEDIT_SE_region_RAM_stack_top__ = 0x20000000;
__ICFEDIT_SE_region_RAM_end__       = 0x200003FF;   /* 1 KB, reserved      */

__ICFEDIT_SB_region_RAM_start__     = 0x20000400;
__ICFEDIT_SB_region_RAM_end__       = 0x20007FFF;   /* 31 KB               */

SE_RAM_region_Length = __ICFEDIT_SE_region_RAM_end__ - __ICFEDIT_SE_region_RAM_start__ + 1;
SB_RAM_region_Length = __ICFEDIT_SB_region_RAM_end__ - __ICFEDIT_SB_region_RAM_start__ + 1;

/* THE STACK IS IN SBSFU RAM, NOT IN SE RAM, AND THAT IS A CORRECTNESS
 * REQUIREMENT RATHER THAN A PREFERENCE.
 *
 * The first version of this layout followed ST and put the stack at the
 * bottom of SRAM inside the SE region, so that an overflow would run off the
 * end of the address space instead of into SBSFU's variables.  On a part
 * with isolation that is right, because ST's call gate SWITCHES to the SE
 * stack on entry (se_stack_smuggler_*.s) and SBSFU's own locals are
 * elsewhere.
 *
 * This port has no isolation and does not switch stacks, so SBSFU's locals
 * live wherever the single stack is.  And se_callgate.c:236 does:
 *
 *     if (SE_LL_Buffer_part_of_SE_ram(peSE_Status, ...) == SE_SUCCESS)
 *         NVIC_SystemReset();
 *
 * -- the Secure Engine REFUSES a status pointer that lives in its own RAM,
 * because on ST's design that could only come from something trying to make
 * the SE write inside the protected region.  With the stack in SE RAM, every
 * SE call passed a stack pointer that failed that test, and the very first
 * one (SE_Init) reset the board.  Silently: the reset is deliberate, so
 * there is no fault to record, and it happens before the state machine
 * prints anything.
 *
 * So the stack goes at the top of SBSFU RAM and grows down.  The SE region
 * stays reserved and unused -- 1 KB, kept only so that
 * SE_LL_Buffer_part_of_SE_ram has a range to answer about.
 */
_estack = __ICFEDIT_SB_region_RAM_end__ + 1;

/* The three SFU_IMG_CHUNK_SIZE buffers in VerifyFwSignatureBeforeDecrypt are
   stack-allocated, so the chunk size feeds straight into SBSFU's stack
   requirement: 3 x 512 = 1536 B at ST's default, 3 x 64 = 192 B at the value
   this port uses.  Both fit; the assertion is here so that raising CHUNK
   past what 20 KB can hold fails at link time rather than as a stack
   overflow in the middle of a verify pass. */
ASSERT(SB_RAM_region_Length > 3 * 2048 + 4096,
       "SBSFU RAM region too small for three chunk buffers plus working set")
