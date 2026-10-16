/*
 * Firmware image slot layout, SAM D21 Xplained Pro.
 *
 * The SAM D21 counterpart of ST's
 * Projects/B-L475E-IOT01A/.../Linker_Common/STM32CubeIDE/mapping_fwimg.ld.
 * Same symbol names -- sfu_fwimg_regions.h builds SlotHeaderAdd[],
 * SlotStartAdd[] and SlotEndAdd[] out of them -- with this part's geometry.
 *
 * GEOMETRY
 *   internal  256 KB at 0x00000000, erase granularity 256 B (NVMCTRL row)
 *   external    1 MB at 0x90000000, AT25DF081A, erase granularity 64 KB
 *
 * 0x90000000 is not a real address on this part: the SAM D21 has no external
 * memory bus and the AT25DF is reachable only over SERCOM5.  It is the
 * convention ST's own external-flash port uses -- sfu_low_level_flash.c
 * dispatches to the internal or external driver by comparing against
 * EXTERNAL_FLASH_ADDRESS, and sfu_low_level_flash_ext.c subtracts it back off
 * to get a chip offset.  Keeping it means both of those files work unchanged.
 *
 * Slots are aligned on 0x800 as ST's comment requires.  That is far coarser
 * than this part needs (a row is 0x100), so the constraint is satisfied with
 * room to spare rather than argued about.
 */

/* --- Active slot #1: the installed, running image -------------------------
 * Bounded above by what is left of the internal array after the bootloader.
 * The header sits in the 512 bytes immediately below the slot, matching
 * SFU_IMG_IMAGE_OFFSET.
 */
__ICFEDIT_SLOT_Active_1_header__ = 0x0001FE00;
__ICFEDIT_SLOT_Active_1_start__  = 0x00020000;
__ICFEDIT_SLOT_Active_1_end__    = 0x0003FFFF;   /* 128 KB */

/* --- Download slot #1: the whole serial flash -----------------------------
 * DELIBERATELY LARGER THAN THE ACTIVE SLOT, which the swap configuration
 * forbids and this one does not: the two size assertions
 * (SFU_IMG_REGION_IS_SAME_SIZE, SFU_IMG_REGION_IS_MULTIPLE) live only in
 * sfu_fwimg_swap.c, and SFU_NO_SWAP means that file is not compiled.
 *
 * It buys less than it looks like it does, and the reason is worth writing
 * down because it sets the whole campaign's shape.  The verify pass iterates
 * over pFwImageHeader->FwSize (sfu_fwimg_no_swap.c:388), NOT over the slot,
 * and FwSize is bounded by the ACTIVE slot -- line 491 rejects an image that
 * would not fit there.  So one boot pass is at most
 *
 *     (128 KB - 512) / 16  =  8 160 AES-CBC block decryptions
 *
 * however big this slot is.  A bigger download slot does not lengthen a pass;
 * what it buys is room to stage a fresh image without erasing the one being
 * measured.
 *
 * SIZED DOWN FROM THE WHOLE CHIP, and it is the campaign's throughput that
 * paid for the lesson.  At 1 MB the pass being measured took 0.3 s and the
 * install around it took over three minutes, because what ST's installer
 * does after the pass is proportional to the SLOT: it reads the whole thing
 * back (65 508 chunk reads at chunk 16, over 2.2 million status polls) and
 * erases it.  Each pass consumes the staged image, so that cost is paid once
 * per 2 815 traces, and a campaign wanting a million traces would have spent
 * 17 hours of it erasing empty flash.
 *
 * 192 KB is the smallest round size that still holds a maximum image --
 * 128 KB of active slot plus its header, staged from offset 0 -- so nothing
 * above is constrained by it, and it leaves the rest of the chip alone.
 * It changes nothing about the measured interval: the verify pass reads the
 * same addresses, in the same order, and decrypts the same blocks.
 */
__ICFEDIT_SLOT_Dwl_1_start__     = 0x90000000;
__ICFEDIT_SLOT_Dwl_1_end__       = 0x9002FFFF;   /* 192 KB of the AT25DF081A */

/* --- Slots not configured ------------------------------------------------- */
__ICFEDIT_SLOT_Active_2_header__ = 0x00000000;
__ICFEDIT_SLOT_Active_2_start__  = 0x00000000;
__ICFEDIT_SLOT_Active_2_end__    = 0x00000000;
__ICFEDIT_SLOT_Dwl_2_start__     = 0x00000000;
__ICFEDIT_SLOT_Dwl_2_end__       = 0x00000000;

__ICFEDIT_SLOT_Active_3_header__ = 0x00000000;
__ICFEDIT_SLOT_Active_3_start__  = 0x00000000;
__ICFEDIT_SLOT_Active_3_end__    = 0x00000000;
__ICFEDIT_SLOT_Dwl_3_start__     = 0x00000000;
__ICFEDIT_SLOT_Dwl_3_end__       = 0x00000000;

/* No swap area: SFU_NO_SWAP. */
__ICFEDIT_SWAP_start__           = 0x00000000;
__ICFEDIT_SWAP_end__             = 0x00000000;
