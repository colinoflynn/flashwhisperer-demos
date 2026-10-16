/*
 * Firmware image slot layout, NUCLEO-L152RE.
 *
 * The L152 counterpart of ST's
 * Projects/B-L475E-IOT01A/.../Linker_Common/STM32CubeIDE/mapping_fwimg.ld.
 * Same symbol names -- sfu_fwimg_regions.h builds SlotHeaderAdd[],
 * SlotStartAdd[] and SlotEndAdd[] out of them -- with this part's geometry.
 *
 * GEOMETRY
 *   internal  512 KB at 0x08000000, erase granularity 256 B (an L1 "page")
 *   external  whatever is on SPI2, erase granularity 64 KB
 *
 * 0x90000000 is not a real address on this part: the L152 has no external
 * memory bus and the serial flash is reachable only over SPI2.  It is the
 * convention ST's own external-flash port uses -- sfu_low_level_flash.c
 * dispatches to the internal or external driver by comparing against
 * EXTERNAL_FLASH_ADDRESS, and sfu_low_level_flash_ext.c subtracts it back
 * off to get a chip offset.  Keeping it means both of those files work
 * unchanged, exactly as on the SAM D21 port.
 *
 * Slots are aligned on 0x800 as ST's comment requires.
 */

/* ===========================================================================
 * THE SLOTS ARE SIZED TO THE CAPTURE INSTRUMENT, NOT TO THE PART.
 * HOW TO UNDO THIS, AND WHAT TO CHANGE IF THE INSTRUMENT CHANGES.
 * ===========================================================================
 *
 * WHAT WAS HERE BEFORE, and what to restore for a build that is about the
 * product rather than about the measurement:
 *
 *     __ICFEDIT_SLOT_Active_1_header__ = 0x0802FE00;
 *     __ICFEDIT_SLOT_Active_1_start__  = 0x08030000;
 *     __ICFEDIT_SLOT_Active_1_end__    = 0x0807FFFF;   // 320 KB
 *     __ICFEDIT_SLOT_Dwl_1_start__     = 0x90000000;
 *     __ICFEDIT_SLOT_Dwl_1_end__       = 0x9005FFFF;   // 384 KB
 *
 * Those are the honest sizes: 320 KB is the whole internal array above the
 * bootloader, and 384 KB is the smallest multiple of the memory's 64 KB
 * erase block that holds a maximum image.  Nothing is wrong with them, and
 * the bootloader installs and runs with them -- that result is recorded in
 * results/bootloader_spi/l152/README.md and was taken at those sizes.
 *
 * WHY THEY CAME DOWN.  The bus-side timer (rigs/fw_f303_spitimer) captures
 * into a fixed buffer of 12 288 edges, which is 6 144 chip-select
 * envelopes, and it is armed once -- at the handshake, just before the
 * install.  What the installer does is NOT all pass: it also reads the
 * download slot back and erases it, and that part is proportional to the
 * SLOT rather than to the image.  At 384 KB the buffer filled with the
 * installer's own housekeeping before the verify pass began, and the
 * classifier found 0 of the 256 alternating poll/data pairs it needed.
 * Measured: 24 036 target reads against 6 144 envelopes captured.
 *
 * THE ARITHMETIC, so the next person can resize for a different instrument
 * instead of guessing.  With SFU_IMG_CHUNK_SIZE = C bytes:
 *
 *     envelopes per chunk            2   (one status poll, one data read)
 *     edges per envelope             2   (one fall, one rise)
 *     the verify pass                2 * FwSize / C envelopes
 *     the install's read-back        2 * FwSize / C envelopes
 *     the download slot's cleanup    2 * DwlSlotSize / C envelopes
 *
 * and the sum must fit in (buffer_edges / 2).  At C = 64, FwSize = 16 KB
 * and a 64 KB download slot that is 512 + 512 + 2 048 = 3 072 envelopes
 * against 6 144 available, which leaves room to roughly double the image
 * before anything has to move.
 *
 * SO, TO CHANGE THE INSTRUMENTATION:
 *   - a BIGGER capture buffer (fw_f303_spitimer's cap[] and the DMA count)
 *     relaxes everything above; raise the slots back toward the honest
 *     sizes in proportion.
 *   - a SMALLER chunk size multiplies every term by 64/C.  C = 16 makes the
 *     same configuration four times as hungry and will not fit.
 *   - a timer armed inside the pass rather than before the install would
 *     remove the cleanup term entirely, and is the right fix if the slots
 *     ever need to be honest and the capture complete at once.
 *
 * WHAT THE RESIZE DOES NOT CHANGE, which is the part that matters for the
 * result: the verify pass reads the same addresses in the same order and
 * decrypts the same blocks.  The interval being timed is between two
 * chip-select edges the driver produces, and neither slot bound appears in
 * it.  What it does change is the CEILING on blocks per boot pass, below.
 * ===========================================================================
 */

/* --- Active slot #1: the installed, running image -------------------------
 * 64 KB.  The header sits in the 512 bytes immediately below the slot,
 * matching SFU_IMG_IMAGE_OFFSET.
 *
 * WHAT THE SIZE BUYS, which is not what it looks like it buys.  The verify
 * pass iterates over pFwImageHeader->FwSize (sfu_fwimg_no_swap.c:388), not
 * over the slot, and FwSize is bounded above by the ACTIVE slot -- line 491
 * rejects an image that would not fit there.  So this number sets the
 * CEILING on one boot pass:
 *
 *     (64 KB - 512) / 16  =  4 064 AES-CBC block decryptions
 *
 * against 20 448 at the honest 320 KB.  The SAM D21 result needed 12 000
 * timed blocks for eleven key bytes, so at this size a campaign needs three
 * passes where the full-size map would have needed one -- which costs
 * throughput and changes nothing about what a pass measures.  Raise it
 * together with the buffer, per the block above.
 */
__ICFEDIT_SLOT_Active_1_header__ = 0x0802FE00;
__ICFEDIT_SLOT_Active_1_start__  = 0x08030000;
__ICFEDIT_SLOT_Active_1_end__    = 0x0803FFFF;   /* 64 KB */

/* --- Download slot #1: part of the serial flash ---------------------------
 * DELIBERATELY LARGER THAN THE ACTIVE SLOT, which the swap configuration
 * forbids and this one does not: the two size assertions
 * (SFU_IMG_REGION_IS_SAME_SIZE, SFU_IMG_REGION_IS_MULTIPLE) live only in
 * sfu_fwimg_swap.c, and SFU_NO_SWAP means that file is not compiled.
 *
 * SIZED TO THE ACTIVE SLOT RATHER THAN TO THE CHIP, and the SAM D21
 * campaign's throughput is what paid for that lesson.  What ST's installer
 * does AFTER the measured pass is proportional to the SLOT, not to the
 * image: it reads the whole slot back and erases it.  At the full 4 MB of
 * an AT25SF321 that would be 65 536 chunk reads and 64 block erases per
 * install, for a pass that is over in a second.
 *
 * 64 KB: one erase block of the memory, and the smallest size that still
 * holds a maximum image for the 64 KB active slot above -- 64 KB minus the
 * 512-byte header, staged from offset 0.  See the resize note at the top of
 * this file for why it is not 384 KB, and for the arithmetic that says what
 * it should be if the capture buffer or the chunk size changes.
 *
 * THIS IS THE TERM THAT WAS SWAMPING THE CAPTURE.  The cleanup reads and
 * erases the whole slot whatever the image size, so it is the one cost that
 * does not shrink when the attacker stages a smaller image -- 2 * SlotSize
 * / CHUNK envelopes, which at 384 KB and CHUNK=64 was 12 288 on its own,
 * exactly the buffer's whole capacity in edges.
 */
__ICFEDIT_SLOT_Dwl_1_start__     = 0x90000000;
__ICFEDIT_SLOT_Dwl_1_end__       = 0x9000FFFF;   /* 64 KB */

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
