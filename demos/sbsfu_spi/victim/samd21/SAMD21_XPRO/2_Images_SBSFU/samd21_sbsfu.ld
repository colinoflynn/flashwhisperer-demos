/*
 * SBSFU bootloader image, SAM D21 Xplained Pro.
 *
 * ONE IMAGE, NOT TWO, AND THAT IS A CONSEQUENCE OF HAVING NO ISOLATION.
 * ---------------------------------------------------------------------
 * ST builds SECoreBin as its own ELF with its own linker script, then
 * incbin's the resulting blob into SBSFU (sfu_secorebin_Inc.c).  The split
 * exists because the two halves live on opposite sides of a firewall and
 * must be programmed and protected separately.
 *
 * This part has no firewall and no MPU, so there is no boundary for the
 * split to express.  Linking one image is simpler, and -- more to the point
 * -- it is HONEST about what the port is: a single privilege level in which
 * the "Secure Engine" is a set of functions at agreed addresses.  Pretending
 * otherwise by keeping two binaries would suggest a separation that is not
 * there.  se_low_level.h says the same thing in more detail.
 *
 * WHAT STILL HAS TO BE AT A FIXED ADDRESS
 * ---------------------------------------
 * se_interface_common.h reaches the Secure Engine through an ABSOLUTE
 * address, not a symbol:
 *     SE_CallGatePtr = (...)((uint32_t) SE_CALLGATE_REGION_ROM_START + 5U);
 * (+5 = +4 for ST's four padding bytes, +1 for the Thumb bit).  So
 * .SE_CallGate_Code must start exactly at SE_CALLGATE_REGION_ROM_START and
 * must begin with those four bytes.  Get this wrong and the bootloader
 * branches into the middle of an instruction on its first crypto call.
 *
 * The other placements that are load-bearing rather than decorative:
 *   .SE_Key_Data      se_key.s, at SE_KEY_REGION_ROM_START
 *   SE code           inside SE_CODE_REGION_ROM_START..END, because
 *                     se_low_level.c's SE_LL_Buffer_part_of_SE_rom() tests
 *                     pointers against that range.  If SE code sat outside
 *                     it, that check would answer "no overlap" for the
 *                     Secure Engine's own memory.
 */

INCLUDE mapping_sbsfu.ld
INCLUDE mapping_fwimg.ld

MEMORY
{
  VECTORS   (rx) : ORIGIN = 0x00000000,                       LENGTH = VECTOR_SIZE
  SE_ENTRY  (rx) : ORIGIN = __ICFEDIT_SE_CallGate_region_ROM_start__,
                   LENGTH = SE_Entry_Secure_ROM_Region_Length
  SE_KEY    (rx) : ORIGIN = __ICFEDIT_SE_Key_region_ROM_start__,
                   LENGTH = SE_Key_region_ROM_Length
  SE_START  (rx) : ORIGIN = __ICFEDIT_SE_Startup_region_ROM_start__,
                   LENGTH = SE_Startup_region_ROM_Length
  SE_ROM    (rx) : ORIGIN = __ICFEDIT_SE_Code_nokey_region_ROM_start__,
                   LENGTH = SE_ROM_region_Length
  SE_IF_ROM (rx) : ORIGIN = __ICFEDIT_SE_IF_region_ROM_start__,
                   LENGTH = SE_IF_region_ROM_Length
  SB_ROM    (rx) : ORIGIN = __ICFEDIT_SB_region_ROM_start__,
                   LENGTH = SB_ROM_region_Length
  SE_RAM   (rwx) : ORIGIN = __ICFEDIT_SE_region_RAM_stack_top__,
                   LENGTH = SE_RAM_region_Length
  SB_RAM   (rwx) : ORIGIN = __ICFEDIT_SB_region_RAM_start__,
                   LENGTH = SB_RAM_region_Length
}

ENTRY(Reset_Handler)

/* _estack is defined in mapping_sbsfu.ld, next to the reasoning for where
 * the stack has to live on a port with no isolation. */

SECTIONS
{
  .vectors : { KEEP(*(.vectors)) } > VECTORS

  .SE_CallGate_Code :
  {
    /* ST's four dummy bytes.  SE_CallGate therefore begins at
       SE_CALLGATE_REGION_ROM_START + 4, which is what the +5 in
       se_interface_common.h's SET_CALLGATE() (with the Thumb bit) points at.
       Removing them moves the entry point and breaks every SE call. */
    BYTE(0); BYTE(0); BYTE(0); BYTE(0);
    KEEP(*(.SE_CallGate_Code))
  } > SE_ENTRY

  .SE_Key_Data : { KEEP(*(.SE_Key_Data)) } > SE_KEY

  .SE_Startup_Code : { KEEP(*se_startup.o(.text .text*)) } > SE_START

  /* Secure Engine code and read-only data: mbedTLS, the SE core, ST's crypto
     bootloader and this port's se_low_level.  Selected by object path, which
     is why the Makefile keeps them in their own build subdirectories. */
  .se_text :
  {
    . = ALIGN(4);
    *mbedtls/*.o (.text .text* .rodata .rodata*)
    *se/se_callgate.o (.text .text* .rodata .rodata*)
    *se/se_exception.o (.text .text* .rodata .rodata*)
    *se/se_fwimg.o (.text .text* .rodata .rodata*)
    *se/se_user_application.o (.text .text* .rodata .rodata*)
    *stock/se_crypto_bootloader.o (.text .text* .rodata .rodata*)
    *port/se_low_level.o (.text .text* .rodata .rodata*)
    . = ALIGN(4);
  } > SE_ROM

  /* The SE interface trampolines sit OUTSIDE the SE code region, because on
     ST's parts they are the only thing allowed to call into it from the
     unprotected side.  Here nothing enforces that, but the placement is kept
     so the regions mean what mapping_sbsfu.ld says they mean. */
  .se_if_text :
  {
    . = ALIGN(4);
    *se/se_interface_bootloader.o (.text .text* .rodata .rodata*)
    *se/se_interface_common.o (.text .text* .rodata .rodata*)
    . = ALIGN(4);
  } > SE_IF_ROM

  .text :
  {
    . = ALIGN(4);
    *(.text .text*)
    *(.rodata .rodata*)
    *(.glue_7) *(.glue_7t) *(.eh_frame)
    . = ALIGN(4);
    _etext = .;
  } > SB_ROM

  .data : AT (_etext)
  {
    . = ALIGN(4);
    _sdata = .;
    *(.data .data*)
    . = ALIGN(4);
    _edata = .;
  } > SB_RAM

  .bss (NOLOAD) :
  {
    . = ALIGN(4);
    _sbss = .;
    *(.bss .bss*)
    *(COMMON)
    . = ALIGN(4);
    _ebss = .;
  } > SB_RAM

  /* Survives reset and is not cleared at startup: startup.c's fault record
     and the BSP's bus-transaction counters.  Placed after .bss so the
     _sbss.._ebss clear loop cannot reach it, and BEFORE the heap so malloc
     cannot either.
     THAT ORDER IS A BUG FIX, NOT TIDINESS.  With the heap symbols emitted
     first, `end` pointed at the address .noinit was about to occupy, and
     mbedTLS's first allocation overwrote the counters -- which then read
     back as SRAM addresses (0x2000128C) rather than as counts.  A record
     that survives reset is worth nothing if the heap eats it. */
  .noinit (NOLOAD) : { . = ALIGN(4); *(.noinit) . = ALIGN(4); } > SB_RAM

  /* THE HEAP.  mbedTLS allocates: ecp.c and bignum.c call mbedtls_calloc for
     every MPI limb array, and ST's config does not select
     MBEDTLS_MEMORY_BUFFER_ALLOC_C, so those go to newlib's malloc and newlib
     asks _sbrk for memory.  _sbrk needs `end`.
     Without it the link fails with the famously unhelpful "undefined
     reference to `end'" from sbrk.o; WITH `end` but no bound, a heap that
     grows into the stack fails much later and much more quietly. */
  . = ALIGN(8);
  PROVIDE(end = .);
  PROVIDE(_end = .);
  _heap_start = .;
  _heap_end = __ICFEDIT_SB_region_RAM_end__;


  /* The Secure Engine's own RAM.  Nothing is placed here by name: with no
     isolation the SE's variables are ordinary .bss.  The region is reserved
     rather than used, so that se_low_level.c's SE_LL_Buffer_part_of_SE_ram()
     has a range to test against and so that the split survives if isolation
     is ever added on a part that has it. */
  .se_bss (NOLOAD) : { . = ALIGN(4); *(.se_bss) . = ALIGN(4); } > SE_RAM

  /DISCARD/ : { *(.ARM.exidx*) *(.comment) *(.ARM.attributes) }

  /* Fail the LINK rather than the BOOT.  Each of these has a failure mode
     that is silent or misleading at run time:
       - an overflowing region shows up as a hard fault in whatever got
         pushed past the end;
       - a call gate at the wrong address branches into an instruction's
         middle on the first crypto call;
       - a bootloader that runs into the active slot's header corrupts the
         image it is about to verify. */
  ASSERT(ADDR(.SE_CallGate_Code) == __ICFEDIT_SE_CallGate_region_ROM_start__,
         "SE_CallGate is not at SE_CALLGATE_REGION_ROM_START")
  ASSERT(SIZEOF(.se_text) <= SE_ROM_region_Length,
         "Secure Engine code overflows SE_ROM -- raise SE_Code_region_ROM_end")
  ASSERT(SIZEOF(.se_if_text) <= SE_IF_region_ROM_Length,
         "SE interface overflows SE_IF_ROM")
  ASSERT(_etext <= __ICFEDIT_SLOT_Active_1_header__,
         "SBSFU code runs into the active slot header")
  ASSERT(_ebss <= __ICFEDIT_SB_region_RAM_end__,
         "SBSFU RAM overflows -- .bss past SB_region_RAM_end")
  ASSERT(_heap_end - _heap_start >= 4096,
         "under 4 KB of heap left for mbedTLS's MPI allocations")
}
