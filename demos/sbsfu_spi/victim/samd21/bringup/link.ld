/* ATSAMD21J18A bring-up image for the SBSFU port's HAL and serial-flash BSP.
 *
 * Deliberately plain.  rigs/fw_samd21_aes/link.ld carries CODEPAD and
 * TABLEPAD, the two placement axes that campaign sweeps; this image measures
 * no timing channel and sweeps nothing, so carrying them here would imply an
 * axis that is never varied.  The bootloader proper gets its own script with
 * the SBSFU slot layout in it.
 *
 * Geometry is the part's, and matches rigs/fw_samd21_aes/link.ld: 256 KB main
 * array at 0x00000000 with no configuration sector below the image (the NVM
 * user row and factory calibration live in the separate auxiliary space at
 * 0x00804000 / 0x00806000), and 32 KB SRAM at 0x20000000 whose base is free
 * because Cortex-M0+ implements VTOR.
 *
 * The mailbox is fixed at 0x20000000 by main.c, so .data and .bss must start
 * above it.  128 bytes is reserved rather than the 32 words currently used,
 * so adding a field does not silently land on top of a variable.
 */
MEMORY
{
  FLASH (rx)  : ORIGIN = 0x00000000, LENGTH = 256K
  RAM   (rwx) : ORIGIN = 0x20000080, LENGTH = 32K - 0x80
}
ENTRY(Reset_Handler)
SECTIONS
{
  .vectors : { KEEP(*(.vectors)) } > FLASH

  .text :
  {
    *(.text*)
    *(.rodata*)
    . = ALIGN(4);
    _etext = .;
  } > FLASH

  .data : AT (_etext)
  {
    _sdata = .;
    *(.data*)
    . = ALIGN(4);
    _edata = .;
  } > RAM

  .bss (NOLOAD) :
  {
    _sbss = .;
    *(.bss*)
    *(COMMON)
    . = ALIGN(4);
    _ebss = .;
  } > RAM

  /* 4 KB of read buffer lives in .bss and the stack grows down from the top
     of SRAM, so they are nowhere near each other; the assert is here because
     a bring-up image that overflows its stack into its own results reports
     plausible wrong numbers rather than crashing. */
  _estack = ORIGIN(RAM) + LENGTH(RAM);
  ASSERT(_ebss + 2048 < _estack, "SRAM exhausted: .bss leaves under 2 KB of stack")

  /DISCARD/ : { *(.ARM.exidx*) *(.comment) }
}
