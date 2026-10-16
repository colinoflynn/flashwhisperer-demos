/* NUCLEO-L152RE bring-up image for the SBSFU port's serial-flash BSP.
 *
 * Deliberately plain, and deliberately NOT the bootloader's script: this
 * image measures no timing channel, sweeps no table placement, and knows
 * nothing about SBSFU's slot layout.  rigs/fw_l1_aes/link.ld carries CODEPAD
 * for the placement sweep and the bootloader gets mapping_sbsfu.ld; carrying
 * either here would imply an axis that is never varied.
 *
 * Geometry is the part's: STM32L152RE, 512 KB flash at 0x08000000 and 80 KB
 * SRAM at 0x20000000.  Symbol names are the ones ST's own
 * startup_stm32l152xe.s expects (_sidata, _sdata, _edata, _sbss, _ebss,
 * _estack), because that file is used unmodified.
 */
MEMORY
{
  FLASH (rx)  : ORIGIN = 0x08000000, LENGTH = 512K
  RAM   (rwx) : ORIGIN = 0x20000000, LENGTH = 80K
}
_estack = ORIGIN(RAM) + LENGTH(RAM);
ENTRY(Reset_Handler)
SECTIONS
{
  .isr_vector : { KEEP(*(.isr_vector)) . = ALIGN(4); } > FLASH

  .text :
  {
    *(.text*)
    *(.rodata*)
    KEEP(*(.init))
    KEEP(*(.fini))
    . = ALIGN(4);
    _etext = .;
  } > FLASH

  .ARM.extab : { *(.ARM.extab*) } > FLASH
  .ARM : { __exidx_start = .; *(.ARM.exidx*) __exidx_end = .; } > FLASH

  .preinit_array : { PROVIDE_HIDDEN(__preinit_array_start = .);
                     KEEP(*(.preinit_array*))
                     PROVIDE_HIDDEN(__preinit_array_end = .); } > FLASH
  .init_array    : { PROVIDE_HIDDEN(__init_array_start = .);
                     KEEP(*(SORT(.init_array.*))) KEEP(*(.init_array*))
                     PROVIDE_HIDDEN(__init_array_end = .); } > FLASH
  .fini_array    : { PROVIDE_HIDDEN(__fini_array_start = .);
                     KEEP(*(SORT(.fini_array.*))) KEEP(*(.fini_array*))
                     PROVIDE_HIDDEN(__fini_array_end = .); } > FLASH

  /* `> RAM AT > FLASH` places .data in RAM and its initialiser image in
     flash, and _sidata is then read back with LOADADDR.  Writing `AT
     (_sidata)` as well -- naming the load address AND the load region --
     is rejected as "section has both a load address and a load region",
     and the overflow figure ld prints for it is a wrapped negative. */
  .data :
  {
    . = ALIGN(4);
    _sdata = .;
    *(.data*)
    . = ALIGN(4);
    _edata = .;
  } > RAM AT > FLASH
  _sidata = LOADADDR(.data);

  .bss (NOLOAD) :
  {
    . = ALIGN(4);
    _sbss = .;
    __bss_start__ = _sbss;
    *(.bss*)
    *(COMMON)
    . = ALIGN(4);
    _ebss = .;
    __bss_end__ = _ebss;
  } > RAM

  /* The BSP's bus-transaction counters live here.  ST's startup clears .bss
     and copies .data, and touches nothing else, so a variable placed here
     survives a reset -- which is the whole point: SBSFU reboots when an
     install fails, and counters cleared by the reset they are meant to
     explain report zero every time.  The bring-up image does not reboot,
     but it links the SAME BSP object the bootloader does, so the section
     has to exist in both scripts or one of them fails to link. */
  .noinit (NOLOAD) :
  {
    . = ALIGN(4);
    *(.noinit*)
    . = ALIGN(4);
  } > RAM

  . = ALIGN(8);
  _end = .;
  PROVIDE(end = .);

  /* A 4 KB read buffer lives in .bss and the stack grows down from the top
     of SRAM.  The assert is here because a bring-up image that overflows
     its stack into its own results reports plausible wrong numbers rather
     than crashing -- and this image exists precisely to be believed. */
  ASSERT(_end + 4096 < _estack, "SRAM exhausted: under 4 KB left for stack")

  /DISCARD/ : { *(.comment) }
}
