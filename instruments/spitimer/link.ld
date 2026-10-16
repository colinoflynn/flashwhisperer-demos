/* NUCLEO-F303RE (STM32F303RET6): 512 KB flash @ 0x08000000, 64 KB SRAM @
 * 0x20000000, plus 16 KB CCM @ 0x10000000.
 *
 * Deliberately plain.  rigs/fw_f303_aes/link.ld carries SBOX_OFF, CODEPAD
 * and a fixed-address RAM table section, because that rig sweeps code and
 * table placement.  This one measures nothing about its own flash -- it is
 * the instrument, not the subject -- so carrying those knobs would imply
 * axes that are never varied.
 *
 * The capture buffer is 48 KB of .bss and the whole point of it is that a
 * verify pass fits, so the ASSERT below is load-bearing: if it ever stops
 * fitting, the DMA silently stops at the end of the buffer and the capture
 * loses its tail.
 */
MEMORY
{
  FLASH (rx)  : ORIGIN = 0x08000000, LENGTH = 512K
  RAM   (rwx) : ORIGIN = 0x20000000, LENGTH = 64K
  CCM   (rwx) : ORIGIN = 0x10000000, LENGTH = 16K
}
ENTRY(Reset_Handler)
SECTIONS
{
  .isr_vector : { KEEP(*(.isr_vector)) } > FLASH

  .text :
  {
    . = ALIGN(4);
    *(.text*)
    *(.rodata*)
    . = ALIGN(4);
    _etext = .;
  } > FLASH
  _sidata = LOADADDR(.data);

  .data : AT (_etext)
  {
    . = ALIGN(4);
    _sdata = .;
    *(.data*)
    . = ALIGN(4);
    _edata = .;
  } > RAM

  .bss (NOLOAD) :
  {
    . = ALIGN(4);
    _sbss = .;
    *(.bss*)
    *(COMMON)
    . = ALIGN(4);
    _ebss = .;
  } > RAM

  _estack = ORIGIN(RAM) + LENGTH(RAM);

  /* The capture buffer dominates .bss.  4 KB of stack is far more than this
     firmware needs -- it has no recursion and no large locals -- but the
     margin is what stops a buffer enlargement from quietly colliding with
     the stack. */
  ASSERT(_ebss + 4096 < _estack,
         "capture buffer leaves under 4 KB of stack -- reduce CAP_N")

  /DISCARD/ : { *(.ARM.exidx*) *(.comment) *(.ARM.attributes) }
}
