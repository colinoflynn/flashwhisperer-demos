/*
*****************************************************************************
**
**  File        : LinkerScript.ld
**
**  Abstract    : Linker script for STM32L475VGTx Device with
**                1024KByte FLASH, 96KByte RAM
**
**                Set heap size, stack size and stack location according
**                to application requirements.
**
**                Set memory bank area and size if external memory is used.
**
**  Target      : STMicroelectronics STM32
**
**
**  Distribution: The file is distributed as is, without any warranty
**                of any kind.
**
**  (c)Copyright Ac6.
**  You may use this file as-is or modify it according to the needs of your
**  project. Distribution of this file (unmodified or modified) is not
**  permitted. Ac6 permit registered System Workbench for MCU users the
**  rights to distribute the assembled, compiled & linked contents of this
**  file as part of an application binary file, provided that it is built
**  using the System Workbench for MCU toolchain.
**
*****************************************************************************
*/

/* Entry Point */
ENTRY(Reset_Handler)

/* Highest address of the user mode stack */
_estack = 0x20018000;    /* end of SB_SRAM1 */

/* Generate a link error if heap and stack don't fit into RAM */
_Min_Heap_Size = 0;      /* required amount of heap  */
_Min_Stack_Size = 0x2000; /* required amount of stack */

INCLUDE mapping_fwimg.ld
INCLUDE mapping_sbsfu.ld

/* Specific SBSFU definition */
__ICFEDIT_intvec_start__    = 0x08000000;
SE_Binary_region_ROM_Length = __ICFEDIT_SE_Code_region_ROM_end__ - __ICFEDIT_SE_CallGate_region_ROM_start__ + 1;

/* Specify the memory areas */
MEMORY
{
 ISR_VECTOR (rx)               : ORIGIN = __ICFEDIT_intvec_start__, LENGTH = VECTOR_SIZE
 SE_Binary_region_ROM (rx)     : ORIGIN = __ICFEDIT_SE_CallGate_region_ROM_start__, LENGTH = SE_Binary_region_ROM_Length
}

/* Define output sections */
SECTIONS
{
  /* The startup code goes first into FLASH */
  .isr_vector :
  {
    . = ALIGN(8);
    KEEP(*(.isr_vector)) /* Startup code */
    . = ALIGN(8);
  } >ISR_VECTOR
  .text.SE_CORE_Bin :
  {
    SE_CORE_Bin_start = .;
    KEEP(*(SE_CORE_Bin));
    SE_CORE_Bin_end = .;
  } > SE_Binary_region_ROM
  .SE_IF_Code : { KEEP(*se_interface_application.o (.text .text*))
                  KEEP(*se_interface_bootloader.o (.text .text*))
                  KEEP(*se_interface_common.o (.text .text*))
  } >SE_IF_region_ROM

  /* ------------------------------------------------------------------ *
   * L475 PORT: the three Secure Engine sections a SINGLE-ELF link has to
   * place itself.  Copied from ST's own SECoreBin script,
   * 2_Images_SECoreBin/STM32CubeIDE/STM32L475VGTx_FLASH.ld lines 45-54.
   *
   * ST's SBSFU script does not place them because in ST's build the whole
   * Secure Engine arrives as a PREBUILT BINARY: `.text.SE_CORE_Bin` above
   * KEEPs a blob called SE_CORE_Bin into SE_Binary_region_ROM, and the SE's
   * own sections never reach this link.  This rig compiles the SE from
   * source into the same ELF, so without the three rules below those
   * sections have no output section, --gc-sections collects them, and THE
   * LINK SUCCEEDS.  That is the trap worth naming: it succeeded here first
   * time round, reporting 82 416 bytes of text, and the image contained no
   * Secure Engine and no mbedTLS at all -- no undefined reference, because
   * SBSFU reaches the call gate through an ADDRESS taken from a linker
   * symbol rather than through a symbol reference.  A bootloader that
   * links, boots and has no cipher in it.
   *
   * TWO ADDRESSES ARE LOAD-BEARING and both are checked by ST's code at
   * run time rather than by this script:
   *
   *   SE_CallGate_Code   se_interface_common.c:59 takes the gate's address
   *                      from SE_CALLGATE_REGION_ROM_START, so the gate has
   *                      to BE there.
   *   SE_IF_Code         se_callgate.c:99-102 resets the part unless the
   *                      caller's LR lies between SE_IF_REGION_ROM_START
   *                      and _END -- which is why ST's own rule above KEEPs
   *                      the three interface objects in that region, and
   *                      why moving them would present as a watchdog-shaped
   *                      reboot with nothing printed.
   *
   * WHAT IS NOT REPRODUCED: the rest of the SE's code and all of mbedTLS
   * stay in SB_ROM_region with the bootloader, rather than going into
   * SE_ROM_region where ST's blob would sit.  Nothing in this build reads
   * those bounds -- the firewall is off (see
   * 2_Images_SECoreBin/Inc/se_low_level.h) and no guard tests them -- and
   * keeping it this way means ONE region had to grow rather than a cascade
   * of four.  It does mean the AES tables land in the bootloader's region;
   * their address and 32-byte phase are what the attack needs and the build
   * records both in build/tables.txt.
   * ------------------------------------------------------------------ */
  .SE_CallGate_Code :
  {
    /* ST'S FOUR DUMMY BYTES, AND THEY ARE NOT PADDING.  Copied verbatim with
     * ST's own comment: the call gate has to START AT 0x08000204, not at the
     * region's base, because that is the address its callers jump to.  An
     * earlier version of this script dropped them and used ALIGN(4) instead,
     * which at offset zero does nothing -- the gate landed at 0x08000200,
     * every SE call entered four bytes early, and the board printed ST's
     * banner, passed the security check and took a Hard fault on the first
     * SE call.  Measured on silicon, not predicted. */
    BYTE(0);           /* dummy byte to keep the callgate at 0x8000204 */
    BYTE(0);           /* dummy byte to keep the callgate at 0x8000204 */
    BYTE(0);           /* dummy byte to keep the callgate at 0x8000204 */
    BYTE(0);           /* dummy byte to keep the callgate at 0x8000204 */
    KEEP(*(.SE_CallGate_Code))
  } > SE_Entry_Secure_ROM_Region
  .SE_Key_Data : { KEEP(*(.SE_Key_Data)) } > SE_Key_region_ROM
  .SE_Startup_Code : { KEEP (*se_startup.o (.text .text*)) } > SE_Startup_region_ROM
  .text :
  {
    . = ALIGN(8);
    *(.text)           /* .text sections (code) */
    *(.text*)          /* .text* sections (code) */
    *(.glue_7)         /* glue arm to thumb code */
    *(.glue_7t)        /* glue thumb to arm code */
    *(.eh_frame)

    KEEP (*(.init))
    KEEP (*(.fini))

    . = ALIGN(8);
    _etext = .;        /* define a global symbols at end of code */
  } >SB_ROM_region

  /* Constant data goes into FLASH */
  /* L475 PORT: TABLEPAD, defaulting to 0 and defined by the Makefile.
   *
   * mbedTLS's tables live in aes.o's .rodata at a fixed offset from the start
   * of this section, so moving the section moves them -- and WHERE they land
   * is a scoring parameter twice over on this part: `addr mod 8` decides
   * which table entries share an 8-byte read latch line (the attack's
   * `line_off`), and `addr mod 32` decides the data cache's conflict phase
   * (research/targets/stm32l475.md section 5f).
   *
   * It exists because INSTR=0 moves them.  Taking the instrument out shrinks
   * .text by about 1.1 KB, which took RT0 from mod 32 == 8, mod 8 == 0 to
   * mod 32 == 20, mod 8 == 4.  A bus-side capture of that image compared with
   * the self-instrumented one would then differ in the observer AND in the
   * row geometry at the same time, and the geometry term is worth about 4x in
   * traces here -- so the comparison would measure the wrong thing.
   *
   * Padding changes no instruction in the decrypt path.  `make` prints the
   * resulting addresses and phases to build/tables.txt either way, and a
   * capture records them, so an unpadded build is not wrong -- just not
   * comparable. */
  .rodata :
  {
    . = ALIGN(8);
    . = . + TABLEPAD;
    *(.rodata)         /* .rodata sections (constants, strings, etc.) */
    *(.rodata*)        /* .rodata* sections (constants, strings, etc.) */
    . = ALIGN(8);
  } >SB_ROM_region

  .ARM.extab (READONLY) : /* The READONLY keyword is only supported in GCC11 and later, remove it if using GCC10 or earlier. */
  {
  . = ALIGN(8);
  *(.ARM.extab* .gnu.linkonce.armextab.*)
  . = ALIGN(8);
  } >SB_ROM_region

  .ARM (READONLY) : /* The READONLY keyword is only supported in GCC11 and later, remove it if using GCC10 or earlier. */
  {
	. = ALIGN(8);
    __exidx_start = .;
    *(.ARM.exidx*)
    __exidx_end = .;
	. = ALIGN(8);
  } >SB_ROM_region

  .preinit_array (READONLY) : /* The READONLY keyword is only supported in GCC11 and later, remove it if using GCC10 or earlier. */
  {
	. = ALIGN(8);
    PROVIDE_HIDDEN (__preinit_array_start = .);
    KEEP (*(.preinit_array*))
    PROVIDE_HIDDEN (__preinit_array_end = .);
	. = ALIGN(8);
  } >SB_ROM_region

  .init_array (READONLY) : /* The READONLY keyword is only supported in GCC11 and later, remove it if using GCC10 or earlier. */
  {
	. = ALIGN(8);
    PROVIDE_HIDDEN (__init_array_start = .);
    KEEP (*(SORT(.init_array.*)))
    KEEP (*(.init_array*))
    PROVIDE_HIDDEN (__init_array_end = .);
	. = ALIGN(8);
  } >SB_ROM_region

  .fini_array (READONLY) : /* The READONLY keyword is only supported in GCC11 and later, remove it if using GCC10 or earlier. */
  {
	. = ALIGN(8);
    PROVIDE_HIDDEN (__fini_array_start = .);
    KEEP (*(SORT(.fini_array.*)))
    KEEP (*(.fini_array*))
    PROVIDE_HIDDEN (__fini_array_end = .);
	. = ALIGN(8);
  } >SB_ROM_region

  /* used by the startup to initialize data */
  _sidata = LOADADDR(.data);

  /* Initialized data sections goes into RAM, load LMA copy after code */
  .data :
  {
    . = ALIGN(8);
    _sdata = .;        /* create a global symbol at data start */
    *(.data)           /* .data sections */
    *(.data*)          /* .data* sections */

    . = ALIGN(8);
    _edata = .;        /* define a global symbol at data end */
  } >SB_RAM_region AT>SB_ROM_region


  /* Uninitialized data section */
  . = ALIGN(4);
  .bss :
  {
    /* This is used by the startup in order to initialize the .bss section */
    _sbss = .;         /* define a global symbol at bss start */
    __bss_start__ = _sbss;
    *(.bss)
    *(.bss*)
    *(COMMON)

    . = ALIGN(4);
    _ebss = .;         /* define a global symbol at bss end */
    __bss_end__ = _ebss;
  } >SB_RAM_region

  /* User_heap_stack section, used to check that there is enough RAM left */
  ._user_heap_stack :
  {
    . = ALIGN(8);
    PROVIDE ( end = . );
    PROVIDE ( _end = . );
    . = . + _Min_Heap_Size;
    . = . + _Min_Stack_Size;
    . = ALIGN(8);
  } >SB_RAM_region



  /* Remove information from the standard libraries */
  /DISCARD/ :
  {
    libc.a ( * )
    libm.a ( * )
    libgcc.a ( * )
  }

  .ARM.attributes 0 : { *(.ARM.attributes) }
}


