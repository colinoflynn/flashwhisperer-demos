# X-CUBE-SBSFU v2.7.0 for the B-L475E-IOT01A.
#
# Built in WSL -- arm-none-eabi-gcc is WSL-only on this host:
#
#   ../fw_samd21_sbsfu/fetch_sbsfu.sh   # once: ST's bootloader package
#   ./gen_keys.sh                       # once: ST's demo keys as se_key.s
#   wsl -- bash -lc 'cd <this dir> && make check'
#
# Targets:
#   check       compile every translation unit, link nothing
#   all         link the bootloader
#   chunkcheck  assert SFU_IMG_CHUNK_SIZE as ST'S SOURCES RESOLVE IT
#   stockcheck  confirm the pinned tree is present and complete
#
# THERE IS NO SECOND FETCH HERE, and that is the difference from the two
# ports next door.  X-CUBE-SBSFU ships a project for THIS board --
# Projects/B-L475E-IOT01A/Applications/2_Images_ExtFlash, which is the very
# project both other ports were derived from -- and the package also ships
# the STM32L4 HAL, the CMSIS device headers and the B-L475E-IOT01 BSP that
# project builds against.  So one pinned tree supplies everything: no second
# version to keep in step, and the HAL is the one ST validated against this
# release of the bootloader.  The L152 port fetches STM32CubeL1 only because
# the package contains no STM32L1 project at all.
#
# WHAT THIS PORT OWNS, which is nearly nothing:
#
#   B_L475E_IOT01A/Instr/           new: the victim times its own loop
#   B_L475E_IOT01A/.../app_sfu.h            ST's + a build knob
#   B_L475E_IOT01A/.../sfu_fwimg_internal.h ST's + a build knob
#   B_L475E_IOT01A/.../se_mbedtls_config.h  ST's + AES ROM tables
#   B_L475E_IOT01A/.../se_low_level.h       ST's + SE isolation off
#   B_L475E_IOT01A/.../se_intrinsics.h      GCC get_LR(), from the L152 port
#   patches/                                two instrumentation hunks
#
# Every other file compiled below is ST's, read out of the pinned checkout
# and never written to.  There is no port layer: ST wrote this board's
# Target/ and SECoreBin/ files, so a file that is not in B_L475E_IOT01A/
# cannot have been edited, because the build never reads a local copy of it.
# ./diff_vs_stock.sh prints the complete list.

# The staging rules below are generated with $(eval), and the first of them
# is defined long before `all:` -- so without this, a bare `make` builds one
# staged .c file and stops, reporting "is up to date" as though it had done
# the whole build.
.DEFAULT_GOAL := all

SBSFU_ROOT ?= $(abspath ../../../sbsfu-src)

STOCK   = $(SBSFU_ROOT)/Projects/B-L475E-IOT01A/Applications/2_Images_ExtFlash
SE_MW   = $(SBSFU_ROOT)/Middlewares/ST/STM32_Secure_Engine
MBEDTLS = $(SBSFU_ROOT)/Middlewares/Third_Party/mbedtls

HAL     = $(SBSFU_ROOT)/Drivers/STM32L4xx_HAL_Driver
CMSIS_D = $(SBSFU_ROOT)/Drivers/CMSIS/Device/ST/STM32L4xx
CMSIS_C = $(SBSFU_ROOT)/Drivers/CMSIS/Core/Include
BSP     = $(SBSFU_ROOT)/Drivers/BSP/B-L475E-IOT01
BSPCOMP = $(SBSFU_ROOT)/Drivers/BSP/Components

CROSS  = arm-none-eabi-
# ST's own flags for this project (2_Images_SBSFU/STM32CubeIDE/.cproject):
# hard float on an fpv4-sp-d16.  Following them rather than dropping to
# soft float keeps the FPU question ST's: SystemInit sets CPACR under
# __FPU_USED, which is defined because of these flags, and the startup file
# is hand-written assembly so there is no C copy loop to vectorise before
# that happens.
CPU    = -mcpu=cortex-m4 -mthumb -mfloat-abi=hard -mfpu=fpv4-sp-d16
PORT   = B_L475E_IOT01A
BUILD ?= build

# Defined HERE, not next to its rule.  The $(eval)-generated compile rules
# below expand their prerequisite lists at eval time, so a variable defined
# further down the file expands to nothing there and the staged header tree
# does not get built first.
STAGED_H = $(BUILD)/inc/.stamp

# Every compile depends on this stamp, and the stamp is rewritten whenever
# the flag set changes.  Without it, `make CHUNK=64` after `make CHUNK=512`
# reports "Nothing to be done" and leaves the previous chunk size in the
# binary.  The comparison is on CONTENT, so a rebuild with unchanged flags
# does not touch the stamp and nothing recompiles.
FLAGS_STAMP = $(BUILD)/.flags

# --- the chunk size --------------------------------------------------------
# ST ships 512, and ON THIS PART THE DEFAULT STAYS THERE -- which is new.
# Both other ports had to bring it down, the SAM D21 to 64 because its
# 64-byte unified cache needs the chunk small for a collision attack to see
# anything.  Simulated on this part's MEASURED geometry
# (results/bootloader_spi/sim_spi_oracle_l475_ttable.json), round-1 recovery
# against a 1 KB table is FLAT from 16 B to ST's 512 B: 24/24 pair deltas at
# every chunk size, because traces-to-key is set by AES blocks and a bigger
# chunk buys proportionally more blocks per read.  So the knob exists to
# check that on silicon, not to make the demo work.
CHUNK ?= 512
ifneq ($(shell expr $(CHUNK) % 16),0)
$(error CHUNK must be a multiple of 16, got $(CHUNK))
endif

# --- the AES tables, which is this port's one real deviation ---------------
# RAMTABLES=1 is ST'S SHIPPED CONFIGURATION: the package leaves
# MBEDTLS_AES_ROM_TABLES commented out, so mbedTLS computes its tables into
# .bss and the cipher's lookups never touch flash.  The default here turns
# it on, which is a documented mbedTLS option and the thing a small-RAM
# integrator reaches for -- but it is not what ST hands you, and the README
# says so in those words.
#
# The polarity makes one build do two jobs: RAMTABLES=1 is simultaneously
# ST's default AND the RAM twin that research/mechanism/MEASURING_CHANNELS.md
# requires as a control.
RAMTABLES ?= 0
VARDEF =
ifeq ($(RAMTABLES),1)
VARDEF += -DPORT_RAM_TABLES
TABLES = ram
else
TABLES = flash
endif

# --- protections -----------------------------------------------------------
# PROTECT=bench is the only build this rig links, and the refusal below
# names the reason rather than letting a `stock` build fail in the linker
# with duplicate HAL_GetTick.  B_L475E_IOT01A/2_Images_SECoreBin/Inc/
# se_low_level.h has the whole of it: firewall isolation needs ST's
# two-binary flow, which this Makefile does not implement.
PROTECT ?= bench
ifeq ($(PROTECT),bench)
VARDEF += -DPORT_DISABLE_SECURITY_IPS
else
$(error PROTECT=$(PROTECT) is not supported by this rig -- only `bench`. \
  A stock-protection build needs Secure Engine isolation, and that needs \
  SECoreBin built as a separate binary; see \
  B_L475E_IOT01A/2_Images_SECoreBin/Inc/se_low_level.h)
endif

# --- the instrument, and whether there is one ------------------------------
# INSTR=0 builds the bus-side target: ST's decrypt path with NOTHING added to
# it, for a capture taken from a probe on the flash's chip select rather than
# from the victim's own clock.  It is what the attacker in
# results/bootloader_spi/l475_bus/ faces.
#
# THREE THINGS GO TOGETHER HERE and dropping any one leaves an image that
# looks stock and is not: patches/0001 and 0002 are not applied, Instr/ is not
# compiled (its buffer is 12 KB of .bss and its dump is .text -- present in
# the image is present, whether or not anything calls it), and the variant
# string records which build this is, because with INSTR=0 the firmware prints
# no I-BEGIN line and cannot name itself to a capture.  `make instrcheck`
# asserts all of it, in whichever direction INSTR is set.
INSTR ?= 1

# TABLEPAD moves the AES tables without touching the code, so two builds can
# be compared on one row geometry.  See the comment on .rodata in
# B_L475E_IOT01A/2_Images_SBSFU/l475_sbsfu.ld for what the phases decide.
#
# 0 means "wherever this build's size puts them", which is right for a single
# campaign and wrong for comparing two.  INSTR=0 TABLEPAD=20 reproduces the
# instrumented build's phases (RT0 mod 32 == 8, mod 8 == 0) in a stock image.
TABLEPAD ?= 0
ifeq ($(INSTR),1)
SKIP_PATCHES =
INSTRTAG = instr
else ifeq ($(INSTR),0)
# By NUMBER, not by name: the number is what the staging loop matches on, and
# a rename of a patch file then fails loudly instead of quietly instrumenting
# a stock build.
SKIP_PATCHES = 0001 0002
INSTRTAG = stock
else
$(error INSTR must be 0 or 1, got $(INSTR))
endif

# --- the instrument --------------------------------------------------------
# SLOTS is how many intervals one pass can record.  ST's 512-byte chunk over
# a 44 KB body is 88; the same body at chunk 16 is 2 816, which is what the
# default has to cover.  A full buffer is counted and reported, never
# wrapped.
SLOTS ?= 3072

# ORACLE=1 is the capture build: ST's own verbose trace off, so that nothing
# prints inside the pass being timed.  Two of ST's traces sit in the decrypt
# loop and cost milliseconds of polled UART each, against a signal a cycle
# or two wide -- and on another rig in this repository a 1 Hz console line
# on the far end corrupted whole groups and produced a wrong conclusion.
# The instrument's own dump runs after the pass, never inside it.
ORACLE ?= 0
ifeq ($(ORACLE),1)
VERBOSE ?= 0
endif
VERBOSE ?= 1
ifneq ($(VERBOSE),1)
VARDEF += -DPORT_NO_VERBOSE
endif

OPT ?= -O2

# The variant string the firmware prints with every capture, so a trace file
# can always name the build that produced it.  Every knob that changes the
# measurement is in it.
VARIANT = chunk$(CHUNK)-$(TABLES)-$(PROTECT)-$(INSTRTAG)-pad$(TABLEPAD)-$(subst -O,O,$(OPT))

# ONE header tree, built by stage_headers.sh, plus the directories nothing
# is overridden in.  See that script for why the obvious spelling (ST's
# directories and this port's both on -I, ours first) does NOT work.
INCS = \
  -I$(BUILD)/inc \
  -I$(SE_MW)/Core \
  -I$(SE_MW)/Key \
  -I$(SE_MW)/Interface \
  -I$(MBEDTLS)/include \
  -I$(HAL)/Inc \
  -I$(CMSIS_D)/Include \
  -I$(CMSIS_C) \
  -I$(BSP) \
  -I$(BSPCOMP)/mx25r6435f \
  -I$(BSPCOMP)/Common

# MBEDTLS_CONFIG_FILE is set for EVERY translation unit, not just mbedTLS's
# own.  mbedTLS's headers are configured by that macro, so a unit that
# includes mbedtls/aes.h without it gets the library's DEFAULT config and a
# different idea of structure layouts and enabled features than the compiled
# library has.  That mismatch links cleanly and corrupts memory at run time,
# which is the worst way for a bootloader to be wrong.
#
# USE_STM32L475E_IOT01 is ST's board define, taken from their .cproject.
# -MMD -MP emit a .d per object; the -include near the bottom picks them up.
# WITHOUT THAT a header edit rebuilds nothing, and the link runs against
# objects compiled from a version of the header that no longer exists.
CFLAGS = $(CPU) $(OPT) -g -MMD -MP -ffreestanding -fno-common -Wall -Wextra \
         -DSTM32L475xx -DUSE_HAL_DRIVER -DUSE_STM32L475E_IOT01 \
         -DSFU_IMG_CHUNK_SIZE_OVERRIDE=$(CHUNK) \
         -DPORT_SINGLE_IMAGE=1 \
         -DSFU_INSTR_SLOTS=$(SLOTS)U \
         -DPORT_VARIANT='"$(VARIANT)"' \
         -DMBEDTLS_CONFIG_FILE='"se_mbedtls_config.h"' \
         $(VARDEF) $(INCS)

# ST's code compiles with its own format warnings silenced.  They are real
# but they are ST's: uint32_t is `long unsigned int` for this toolchain and
# `unsigned int` for the one ST builds with, so every "%d" on a uint32_t in
# their trace strings fires here and nowhere for them.  Silenced for ST's
# files ONLY -- this port's own sources keep -Wall -Wextra with nothing
# suppressed -- so a real warning in our code stays visible instead of being
# buried in a hundred of theirs.
#
# -fcommon, which is NOT a style choice.  ST's sfu_fwimg_regions.h DEFINES
# the slot tables -- SlotStartAdd, SlotEndAdd, SlotHeaderAdd -- in the
# header itself rather than declaring them extern, so every translation unit
# that includes it emits one.  Those merge under -fcommon, which was GCC's
# default up to GCC 9 and is what ST builds with; under GCC 10's -fno-common
# they are three definitions of the same array and the link fails.  ST's
# intent is one table, so the flag that produces one table is the faithful
# build.  IT APPLIES TO ST'S FILES ONLY: this port's own source keeps
# -fno-common, where a duplicate definition is a bug and should fail.
STOCK_CFLAGS = $(CFLAGS) -Wno-format -Wno-unused-parameter -fcommon

# Recorded verbatim, not summarised: a stamp that lists only the knobs
# someone remembered to add is a stamp that silently stops covering the
# next one.
FLAGS_TEXT := $(CFLAGS) | $(STOCK_CFLAGS) | $(LDFLAGS)

# ---------------------------------------------------------------- sources --

# This port's own code.  One file, and none at all in a stock build -- see
# INSTR above for why leaving it compiled-but-uncalled would not count.
ifeq ($(INSTR),1)
PORT_SRC = \
  $(PORT)/Instr/sfu_instr.c
else
PORT_SRC =
endif

# ST's STM32L4xx HAL, compiled in place and unmodified.  Only the modules
# this firmware calls -- the list was taken from the HAL_<MODULE>_ symbols
# ST's own project, BSP and Secure Engine reference, not guessed.  ST's
# stm32l4xx_hal_conf.h enables every module in the package, which decides
# which HEADERS are visible rather than which objects are linked, so the
# subset here is a build-time choice and not a deviation from ST's
# configuration.
HAL_SRC = \
  $(HAL)/Src/stm32l4xx_hal.c \
  $(HAL)/Src/stm32l4xx_hal_cortex.c \
  $(HAL)/Src/stm32l4xx_hal_rcc.c \
  $(HAL)/Src/stm32l4xx_hal_rcc_ex.c \
  $(HAL)/Src/stm32l4xx_hal_gpio.c \
  $(HAL)/Src/stm32l4xx_hal_pwr.c \
  $(HAL)/Src/stm32l4xx_hal_pwr_ex.c \
  $(HAL)/Src/stm32l4xx_hal_qspi.c \
  $(HAL)/Src/stm32l4xx_hal_dma.c \
  $(HAL)/Src/stm32l4xx_hal_uart.c \
  $(HAL)/Src/stm32l4xx_hal_uart_ex.c \
  $(HAL)/Src/stm32l4xx_hal_crc.c \
  $(HAL)/Src/stm32l4xx_hal_crc_ex.c \
  $(HAL)/Src/stm32l4xx_hal_flash.c \
  $(HAL)/Src/stm32l4xx_hal_flash_ex.c \
  $(HAL)/Src/stm32l4xx_hal_flash_ramfunc.c \
  $(HAL)/Src/stm32l4xx_hal_iwdg.c \
  $(HAL)/Src/stm32l4xx_hal_rtc.c \
  $(HAL)/Src/stm32l4xx_hal_rtc_ex.c \
  $(HAL)/Src/stm32l4xx_hal_firewall.c \
  $(HAL)/Src/stm32l4xx_hal_i2c.c \
  $(HAL)/Src/stm32l4xx_hal_i2c_ex.c \
  $(CMSIS_D)/Source/Templates/system_stm32l4xx.c

# ST's BSP for this board.  stm32l475e_iot01_qspi.c is the whole of it: it
# includes only its own header and carries its own BSP_QSPI_MspInit, so the
# board file stm32l475e_iot01.c is built only for what SBSFU itself calls:
# BSP_LED_Init/Off/Toggle from sfu_boot.c and sfu_com_loader.c, and
# BSP_PB_GetState, which is how ST's local loader is entered.  Its sensor
# drivers come with it, which is why HAL_SRC above carries stm32l4xx_hal_i2c
# -- the board file's NFC and sensor helpers reference it whether or not
# anything calls them.  --gc-sections drops the unreachable ones from the
# image, and the I2C itself is never initialised at run time.
#
# THIS FILE IS WHERE THE PORTS DIVERGE.  On the L152 and the SAM D21 the
# serial flash hangs off an SPI peripheral with chip-select on a plain GPIO,
# so the driver's own C opens and closes every envelope.  Here the
# MX25R6435F is on QUADSPI and nCS is driven by the IP per command -- which
# is why this rig times the gap from inside the victim instead.  See
# B_L475E_IOT01A/Instr/sfu_instr.h.
BSP_SRC = \
  $(BSP)/stm32l475e_iot01_qspi.c \
  $(BSP)/stm32l475e_iot01.c

# ST's SBSFU sources, paths relative to $(STOCK).  This list IS the realism
# claim: every one is the product's own code, byte for byte, bar the tracked
# patches in patches/.  sfu_fwimg_no_swap.c holds the read / decrypt / hash
# loop the whole campaign targets.
#
# !! THEY ARE STAGED INTO $(BUILD)/src/ AND COMPILED FROM THERE, NOT COMPILED
# !! WHERE THEY LIE, AND THE REASON IS A BUG THE SAM D21 BUILD ALREADY HAD.
#
# A quoted #include searches THE INCLUDING FILE'S OWN DIRECTORY FIRST, before
# any -I.  That is not overridable -- not by -I order, not by -iquote.  So
# while ST's sfu_fwimg_no_swap.c was compiled in ST's App/ directory, its
# `#include "sfu_fwimg_internal.h"` found ST's copy sitting next to it, and
# the port's copy -- the one that makes SFU_IMG_CHUNK_SIZE configurable --
# was never read.  CHUNK=64 and CHUNK=512 produced BYTE-IDENTICAL objects
# while the build reported success at both.
#
# Staging the .c files into a directory that holds NO headers fixes it: the
# own-directory search finds nothing and resolution falls through to -I.
# `make chunkcheck` asserts the outcome rather than trusting this comment.
#
# ONE OF THESE IS NOT WHERE A READER WOULD LOOK FOR IT: ST keeps syscalls.c
# in the CubeIDE project directory rather than in Src/, so nothing under Src/
# mentions it.  It is the newlib retarget that makes ST's TRACE macro (which
# is printf) reach the UART at all.
#
# ITS NEIGHBOUR data_init.c IS DELIBERATELY NOT BUILT.  It supplies
# __gcc_data_init, which se_startup.c calls on the first Secure Engine call
# to zero _sbss.._ebss and re-copy _sdata.._edata -- the whole image's RAM,
# in a single-ELF build.  patches/0005 removes the call, after it was
# measured wiping the bootloader's state on silicon; with the call gone this
# file has no caller.
STOCK_SRC = \
  2_Images_SBSFU/Core/Src/main.c \
  2_Images_SBSFU/Core/Src/stm32l4xx_hal_msp.c \
  2_Images_SBSFU/Core/Src/stm32l4xx_it.c \
  2_Images_SBSFU/STM32CubeIDE/Application/Core/syscalls.c \
  2_Images_SBSFU/SBSFU/Target/sfu_low_level.c \
  2_Images_SBSFU/SBSFU/Target/sfu_low_level_flash.c \
  2_Images_SBSFU/SBSFU/Target/sfu_low_level_flash_ext.c \
  2_Images_SBSFU/SBSFU/Target/sfu_low_level_flash_int.c \
  2_Images_SBSFU/SBSFU/Target/sfu_low_level_security.c \
  2_Images_SBSFU/SBSFU/App/sfu_boot.c \
  2_Images_SBSFU/SBSFU/App/sfu_fwimg_common.c \
  2_Images_SBSFU/SBSFU/App/sfu_fwimg_no_swap.c \
  2_Images_SBSFU/SBSFU/App/sfu_loader.c \
  2_Images_SBSFU/SBSFU/App/sfu_com_loader.c \
  2_Images_SBSFU/SBSFU/App/sfu_com_trace.c \
  2_Images_SBSFU/SBSFU/App/sfu_error.c \
  2_Images_SBSFU/SBSFU/App/sfu_new_image.c \
  2_Images_SECoreBin/Src/se_crypto_bootloader.c \
  2_Images_SECoreBin/Src/se_low_level.c

# ST's Secure Engine middleware.
#
# TWO OF ST'S SE CORE FILES ARE DELIBERATELY NOT BUILT:
#
#   se_crypto_common.c  is the AES-GCM helper set for the ST cryptolib back
#                       end.  It #includes "crypto.h", the cryptolib header,
#                       which is not in this package's mbedTLS build at all.
#                       The scheme here is SECBOOT_ECCDSA_WITH_AES128_CBC_
#                       SHA256, which calls no SE_CRYPTO_AES_GCM_* symbol.
#
# ONE IS BUILT WITH TWO FUNCTIONS PATCHED OUT:
#
#   se_utils.c          carries three things: SE_SetSystemCoreClock, which
#                       se_callgate.c calls and nothing else provides, and
#                       HAL_GetTick/HAL_Delay, which exist because behind
#                       ST's firewall the SE cannot reach the application's
#                       SysTick.  This build has the firewall off
#                       (se_low_level.h in B_L475E_IOT01A/), so ST's own HAL
#                       defines those two and keeping both copies is a
#                       duplicate definition.  patches/0004 drops se_utils'
#                       pair and keeps the clock setter.
SE_SRC = \
  $(SE_MW)/Core/se_callgate.c \
  $(SE_MW)/Core/se_exception.c \
  $(SE_MW)/Core/se_fwimg.c \
  $(SE_MW)/Core/se_startup.c \
  $(SE_MW)/Core/se_user_application.c \
  $(SE_MW)/Core/se_interface_bootloader.c \
  $(SE_MW)/Core/se_interface_common.c \
  $(SE_MW)/Core/se_utils.c

# The mbedTLS subset SECBOOT_ECCDSA_WITH_AES128_CBC_SHA256 actually reaches:
# AES-CBC through the cipher layer, SHA-256, and ECDSA-P256 verify (which
# drags in ecp, the bignum stack and ASN.1).  Everything else in the library
# is left out rather than left to --gc-sections, so the footprint is a
# decision rather than an accident.
#
# The last three are here because ST'S CONFIG ASKS FOR THEM, not because
# this scheme uses them: se_mbedtls_config.h enables MBEDTLS_CAMELLIA_C
# (which cipher_wrap.c then references unconditionally) and
# MBEDTLS_ECDSA_DETERMINISTIC (which pulls hmac_drbg into ecdsa.c, on the
# SIGNING path this bootloader never takes).  Keeping them keeps ST's
# configuration byte-identical; switching the features off would be a change
# to the product rather than to the build.  --gc-sections drops what is
# unreachable anyway.
MBEDTLS_SRC = \
  $(MBEDTLS)/library/aes.c \
  $(MBEDTLS)/library/cipher.c \
  $(MBEDTLS)/library/cipher_wrap.c \
  $(MBEDTLS)/library/block_cipher.c \
  $(MBEDTLS)/library/sha256.c \
  $(MBEDTLS)/library/ecdsa.c \
  $(MBEDTLS)/library/ecp.c \
  $(MBEDTLS)/library/ecp_curves.c \
  $(MBEDTLS)/library/ecp_curves_new.c \
  $(MBEDTLS)/library/bignum.c \
  $(MBEDTLS)/library/bignum_core.c \
  $(MBEDTLS)/library/bignum_mod.c \
  $(MBEDTLS)/library/bignum_mod_raw.c \
  $(MBEDTLS)/library/asn1parse.c \
  $(MBEDTLS)/library/asn1write.c \
  $(MBEDTLS)/library/constant_time.c \
  $(MBEDTLS)/library/platform.c \
  $(MBEDTLS)/library/platform_util.c \
  $(MBEDTLS)/library/md.c \
  $(MBEDTLS)/library/oid.c \
  $(MBEDTLS)/library/camellia.c \
  $(MBEDTLS)/library/hmac_drbg.c \
  $(MBEDTLS)/library/gcm.c

PORT_OBJ    = $(addprefix $(BUILD)/port/,$(notdir $(PORT_SRC:.c=.o)))
HAL_OBJ     = $(addprefix $(BUILD)/hal/,$(notdir $(HAL_SRC:.c=.o)))
BSP_OBJ     = $(addprefix $(BUILD)/bsp/,$(notdir $(BSP_SRC:.c=.o)))
STOCK_OBJ   = $(addprefix $(BUILD)/stock/,$(notdir $(STOCK_SRC:.c=.o)))
SE_OBJ      = $(addprefix $(BUILD)/se/,$(notdir $(SE_SRC:.c=.o)))
MBEDTLS_OBJ = $(addprefix $(BUILD)/mbedtls/,$(notdir $(MBEDTLS_SRC:.c=.o)))

# A basename collision between two lists would silently give one object two
# rules and let one source be dropped.  Catch it instead.
ALLBASE := $(notdir $(PORT_SRC) $(HAL_SRC) $(BSP_SRC) $(STOCK_SRC) $(SE_SRC) \
                    $(MBEDTLS_SRC))
DUPS := $(strip $(foreach b,$(sort $(ALLBASE)), \
          $(if $(word 2,$(filter $(b),$(ALLBASE))),$(b),)))
ifneq ($(DUPS),)
$(error source lists share basenames: $(DUPS) -- one of them is being ignored)
endif

# ------------------------------------------------------------------ rules --

# Stage one of ST's SBSFU .c files: CRLF -> LF, then apply any tracked patch
# whose filename mentions it.
#
# CRLF -> LF matters twice.  ST ships CRLF; this repository is LF throughout
# (.gitattributes, because the firmware is built under WSL).  And the
# patches are LF, so without the conversion no hunk context ever matches and
# `patch` reports a malformed patch rather than a line-ending mismatch.
#
# The fetched checkout is NEVER written to.  That is what keeps
# ../fw_samd21_sbsfu/fetch_sbsfu.sh idempotent and ./diff_vs_stock.sh
# meaningful.
#
# `patch` runs with -F0 (no fuzz) and without --forward, so if ST's file
# ever differs from what the diff expects the build STOPS rather than
# applying something approximate to a bootloader.
#
# It writes to `-o <file>.patched` and then moves, rather than patching in
# place.  In-place patching renames a temp over the original, and under
# Dropbox on Windows that rename intermittently fails with EPERM while the
# syncing client holds the file -- which patch reports as "no longer
# matches", a very misleading thing for a build to say.
#
# The patch files are prerequisites, not just inputs to the recipe.  Without
# that, editing a patch rebuilds NOTHING -- the staged .c is newer than the
# ST source, so make declares it up to date and the old instrumentation
# stays in the binary.
define STAGE_RULE
$(BUILD)/src/$(notdir $(1)): $(STOCK)/$(1) $$(wildcard patches/*$(basename $(notdir $(1)))*.patch) $$(FLAGS_STAMP) | $(BUILD)/src
	@tr -d '\r' < $$< > $$@
	@for p in patches/*.patch; do \
	   [ -e "$$$$p" ] || continue; \
	   case "$$$$(basename $$$$p .patch)" in \
	     [0-9][0-9][0-9][0-9]-$(basename $(notdir $(1)))-*) ;; \
	     *) continue ;; \
	   esac; \
	   case " $(SKIP_PATCHES) " in \
	     *" $$$$(basename $$$$p .patch | cut -c1-4) "*) \
	        echo "  skipping $$$$p (INSTR=$(INSTR))"; continue ;; \
	   esac; \
	   echo "  applying $$$$p"; \
	   patch -s -F0 -o $$@.patched $$@ < "$$$$p" \
	     || { echo "PATCH FAILED: $$$$p no longer matches ST." >&2; exit 1; }; \
	   mv -f $$@.patched $$@; \
	 done
endef
$(foreach s,$(STOCK_SRC),$(eval $(call STAGE_RULE,$(s))))

# The same, for ST's Secure Engine middleware.  A patch mechanism that
# covers some of the vendor sources and not others is one that works until
# the question you need to answer is in the wrong file.
define SE_STAGE_RULE
$(BUILD)/se_src/$(notdir $(1)): $(1) $$(wildcard patches/*$(basename $(notdir $(1)))*.patch) $$(FLAGS_STAMP) | $(BUILD)/se_src
	@tr -d '\r' < $$< > $$@
	@for p in patches/*.patch; do \
	   [ -e "$$$$p" ] || continue; \
	   case "$$$$(basename $$$$p .patch)" in \
	     [0-9][0-9][0-9][0-9]-$(basename $(notdir $(1)))-*) ;; \
	     *) continue ;; \
	   esac; \
	   case " $(SKIP_PATCHES) " in \
	     *" $$$$(basename $$$$p .patch | cut -c1-4) "*) \
	        echo "  skipping $$$$p (INSTR=$(INSTR))"; continue ;; \
	   esac; \
	   echo "  applying $$$$p"; \
	   patch -s -F0 -o $$@.patched $$@ < "$$$$p" \
	     || { echo "PATCH FAILED: $$$$p no longer matches ST." >&2; exit 1; }; \
	   mv -f $$@.patched $$@; \
	 done
endef
$(foreach s,$(SE_SRC),$(eval $(call SE_STAGE_RULE,$(s))))

$(BUILD)/stock/%.o: $(BUILD)/src/%.c $(STAGED_H) $(FLAGS_STAMP) | $(BUILD)/stock
	$(CROSS)gcc $(STOCK_CFLAGS) -c $< -o $@

define PORT_RULE
$(BUILD)/port/$(notdir $(1:.c=.o)): $(1) $$(STAGED_H) $$(FLAGS_STAMP) | $(BUILD)/port
	$$(CROSS)gcc $$(CFLAGS) -c $$< -o $$@
endef
$(foreach s,$(PORT_SRC),$(eval $(call PORT_RULE,$(s))))

# ST's HAL and BSP are compiled in place and get STOCK_CFLAGS: vendor code,
# vendor warnings.
define HAL_RULE
$(BUILD)/hal/$(notdir $(1:.c=.o)): $(1) $$(STAGED_H) $$(FLAGS_STAMP) | $(BUILD)/hal
	$$(CROSS)gcc $$(STOCK_CFLAGS) -c $$< -o $$@
endef
$(foreach s,$(HAL_SRC),$(eval $(call HAL_RULE,$(s))))

define BSP_RULE
$(BUILD)/bsp/$(notdir $(1:.c=.o)): $(1) $$(STAGED_H) $$(FLAGS_STAMP) | $(BUILD)/bsp
	$$(CROSS)gcc $$(STOCK_CFLAGS) -c $$< -o $$@
endef
$(foreach s,$(BSP_SRC),$(eval $(call BSP_RULE,$(s))))

define SE_RULE
$(BUILD)/se/$(notdir $(1:.c=.o)): $(BUILD)/se_src/$(notdir $(1)) $$(STAGED_H) $$(FLAGS_STAMP) | $(BUILD)/se
	$$(CROSS)gcc $$(STOCK_CFLAGS) -c $$< -o $$@
endef
$(foreach s,$(SE_SRC),$(eval $(call SE_RULE,$(s))))

define MBEDTLS_RULE
$(BUILD)/mbedtls/$(notdir $(1:.c=.o)): $(1) $$(STAGED_H) $$(FLAGS_STAMP) | $(BUILD)/mbedtls
	$$(CROSS)gcc $$(STOCK_CFLAGS) -c $$< -o $$@
endef
$(foreach s,$(MBEDTLS_SRC),$(eval $(call MBEDTLS_RULE,$(s))))

$(BUILD)/port $(BUILD)/hal $(BUILD)/bsp $(BUILD)/stock $(BUILD)/src \
$(BUILD)/se $(BUILD)/se_src $(BUILD)/mbedtls:
	mkdir -p $@

# The staged header tree.  A stamp file rather than a directory so that
# editing one of this port's headers restages the tree; the .d files then
# make every object depend on the staged copies, so a header edit rebuilds
# what it should.
$(BUILD)/inc/.stamp: stage_headers.sh $(shell find $(PORT) -name '*.h' 2>/dev/null)
	@mkdir -p $(BUILD)/inc
	@SBSFU_ROOT=$(SBSFU_ROOT) ./stage_headers.sh $(BUILD)/inc
	@touch $@

# FORCE, so the comparison runs on every invocation -- but the stamp is
# rewritten only when the flag text actually differs, so an unchanged
# rebuild recompiles nothing.
.PHONY: FORCE
FORCE:
$(FLAGS_STAMP): FORCE
	@mkdir -p $(BUILD)
	@echo '$(FLAGS_TEXT)' > $@.new
	@if cmp -s $@.new $@; then rm -f $@.new; \
	 else if [ -e $@ ]; then echo "  build flags changed -- recompiling"; fi; \
	      mv -f $@.new $@; fi

# ---------------------------------------------------------------- targets --

# ST'S OWN GCC LINKER SCRIPT, PLUS THREE SECTIONS.  ST ships a STM32CubeIDE
# project for this board, so the memory map the product uses -- where the SE
# regions sit, where the slots are, which address the call gate is linked at
# -- is ST's file and not a reconstruction.  That is the single biggest
# reason this port is closer to stock than the other two.
#
# What the port's copy adds is the placement of the three Secure Engine
# sections that in ST's build arrive as a prebuilt binary instead.  The
# script itself says what and why; the short version is that WITHOUT them
# the link succeeds and the image has no cipher in it.
LDSCRIPT = $(PORT)/2_Images_SBSFU/l475_sbsfu.ld
# The scripts the linker script INCLUDEs are prerequisites too.  They are
# reached through -L, so make cannot see them, and editing the slot map
# relinked nothing on the SAM D21 build until this line was added.
LDSCRIPT_DEPS = $(wildcard $(STOCK)/Linker_Common/STM32CubeIDE/*.ld)
STARTUP  = $(STOCK)/2_Images_SBSFU/STM32CubeIDE/Application/Startup/startup_stm32l475xx.s
# se_key.s is GENERATED, by ./gen_keys.sh, from ST's demo keys -- it is ST's
# own prebuild step reduced to this one crypto scheme.  It IS tracked, as it
# is on both sibling rigs: the keys are ST's published demo keys rather than
# secrets, and committing the file means a clone can link this firmware
# without running ST's tool.
KEYASM   = $(PORT)/2_Images_SECoreBin/Src/se_key.s
STARTOBJ = $(BUILD)/port/startup_stm32l475xx.o
KEYOBJ   = $(BUILD)/port/se_key.o
ALLOBJ   = $(PORT_OBJ) $(HAL_OBJ) $(BSP_OBJ) $(STARTOBJ) $(KEYOBJ) \
           $(STOCK_OBJ) $(SE_OBJ) $(MBEDTLS_OBJ)

$(STARTOBJ): $(STARTUP) | $(BUILD)/port
	$(CROSS)gcc $(CPU) -c -x assembler-with-cpp $< -o $@

$(KEYOBJ): $(KEYASM) | $(BUILD)/port
	$(CROSS)gcc $(CPU) -c -x assembler-with-cpp $< -o $@

$(KEYASM):
	@echo "No $(KEYASM) -- run ./gen_keys.sh first." >&2; exit 1

# -L on the linker-script directories so the INCLUDE of mapping_*.ld
# resolves.  --gc-sections is ON: the mbedTLS subset pulls in
# reachable-but-unused code, and dropping it is the difference between
# fitting the SE region and not.  KEEP() in ST's script guards the sections
# that must survive it -- the vectors, the call gate and the keys -- because
# those are referenced only by address, never by symbol.
# -L ORDER IS LOAD-BEARING.  ST's STM32L475VGTx_FLASH.ld reaches its map
# with `INCLUDE mapping_sbsfu.ld`, and ld searches -L in order, so this
# port's Linker_Common goes first and its two overridden maps win.  Putting
# ST's first links ST's 42 KB SB_ROM and fails with an overflow that names
# neither file.
#
# NO -nostartfiles, and that differs from the L152 port.  ST's startup for
# this board calls __libc_init_array, which newlib's lib_a-init.o resolves
# against _init from crti.o -- a file -nostartfiles excludes, so the link
# ends with `undefined reference to _init' and nothing says why.  ST's own
# CubeIDE project does not pass it either.  The vectors still come from ST's
# startup file, because ST's script sets ENTRY(Reset_Handler); crt0's _start
# is linked and never reached.
LDFLAGS = $(CPU) -T $(notdir $(LDSCRIPT)) -Wl,--defsym=TABLEPAD=$(TABLEPAD) \
          -L$(dir $(LDSCRIPT)) -L$(PORT)/Linker_Common \
          -L$(STOCK)/Linker_Common/STM32CubeIDE \
          --specs=nano.specs --specs=nosys.specs \
          -Wl,--gc-sections -Wl,-Map=$(BUILD)/sbsfu.map

.PHONY: all
all: $(BUILD)/sbsfu.bin

$(BUILD)/sbsfu.elf: $(ALLOBJ) $(LDSCRIPT) $(LDSCRIPT_DEPS)
	$(CROSS)gcc $(LDFLAGS) $(ALLOBJ) -o $@
	@echo
	$(CROSS)size $@

$(BUILD)/sbsfu.bin: $(BUILD)/sbsfu.elf
	$(CROSS)objcopy -O binary --gap-fill 0xFF $< $@
	@$(MAKE) --no-print-directory $(BUILD)/tables.txt

# THE TABLE ADDRESSES ARE A BUILD PRODUCT, so the build emits them.
#
# A trace count quoted without the table's address is under-specified: the
# same firmware at three link-time accidents needed 6 250, 12 500 and 25 000
# traces (CLAUDE.md).  The tables here are STATIC in mbedTLS's aes.c, so
# they do not appear in the link map at all and nothing but the symbol table
# knows where they are -- which is why this is generated rather than written
# down.
#
# ON THIS PART THE ALIGNMENT MATTERS AND NOT ONLY THE ADDRESS.  The data
# cache is 256 B over a 32-byte conflict period, and a 256 B table at
# `mod 32 == 0` spans 8 lines and fits it exactly while the same table at
# any other phase spans 9 and cannot (research/targets/stm32l475.md section
# 5f).  RSb is 256 B.  So `RSb % 32` is part of what a capture has to
# record, and the column is printed rather than left to be worked out.
#
# RT0 is the table the round-1 attack indexes -- AES-CBC DECRYPTION, so the
# first round's lookups go to the inverse T-table and not to a forward
# S-box.  RSb is the final inverse round.  FT0 and FSb are emitted too, so a
# reader can see they are present and unused.
#
# FSb APPEARS TWICE AND BOTH ARE REAL.  aes.c and camellia.c each define a
# static table of that name, and camellia.c is built because ST's
# se_mbedtls_config.h enables MBEDTLS_CAMELLIA_C.  The attack never touches
# either, but an unexplained duplicate in a file whose whole job is to pin
# addresses would be the first thing to doubt in a write-up, so: the lower
# address is aes.c's.
$(BUILD)/tables.txt: $(BUILD)/sbsfu.elf
	@echo "# variant $(VARIANT)" > $@
	@echo "# name addr size addr_mod_32" >> $@
	@$(CROSS)nm -S $< \
	  | awk '$$4=="RT0"||$$4=="RSb"||$$4=="FT0"||$$4=="FSb" \
	         {printf "%s 0x%s 0x%s %d\n", $$4, $$1, $$2, \
	                 strtonum("0x" $$1) % 32}' \
	  | sort >> $@
	@cat $@

.PHONY: check
check: $(PORT_OBJ) $(HAL_OBJ) $(BSP_OBJ) $(STOCK_OBJ) $(SE_OBJ) $(MBEDTLS_OBJ)
	@echo
	@echo "compiled $(words $(PORT_OBJ)) port + $(words $(HAL_OBJ)) HAL + $(words $(BSP_OBJ)) BSP + $(words $(STOCK_OBJ)) SBSFU + $(words $(SE_OBJ)) SecureEngine + $(words $(MBEDTLS_OBJ)) mbedTLS objects"
	@echo "variant $(VARIANT) slots=$(SLOTS) verbose=$(VERBOSE)"

# `chunkcheck` asserts that SFU_IMG_CHUNK_SIZE really is $(CHUNK) AS ST'S
# SOURCES SEE IT -- not as this Makefile intends it, and not as this port's
# copy of sfu_fwimg_internal.h declares it, but as resolved from the
# directory ST's .c files are actually compiled in.
.PHONY: chunkcheck
chunkcheck: $(STAGED_H) | $(BUILD)/src
	cp chunkprobe.c $(BUILD)/src/_chunkprobe.c
	$(CROSS)gcc $(CFLAGS) -DCHUNK_EXPECTED=$(CHUNK) -fsyntax-only \
	  $(BUILD)/src/_chunkprobe.c
	@rm -f $(BUILD)/src/_chunkprobe.c
	@echo "chunkcheck: SFU_IMG_CHUNK_SIZE == $(CHUNK) as ST's sources resolve it"

# The checkout has to be present AND complete.  A sparse checkout that
# aborted part way leaves directories that exist and are empty, which a
# plain -d test calls success -- and the HAL landing while the BSP did not
# is exactly what one interrupted fetch did here.
# `instrcheck` asserts what INSTR actually did, BOTH WAYS.  A check that can
# only fail in one direction is how a stock build quietly keeps its
# instrumentation: at INSTR=0 it requires the two staged sources to be
# byte-identical to ST's and the image to carry no SFU_INSTR symbol, and at
# INSTR=1 it requires the opposite of both.  The pair is the point.
#
# It compares the STAGED sources rather than the patches, because the staged
# copy is what the compiler read.
INSTR_FILES = 2_Images_SBSFU/SBSFU/Target/sfu_low_level_flash_ext.c \
              2_Images_SBSFU/SBSFU/App/sfu_fwimg_no_swap.c

.PHONY: instrcheck
instrcheck: $(BUILD)/sbsfu.elf
	@fail=0; \
	 for f in $(INSTR_FILES); do \
	   b=$$(basename $$f); \
	   if diff -q --strip-trailing-cr "$(STOCK)/$$f" "$(BUILD)/src/$$b" >/dev/null 2>&1; then \
	     same=yes; else same=no; fi; \
	   echo "  $$b: identical to ST's = $$same"; \
	   if [ "$(INSTR)" = "0" ] && [ "$$same" = "no" ]; then \
	     echo "    FAIL: INSTR=0 but this file is still patched" >&2; fail=1; fi; \
	   if [ "$(INSTR)" = "1" ] && [ "$$same" = "yes" ]; then \
	     echo "    FAIL: INSTR=1 but this file was never patched" >&2; fail=1; fi; \
	 done; \
	 n=$$($(CROSS)nm $(BUILD)/sbsfu.elf | grep -c SFU_INSTR || true); \
	 echo "  SFU_INSTR symbols in the image: $$n"; \
	 if [ "$(INSTR)" = "0" ] && [ "$$n" != "0" ]; then \
	   echo "    FAIL: a stock image carries the instrument" >&2; fail=1; fi; \
	 if [ "$(INSTR)" = "1" ] && [ "$$n" = "0" ]; then \
	   echo "    FAIL: an instrumented image carries no instrument" >&2; fail=1; fi; \
	 test $$fail -eq 0 || exit 1; \
	 echo "instrcheck: INSTR=$(INSTR) is consistent, variant $(VARIANT)"

.PHONY: stockcheck
stockcheck:
	@test -d "$(STOCK)" || { \
	  echo "No SBSFU checkout at $(SBSFU_ROOT)."; \
	  echo "Run ../fw_samd21_sbsfu/fetch_sbsfu.sh, or pass SBSFU_ROOT=<path>."; \
	  exit 1; }
	@for f in "$(HAL)/Src/stm32l4xx_hal_qspi.c" \
	          "$(CMSIS_D)/Include/stm32l475xx.h" \
	          "$(CMSIS_C)/core_cm4.h" \
	          "$(BSP)/stm32l475e_iot01_qspi.c" \
	          "$(BSPCOMP)/mx25r6435f/mx25r6435f.h" \
	          "$(LDSCRIPT)" "$(STARTUP)"; do \
	  test -f "$$f" || { \
	    echo "Missing from the checkout: $$f"; \
	    echo "The sparse-checkout list in ../fw_samd21_sbsfu/fetch_sbsfu.sh"; \
	    echo "covers it, so re-run that script (a sparse checkout that was"; \
	    echo "interrupted leaves the directory present and empty)."; \
	    exit 1; }; \
	 done
	@echo "SBSFU tree: $(STOCK)"
	@echo "HAL/BSP/CMSIS/linker: from the same pinned tree"

-include $(shell find $(BUILD) -name '*.d' 2>/dev/null)

.PHONY: clean
clean:
	rm -rf $(BUILD)
