# X-CUBE-SBSFU v2.7.0 for the NUCLEO-L152RE.
#
# Built in WSL -- arm-none-eabi-gcc is WSL-only on this host:
#
#   ./deps/fetch.sh sbsfu                  # once: ST's bootloader package
#   ./deps/fetch.sh stm32cube-l1                 # once: ST's STM32L1 HAL
#   wsl -- bash -lc 'cd <this dir> && make check'
#
# Targets:
#   check       compile every translation unit, link nothing
#   all         link the bootloader
#   chunkcheck  assert SFU_IMG_CHUNK_SIZE as ST'S SOURCES RESOLVE IT
#   stockcheck  confirm both pinned trees are present
#
# This is the SAM D21 port's Makefile with the pieces that differ for an ST
# target.  The structure, and every comment explaining why a rule is shaped
# the way it is, came from rigs/fw_samd21_sbsfu/Makefile and the bugs it
# records were paid for there.
#
# WHY ST'S SOURCES ARE NOT COPIED INTO THIS DIRECTORY
# ----------------------------------------------------
# ST's own tree gives every board a full copy of App/ and Target/ --
# nineteen near-identical copies.  Following that here would bury this
# port's actual deviations in thousands of lines of duplicated ST code, and
# "unmodified" would be a claim a reader has to take on trust.  Instead
# NUCLEO_L152RE/ holds only the files this port changes or owns; everything
# else comes from the pinned checkouts.  A file that is not in
# NUCLEO_L152RE/ cannot have been edited, because the build never reads a
# local copy of it.

# The staging rules below are generated with $(eval), and the first of them
# is defined long before `all:` -- so without this, a bare `make` builds one
# staged .c file and stops, reporting "is up to date" as though it had done
# the whole build.
.DEFAULT_GOAL := all

# The vendor trees are the pinned checkouts under deps/, fetched with
# `./deps/fetch.sh sbsfu stm32cube-l1`. There is no fetch script in this
# directory on purpose: deps/fetch.sh already pulls X-CUBE-SBSFU at the pin
# deps/PINS names, with the sparse list that serves every port here, and a
# second fetch path would be a second pin to keep in step.
HERE_MK := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
REPO_ROOT := $(abspath $(HERE_MK)/../../../..)
SBSFU_ROOT ?= $(REPO_ROOT)/deps/sbsfu
CUBEL1_ROOT ?= $(REPO_ROOT)/deps/stm32cube-l1


STOCK   = $(SBSFU_ROOT)/Projects/B-L475E-IOT01A/Applications/2_Images_ExtFlash
SE_MW   = $(SBSFU_ROOT)/Middlewares/ST/STM32_Secure_Engine
MBEDTLS = $(SBSFU_ROOT)/Middlewares/Third_Party/mbedtls

HAL     = $(CUBEL1_ROOT)/Drivers/STM32L1xx_HAL_Driver
CMSIS_D = $(CUBEL1_ROOT)/Drivers/CMSIS/Device/ST/STM32L1xx
CMSIS_C = $(CUBEL1_ROOT)/Drivers/CMSIS/Include

CROSS  = arm-none-eabi-
CPU    = -mcpu=cortex-m3 -mthumb -mfloat-abi=soft
PORT   = NUCLEO_L152RE
BUILD ?= build

# Defined HERE, not next to its rule.  The $(eval)-generated compile rules
# below expand their prerequisite lists at eval time, so a variable defined
# further down the file expands to nothing there and the staged header tree
# does not get built first.
STAGED_H = $(BUILD)/inc/.stamp

# Every compile depends on this stamp, and the stamp is rewritten whenever
# the flag set changes.  Without it, `make CHUNK=64` after `make CHUNK=512`
# reports "Nothing to be done" and leaves the previous chunk size in the
# binary -- and CHUNK is the single most load-bearing knob here, because it
# is what sets how many chip-select envelopes a verify pass produces.  The
# comparison is on CONTENT, so a rebuild with unchanged flags does not touch
# the stamp and nothing recompiles.
FLAGS_STAMP = $(BUILD)/.flags

# --- the flash read-path configuration the image is built for ---------------
# The L152 has no cache and a one-bit LATENCY field, so the only knob is the
# wait state itself -- and at the 32 MHz this port runs, range 1, one wait
# state is the ONLY configuration in spec.  That is the whole reason this
# part is interesting: it is the floor case.  research/targets/stm32l152.md
# has the measurement.  ACC64 and PRFTEN are the two that can be varied, and
# RM0038 3.9.1 makes both conditional on ACC64, so they move together.
PREFETCH ?= on
ifeq ($(PREFETCH),on)
MITDEF =
else ifeq ($(PREFETCH),off)
MITDEF = -DSBSFU_FLASH_NO_PREFETCH=1
else
$(error PREFETCH must be on or off)
endif

# --- the chunk size, which is the attack's main axis ------------------------
# ST ships 512.  ST's own comment on SFU_IMG_CHUNK_SIZE requires a multiple
# of 16 because the image is encrypted in 128-bit blocks.  64 is what the
# SAM D21 campaign settled on; whether this part wants the same is a
# measurement this port has not taken yet, so the default stays at ST's
# value until it has.
CHUNK ?= 512
ifneq ($(shell expr $(CHUNK) % 16),0)
$(error CHUNK must be a multiple of 16, got $(CHUNK))
endif

# DIRECT_INSTALL=1 makes main() call SFU_IMG_TriggerImageInstallation
# straight after the pre-flight, bypassing the state machine.  It is how the
# decrypt loop -- the oracle -- is exercised while the surrounding boot flow
# is still being brought up.
# SE_PROBE=1 additionally runs one iteration of ST's decrypt loop from
# main(), before the install, with the same ST calls and the same chunk
# size.  It is the control for the install: the two differ only in what ran
# before them, so a probe that passes while the install fails localises the
# fault to the install's prologue rather than to the loop body.
DIRECT_INSTALL ?= 0
SE_PROBE       ?= 0
INSTDEF =
ifeq ($(DIRECT_INSTALL),1)
INSTDEF += -DPORT_DIRECT_INSTALL
endif
ifeq ($(SE_PROBE),1)
INSTDEF += -DPORT_SE_PROBE
endif
# RAMTABLES=1 builds the RAM twin: mbedTLS generates its AES tables into
# .bss at run time instead of linking them into flash.  Nothing else
# changes, so a capture that still shows the channel here is not measuring
# the flash read path.  See se_mbedtls_config.h.  It is the control
# research/mechanism/MEASURING_CHANNELS.md requires, not an option.
RAMTABLES      ?= 0
ifeq ($(RAMTABLES),1)
INSTDEF += -DPORT_RAM_TABLES
endif
CRYPTO_TRACE   ?= 0
ifeq ($(CRYPTO_TRACE),1)
INSTDEF += -DPORT_SE_CRYPTO_TRACE
endif
# GATE_TRACE=1 turns on patches/0002, which reports the caller's LR and the
# status pointer at each of SE_CallGate's guards.  Those guards call
# NVIC_SystemReset rather than returning an error -- ST's comment says that
# is mandatory, to stop an attacker reaching into the enclave by editing the
# call stack -- so a guard that fires looks exactly like a watchdog and says
# nothing.  This is how it was found that the first SE call on this port was
# recursing: four lines per SE call, which is far too much for anything but
# bring-up.  Never on for a capture.
GATE_TRACE     ?= 0
ifeq ($(GATE_TRACE),1)
INSTDEF += -DPORT_GATE_TRACE
endif
# ORACLE=1 makes the direct install stop and say so before it starts, so
# the bus-side timer can be armed in the gap between the YMODEM upload and
# the verify pass, and makes it print the driver's own envelope counts
# afterwards for the cross-check.  It requires DIRECT_INSTALL=1.
ORACLE         ?= 0
ifeq ($(ORACLE),1)
INSTDEF += -DPORT_ORACLE
# A capture build does not print inside the loop it is timing.  Two of ST's
# verbose traces sit in the decrypt loop and cost milliseconds of polled
# UART each, against a signal a microsecond wide.  ORACLE=1 therefore turns
# verbose off unless VERBOSE=1 is asked for explicitly, which is for
# debugging the pass, not measuring it.
VERBOSE ?= 0
ifneq ($(DIRECT_INSTALL),1)
$(error ORACLE=1 needs DIRECT_INSTALL=1 -- the handshake sits inside it)
endif
endif

# Verbose defaults ON for an ordinary build (it is how the port's failures
# name themselves) and is forced off by ORACLE=1 above.
VERBOSE ?= 1
ifneq ($(VERBOSE),1)
INSTDEF += -DPORT_NO_VERBOSE
endif

# ONE header tree, built by stage_headers.sh, plus the directories nothing
# is overridden in.  See that script for why the obvious spelling (ST's
# directories and this port's both on -I, ours first) does NOT work.
INCS = \
  -I$(BUILD)/inc \
  -I$(PORT)/BSP \
  -I$(SE_MW)/Core \
  -I$(SE_MW)/Key \
  -I$(SE_MW)/Interface \
  -I$(MBEDTLS)/include \
  -I$(HAL)/Inc \
  -I$(CMSIS_D)/Include \
  -I$(CMSIS_C)

OPT   ?= -O2
# MBEDTLS_CONFIG_FILE is set for EVERY translation unit, not just mbedTLS's
# own.  mbedTLS's headers are configured by that macro, so a unit that
# includes mbedtls/aes.h without it gets the library's DEFAULT config and a
# different idea of structure layouts and enabled features than the compiled
# library has.  That mismatch links cleanly and corrupts memory at run time,
# which is the worst way for a bootloader to be wrong.
# -MMD -MP emit a .d per object; the -include near the bottom picks them up.
# WITHOUT THIS a header edit rebuilds nothing, and the link runs against
# objects compiled from a version of the header that no longer exists.
CFLAGS = $(CPU) $(OPT) -g -MMD -MP -ffreestanding -fno-common -Wall -Wextra \
         -DSTM32L152xE -DUSE_HAL_DRIVER \
         -DSFU_IMG_CHUNK_SIZE_OVERRIDE=$(CHUNK) \
         -DMBEDTLS_CONFIG_FILE='"se_mbedtls_config.h"' \
         $(MITDEF) $(INSTDEF) $(INCS)

# ST's code compiles with its own format warnings silenced.  They are real
# but they are ST's: uint32_t is `long unsigned int` for this toolchain and
# `unsigned int` for the one ST builds with, so every "%d" on a uint32_t in
# their trace strings fires here and nowhere for them.  Silenced for ST's
# files ONLY -- this port's own sources keep -Wall -Wextra with nothing
# suppressed -- so a real warning in our code stays visible instead of being
# buried in a hundred of theirs.
STOCK_CFLAGS = $(CFLAGS) -Wno-format -Wno-unused-parameter

# Recorded verbatim, not summarised: a stamp that lists only the knobs
# someone remembered to add is a stamp that silently stops covering the
# next one.
FLAGS_TEXT := $(CFLAGS) | $(STOCK_CFLAGS) | $(LDFLAGS)

# ---------------------------------------------------------------- sources --

# This port's own code: the files ST expects a board port to write, plus the
# BSP.  There is no HAL here -- that is the whole point of choosing an ST
# part for the second board.
PORT_SRC = \
  $(PORT)/2_Images_SBSFU/Core/Src/main.c \
  $(PORT)/2_Images_SBSFU/Core/Src/stm32l1xx_it.c \
  $(PORT)/2_Images_SBSFU/Core/Src/syscalls.c \
  $(PORT)/BSP/l152_nucleo_spif.c \
  $(PORT)/2_Images_SBSFU/SBSFU/Target/sfu_low_level.c \
  $(PORT)/2_Images_SBSFU/SBSFU/Target/sfu_low_level_flash_int.c \
  $(PORT)/2_Images_SBSFU/SBSFU/Target/sfu_low_level_flash_ext.c \
  $(PORT)/2_Images_SBSFU/SBSFU/Target/sfu_low_level_security.c \
  $(PORT)/2_Images_SECoreBin/Src/se_low_level.c

# ST's STM32L1xx HAL, compiled in place and unmodified.  Only the modules
# this firmware calls; ST's stm32l1xx_hal_conf.h enables every module in the
# package, which decides which HEADERS are visible rather than which objects
# are linked, so the subset here is a build-time choice and not a deviation
# from ST's configuration.
HAL_SRC = \
  $(HAL)/Src/stm32l1xx_hal.c \
  $(HAL)/Src/stm32l1xx_hal_cortex.c \
  $(HAL)/Src/stm32l1xx_hal_rcc.c \
  $(HAL)/Src/stm32l1xx_hal_rcc_ex.c \
  $(HAL)/Src/stm32l1xx_hal_gpio.c \
  $(HAL)/Src/stm32l1xx_hal_pwr.c \
  $(HAL)/Src/stm32l1xx_hal_pwr_ex.c \
  $(HAL)/Src/stm32l1xx_hal_spi.c \
  $(HAL)/Src/stm32l1xx_hal_uart.c \
  $(HAL)/Src/stm32l1xx_hal_crc.c \
  $(HAL)/Src/stm32l1xx_hal_flash.c \
  $(HAL)/Src/stm32l1xx_hal_flash_ex.c \
  $(HAL)/Src/stm32l1xx_hal_flash_ramfunc.c \
  $(HAL)/Src/stm32l1xx_hal_dma.c \
  $(HAL)/Src/stm32l1xx_hal_iwdg.c \
  $(HAL)/Src/stm32l1xx_hal_rtc.c \
  $(HAL)/Src/stm32l1xx_hal_rtc_ex.c \
  $(CMSIS_D)/Source/Templates/system_stm32l1xx.c

# ST's SBSFU sources, paths relative to $(STOCK).  This list IS the realism
# claim: every one is the product's own code, byte for byte, bar the tracked
# patches in patches/.  sfu_fwimg_no_swap.c is the one the campaign targets
# -- the read / decrypt / hash loop -- and it needs no port at all.
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
STOCK_SRC = \
  2_Images_SBSFU/SBSFU/Target/sfu_low_level_flash.c \
  2_Images_SBSFU/SBSFU/App/sfu_boot.c \
  2_Images_SBSFU/SBSFU/App/sfu_fwimg_common.c \
  2_Images_SBSFU/SBSFU/App/sfu_fwimg_no_swap.c \
  2_Images_SBSFU/SBSFU/App/sfu_loader.c \
  2_Images_SBSFU/SBSFU/App/sfu_com_loader.c \
  2_Images_SBSFU/SBSFU/App/sfu_com_trace.c \
  2_Images_SBSFU/SBSFU/App/sfu_error.c \
  2_Images_SBSFU/SBSFU/App/sfu_new_image.c \
  2_Images_SECoreBin/Src/se_crypto_bootloader.c

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
#   se_utils.c          defines HAL_GetTick and HAL_Delay for the Secure
#                       Engine, because behind ST's firewall the SE cannot
#                       reach the application's SysTick.  THIS PORT HAS NO
#                       FIREWALL: one address space, one SysTick, and ST's
#                       own HAL already defines both symbols.  Building it
#                       would be a duplicate definition.
SE_SRC = \
  $(SE_MW)/Core/se_callgate.c \
  $(SE_MW)/Core/se_exception.c \
  $(SE_MW)/Core/se_fwimg.c \
  $(SE_MW)/Core/se_startup.c \
  $(SE_MW)/Core/se_user_application.c \
  $(SE_MW)/Core/se_interface_bootloader.c \
  $(SE_MW)/Core/se_interface_common.c

# The mbedTLS subset SECBOOT_ECCDSA_WITH_AES128_CBC_SHA256 actually reaches:
# AES-CBC through the cipher layer, SHA-256, and ECDSA-P256 verify (which
# drags in ecp, the bignum stack and ASN.1).  Everything else in the library
# is left out rather than left to --gc-sections, so the footprint is a
# decision rather than an accident.
#
# The last two are here because ST'S CONFIG ASKS FOR THEM, not because this
# scheme uses them.  se_mbedtls_config.h enables MBEDTLS_CAMELLIA_C (which
# cipher_wrap.c then references unconditionally) and
# MBEDTLS_ECDSA_DETERMINISTIC (which pulls hmac_drbg into ecdsa.c, on the
# SIGNING path this bootloader never takes).  Adding the two files keeps
# ST's configuration byte-identical; switching the features off would have
# been smaller but would be a change to the product rather than to the
# build.  --gc-sections drops what is unreachable anyway.
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
STOCK_OBJ   = $(addprefix $(BUILD)/stock/,$(notdir $(STOCK_SRC:.c=.o)))
SE_OBJ      = $(addprefix $(BUILD)/se/,$(notdir $(SE_SRC:.c=.o)))
MBEDTLS_OBJ = $(addprefix $(BUILD)/mbedtls/,$(notdir $(MBEDTLS_SRC:.c=.o)))

# A basename collision between two lists would silently give one object two
# rules and let one source be dropped.  Catch it instead.
ALLBASE := $(notdir $(PORT_SRC) $(HAL_SRC) $(STOCK_SRC) $(SE_SRC) $(MBEDTLS_SRC))
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
# The fetched checkouts are NEVER written to.  That is what keeps
# ./fetch_*.sh idempotent and ./diff_vs_stock.sh meaningful.
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
$(BUILD)/src/$(notdir $(1)): $(STOCK)/$(1) $$(wildcard patches/*$(basename $(notdir $(1)))*.patch) | $(BUILD)/src
	@tr -d '\r' < $$< > $$@
	@for p in patches/*.patch; do \
	   [ -e "$$$$p" ] || continue; \
	   case "$$$$(basename $$$$p .patch)" in \
	     [0-9][0-9][0-9][0-9]-$(basename $(notdir $(1)))-*) ;; \
	     *) continue ;; \
	   esac; \
	   echo "  applying $$$$p"; \
	   patch -s -F0 -o $$@.patched $$@ < "$$$$p" \
	     || { echo "PATCH FAILED: $$$$p no longer matches ST." >&2; exit 1; }; \
	   mv -f $$@.patched $$@; \
	 done
endef
$(foreach s,$(STOCK_SRC),$(eval $(call STAGE_RULE,$(s))))

# The same, for ST's Secure Engine middleware.  These were compiled in place
# in the SAM D21 build until a diagnostic needed to go into se_callgate.c
# and could not: the patch mechanism only reached files that were staged.  A
# patch mechanism that covers some of the vendor sources and not others is
# one that works until the question you need to answer is in the wrong file.
define SE_STAGE_RULE
$(BUILD)/se_src/$(notdir $(1)): $(1) $$(wildcard patches/*$(basename $(notdir $(1)))*.patch) | $(BUILD)/se_src
	@tr -d '\r' < $$< > $$@
	@for p in patches/*.patch; do \
	   [ -e "$$$$p" ] || continue; \
	   case "$$$$(basename $$$$p .patch)" in \
	     [0-9][0-9][0-9][0-9]-$(basename $(notdir $(1)))-*) ;; \
	     *) continue ;; \
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

# ST's HAL is compiled in place and gets STOCK_CFLAGS: it is vendor code and
# its warnings are vendor warnings.  stm32l1xx_hal_flash.c has an unused
# parameter that fires under -Wextra and is ST's to fix, not this port's.
define HAL_RULE
$(BUILD)/hal/$(notdir $(1:.c=.o)): $(1) $$(STAGED_H) $$(FLAGS_STAMP) | $(BUILD)/hal
	$$(CROSS)gcc $$(STOCK_CFLAGS) -c $$< -o $$@
endef
$(foreach s,$(HAL_SRC),$(eval $(call HAL_RULE,$(s))))

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

$(BUILD)/port $(BUILD)/hal $(BUILD)/stock $(BUILD)/src $(BUILD)/se $(BUILD)/se_src $(BUILD)/mbedtls:
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

LDSCRIPT = $(PORT)/2_Images_SBSFU/l152_sbsfu.ld
# The scripts l152_sbsfu.ld INCLUDEs are prerequisites too.  They are
# reached through -L, so make cannot see them, and editing the slot map
# relinked nothing on the SAM D21 build until this line was added.
LDSCRIPT_DEPS = $(wildcard $(PORT)/Linker_Common/*.ld)
STARTUP  = $(CMSIS_D)/Source/Templates/gcc/startup_stm32l152xe.s
KEYASM   = $(PORT)/2_Images_SECoreBin/Src/se_key.s
STARTOBJ = $(BUILD)/port/startup_stm32l152xe.o
KEYOBJ   = $(BUILD)/port/se_key.o
ALLOBJ   = $(PORT_OBJ) $(HAL_OBJ) $(STARTOBJ) $(KEYOBJ) $(STOCK_OBJ) \
           $(SE_OBJ) $(MBEDTLS_OBJ)

$(STARTOBJ): $(STARTUP) | $(BUILD)/port
	$(CROSS)gcc $(CPU) -c -x assembler-with-cpp $< -o $@

$(KEYOBJ): $(KEYASM) | $(BUILD)/port
	$(CROSS)gcc $(CPU) -c -x assembler-with-cpp $< -o $@

# -L on the linker-script directory so its INCLUDE of mapping_*.ld resolves.
# --gc-sections is ON: the mbedTLS subset pulls in reachable-but-unused code
# (oid.c alone is 4.5 KB of tables this scheme never reads), and dropping it
# is the difference between fitting the SE region and not.  KEEP() guards
# the sections that must survive it -- the vectors, the call gate and the
# keys -- because those are referenced only by address, never by symbol, and
# would otherwise be collected as unreachable.
LDFLAGS = $(CPU) -T $(notdir $(LDSCRIPT)) \
          -L$(dir $(LDSCRIPT)) -L$(PORT)/Linker_Common \
          -nostartfiles --specs=nano.specs --specs=nosys.specs \
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
# RT0 is the one that matters for this target: AES-CBC DECRYPTION, so the
# first round's lookups go to the inverse T-table, not to a forward S-box.
# RSb is the final decryption round.  FT0 and FSb are emitted too, so a
# reader can see they are present and unused.
#
# FSb APPEARS TWICE AND BOTH ARE REAL.  aes.c and camellia.c each define a
# static table of that name, and camellia.c is built because ST's
# se_mbedtls_config.h enables MBEDTLS_CAMELLIA_C (see the MBEDTLS_SRC note
# above -- keeping it is what makes this ST's configuration rather than a
# trimmed one).  The attack never touches either, but an unexplained
# duplicate in a file whose whole job is to pin addresses would be the
# first thing to doubt in a write-up, so: the lower address is aes.c's.
$(BUILD)/tables.txt: $(BUILD)/sbsfu.elf
	@$(CROSS)nm -S $< | awk '$$4=="RT0"||$$4=="RSb"||$$4=="FT0"||$$4=="FSb" {print $$4, "0x" $$1, "0x" $$2}' | sort > $@
	@cat $@

.PHONY: check
check: $(PORT_OBJ) $(HAL_OBJ) $(STOCK_OBJ) $(SE_OBJ) $(MBEDTLS_OBJ)
	@echo
	@echo "compiled $(words $(PORT_OBJ)) port + $(words $(HAL_OBJ)) HAL + $(words $(STOCK_OBJ)) SBSFU + $(words $(SE_OBJ)) SecureEngine + $(words $(MBEDTLS_OBJ)) mbedTLS objects"
	@echo "chunk=$(CHUNK) prefetch=$(PREFETCH) opt=$(OPT)"

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

.PHONY: stockcheck
stockcheck:
	@test -d "$(STOCK)" || { \
	  echo "No SBSFU checkout at $(SBSFU_ROOT)."; \
	  echo "Run ./deps/fetch.sh sbsfu, or pass SBSFU_ROOT=<path>."; exit 1; }
	@test -d "$(HAL)/Src" || { \
	  echo "No STM32CubeL1 checkout at $(CUBEL1_ROOT)."; \
	  echo "Run ./deps/fetch.sh stm32cube-l1, or pass CUBEL1_ROOT=<path>."; exit 1; }
	@echo "SBSFU tree:  $(STOCK)"
	@echo "CubeL1 tree: $(CUBEL1_ROOT)"

-include $(shell find $(BUILD) -name '*.d' 2>/dev/null)

.PHONY: clean
clean:
	rm -rf $(BUILD)
