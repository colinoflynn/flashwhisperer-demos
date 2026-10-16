# Command-line build of the X-CUBE-SUBG2 Contiki-NG applications
# (IEEE 802.15.4 / 6LoWPAN over the S2-LP radio) with arm-none-eabi-gcc.
#
#   make BOARD=NUCLEO-F401RE APP=S2915A1_UDP_Server PKG=../../deps/x-cube-subg2
#
# build_rig.sh copies this file and cubeproj.py into the build directory and
# passes PKG itself, which is the way to run it: the recipe below resolves
# every source path relative to the directory make runs in.
#   make list                # board/app combinations in the package
#   make pair                # coordinator (RPL root) + end node
#   make V=1 ...             # show full command lines
#
# The file list, include paths, defines and MCU settings are extracted from
# ST's own STM32CubeIDE project files by cubeproj.py, so switching board or
# shield needs no changes here.

BOARD  ?= NUCLEO-F401RE
APP    ?= S2915A1_UDP_Server
CONFIG ?= release

PKG      ?= ../../deps/x-cube-subg2
# Applications/Contiki-NG holds the 6LoWPAN stack apps; Examples holds the bare
# S2-LP ones (P2P, CLI, FIFO) with no Contiki in them.  Look in both so APP=
# takes any name `make list` prints.
APPDIR   := $(firstword $(wildcard \
              $(PKG)/Projects/$(BOARD)/Applications/Contiki-NG/$(APP) \
              $(PKG)/Projects/$(BOARD)/Examples/$(APP)))
CUBEDIR  := $(APPDIR)/STM32CubeIDE
OUT      := out/$(BOARD)/$(APP)-$(CONFIG)
TARGET   := $(OUT)/$(APP)

V ?= 0
ifeq ($(V),0)
  Q := @
  say = @printf '  %-4s %s\n' "$(1)" "$(2)"
else
  Q :=
  say =
endif

CROSS   ?= arm-none-eabi-
CC      := $(CROSS)gcc
OBJCOPY := $(CROSS)objcopy
SIZE    := $(CROSS)size

# ---------------------------------------------------------------- recipe ----
# Auto-remade and re-read by make before the rest is evaluated.
RECIPE := $(OUT)/project.mk

ifeq ($(filter list help clean distclean,$(MAKECMDGOALS)),)
include $(RECIPE)
endif

# NOTE: this only re-runs when the CubeIDE project files or cubeproj.py change.
# cubeproj.py also scans STM32CubeIDE/Application/{Startup,User} as DIRECTORIES,
# so DROPPING A NEW .c INTO Application/User DOES NOT REGENERATE THIS and the
# new file is silently left out of SOURCES -- the symptom is an undefined
# reference at link time.  Delete $(OUT)/project.mk (or `make clean`) after
# adding a source file.  Likewise EXTRA_DEFINES changes are NOT tracked, so a
# rebuild with different -D flags will reuse stale objects.
$(RECIPE): $(CUBEDIR)/.project $(CUBEDIR)/.cproject cubeproj.py
	@mkdir -p $(dir $@)
	$(call say,GEN,$@)
	$(Q)python3 cubeproj.py $(CUBEDIR) --rel . > $@

# ----------------------------------------------------------------- flags ----
ifeq ($(FPU),none)
  FPUFLAGS := -mfloat-abi=soft
else
  FPUFLAGS := -mfpu=$(FPU) -mfloat-abi=$(FLOAT_ABI)
endif

ARCHFLAGS := -mcpu=$(CORE) -mthumb $(FPUFLAGS)

ifeq ($(CONFIG),debug)
  OPTFLAGS := -O0 -g3
  DEFINES  += DEBUG
else
  OPTFLAGS := -Os -g
endif

# Extra -D's for experiments, e.g.
#   make EXTRA_DEFINES="CSMA_CONF_LLSEC_SECURITY_LEVEL=5"
DEFINES += $(EXTRA_DEFINES)

CFLAGS := $(ARCHFLAGS) $(OPTFLAGS) -std=gnu11 -Wall \
          -ffunction-sections -fdata-sections -fno-common \
          $(addprefix -D,$(DEFINES)) $(addprefix -I,$(INCLUDES)) \
          -MMD -MP

ASFLAGS := $(ARCHFLAGS) $(OPTFLAGS) -x assembler-with-cpp \
           $(addprefix -D,$(DEFINES))

LDFLAGS := $(ARCHFLAGS) -T$(LDSCRIPT) -Wl,--gc-sections \
           -Wl,-Map=$(TARGET).map,--cref -static \
           -Wl,--start-group -lc -lm -Wl,--end-group

# --------------------------------------------------------------- objects ----
# Object paths mirror the source tree (minus the leading ../) so that
# same-named files from different directories cannot collide.
OBJS := $(addprefix $(OUT)/obj/,$(patsubst ../%,%,$(addsuffix .o,$(SOURCES))))
DEPS := $(OBJS:.o=.d)

.PHONY: all pair list help clean distclean size flash
.DEFAULT_GOAL := all

all: $(TARGET).elf $(TARGET).bin $(TARGET).hex size

$(OUT)/obj/%.c.o: ../%.c
	@mkdir -p $(dir $@)
	$(call say,CC,$<)
	$(Q)$(CC) $(CFLAGS) -c $< -o $@

$(OUT)/obj/%.s.o: ../%.s
	@mkdir -p $(dir $@)
	$(call say,AS,$<)
	$(Q)$(CC) $(ASFLAGS) -c $< -o $@

$(TARGET).elf: $(OBJS) $(LDSCRIPT)
	@mkdir -p $(dir $@)
	$(call say,LD,$@)
	$(Q)$(CC) $(OBJS) $(LDFLAGS) -o $@

%.bin: %.elf
	$(call say,BIN,$@)
	$(Q)$(OBJCOPY) -O binary $< $@

%.hex: %.elf
	$(call say,HEX,$@)
	$(Q)$(OBJCOPY) -O ihex $< $@

size: $(TARGET).elf
	@$(SIZE) $<

# Coordinator (RPL root) + end node: the two halves of a minimal network.
pair:
	$(MAKE) APP=$(subst _UDP_Client,_UDP_Server,$(APP))
	$(MAKE) APP=$(subst _UDP_Server,_UDP_Client,$(APP))

flash: $(TARGET).bin
	st-flash --reset write $< 0x8000000

list:
	@for b in $(PKG)/Projects/*/; do \
	  echo "$$(basename $$b):"; \
	  for d in $$b/Applications/Contiki-NG $$b/Examples; do \
	    [ -d $$d ] || continue; \
	    for a in $$d/*/; do \
	      [ -d $$a/STM32CubeIDE ] || continue; \
	      echo "    $$(basename $$a)"; \
	    done; \
	  done; \
	done

help:
	@echo "make [BOARD=...] [APP=...] [CONFIG=release|debug] [V=1]"
	@echo "make list   - board/app combinations available in the package"
	@echo "make pair   - build UDP_Server (coordinator) and UDP_Client"
	@echo "make flash  - st-flash the current BOARD/APP"

clean:
	rm -rf $(OUT)

distclean:
	rm -rf out

-include $(DEPS)
