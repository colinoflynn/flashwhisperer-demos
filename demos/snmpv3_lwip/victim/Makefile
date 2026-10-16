# SNMPv3 flash-timing victim -- NUCLEO-F429ZI. Build in WSL (arm-none-eabi-gcc).
#
#   make                 stock mbedTLS: AES tables in RAM  -> Build/snmp_victim.bin
#   make ROMTABLES=1     MBEDTLS_AES_ROM_TABLES: tables in flash
#   make INSTRUMENT=1    + DWT ground-truth ring
#
# Everything compiled here is vendor-shipped: ST's HAL, ST's bundled lwIP (whose
# SNMPv3 agent and mbedTLS crypto backend are upstream lwIP sources, built as
# they ship), and ST's bundled mbedTLS. The only decision this project makes is
# where mbedTLS keeps its AES tables, which is one documented mbedTLS option.
#
# The vendor package is the pinned checkout under deps/, fetched with
# `./deps/fetch.sh stm32cube-f4`. Override with e.g. `make CUBE=/elsewhere`,
# but then it is a different measurement: deps/PINS records which release this
# was built against and why that matters.
HERE    := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
ROOT    := $(abspath $(HERE)/../../..)

CUBE    ?= $(ROOT)/deps/stm32cube-f4
MBED    ?= $(CUBE)/Middlewares/Third_Party/mbedTLS

CROSS  = arm-none-eabi-
CC     = $(CROSS)gcc
AS     = $(CROSS)gcc -x assembler-with-cpp
CP     = $(CROSS)objcopy
SZ     = $(CROSS)size

TARGET = snmp_victim
BUILD  = Build
ifeq ($(INSTRUMENT),1)
TARGET := $(TARGET)_inst
BUILD  := Build/inst
endif
# mbedTLS computes its AES tables into RAM at startup unless this is set;
# MBEDTLS_AES_ROM_TABLES is commented out in its shipped config.h. Setting it is
# routine on MCUs because it saves ~8 KB of RAM, and it is what puts the tables
# in flash -- i.e. what this whole attack needs. Both builds are measured.
ifneq ($(PAD),0)
TARGET := $(TARGET)_pad$(PAD)
BUILD  := $(BUILD)/pad$(PAD)
endif
ifeq ($(ROMTABLES),1)
TARGET := $(TARGET)_romtab
BUILD  := $(BUILD)/romtab
endif

# The flash data cache. ST's example hal_conf for this board never defines
# DATA_CACHE_ENABLE (DCEN=0, FLASH_ACR=0x305); CubeMX does (0x705). They are
# different channels -- at 0x305 the round-1 collision dip is ~230x smaller
# than at 0x705 -- so which one a victim ships with decides which attack
# applies. Verify from the boot banner, not from this flag.
ifeq ($(DCACHE),1)
TARGET := $(TARGET)_dcache
BUILD  := $(BUILD)/dcache
EXTRA_DEFS += -DDATA_CACHE_ENABLE=1U
endif

# One shared T-table instead of four. Four tables cap a round-1 attack at 4/16
# -- byte 0 can only reach {0,4,8,12} -- and leave each group just 6 pairs to
# pool, where the last-round attack pools ~15 per byte. FEWER_TABLES restores
# all 120 pairs to both sides. Combined with DCACHE=1 this is the strongest
# round-1 configuration measured.
ifeq ($(COMPACT),1)
TARGET := $(TARGET)_compact
BUILD  := $(BUILD)/compact
EXTRA_DEFS += -DMBEDTLS_AES_FEWER_TABLES
endif

# Extra flash wait states. The channel is a miss/hit penalty, so the collision
# dip scales with the wait-state count -- WAITSTATES=15 amplifies it ~2.7x over
# the 5 the part needs at 180 MHz, which is ~7x fewer traces. Use it to decide
# whether a path (a switch, a longer link) works at all, then confirm at the
# realistic setting. The boot banner prints the resulting FLASH_ACR -- check it.
ifneq ($(WAITSTATES),)
TARGET := $(TARGET)_ws$(WAITSTATES)
BUILD  := $(BUILD)/ws$(WAITSTATES)
EXTRA_DEFS += -DVICTIM_WAITSTATES=$(WAITSTATES)
endif

CPU    = -mcpu=cortex-m4 -mthumb -mfpu=fpv4-sp-d16 -mfloat-abi=hard

HAL    = $(CUBE)/Drivers/STM32F4xx_HAL_Driver
CMSIS  = $(CUBE)/Drivers/CMSIS
LWIP   = $(CUBE)/Middlewares/Third_Party/LwIP
LAN    = $(CUBE)/Drivers/BSP/Components/lan8742

# ---------------------------------------------------------------- sources ---
C_SRC = \
  Core/Src/main.c \
  Core/Src/snmp_agent.c \
  Core/Src/stm32f4xx_it.c \
  Core/Src/system_stm32f4xx.c \
  LWIP/Target/ethernetif.c \
  $(LAN)/lan8742.c

HAL_SRC = hal hal_cortex hal_rcc hal_rcc_ex hal_gpio hal_dma hal_pwr hal_pwr_ex \
          hal_flash hal_flash_ex hal_flash_ramfunc hal_eth hal_uart
C_SRC += $(foreach m,$(HAL_SRC),$(HAL)/Src/stm32f4xx_$(m).c)

# lwIP: core + IPv4 + netif, the CubeMX NO_SYS selection
C_SRC += $(wildcard $(LWIP)/src/core/*.c) \
         $(wildcard $(LWIP)/src/core/ipv4/*.c) \
         $(LWIP)/src/netif/ethernet.c

# lwIP's own SNMP agent: MIB-2, the v3 User Security Model, and the mbedTLS
# crypto backend. Upstream lwIP sources, compiled as shipped.
C_SRC += $(filter-out %snmp_netconn.c %snmp_threadsync.c, \
                      $(wildcard $(LWIP)/src/apps/snmp/*.c))

# mbedTLS: the AES under test, plus the cipher and message-digest layers that
# lwIP's SNMPv3 backend calls (MD5/SHA1 are RFC 3414 key localization).
C_SRC += $(MBED)/library/aes.c \
         $(MBED)/library/cipher.c \
         $(MBED)/library/cipher_wrap.c \
         $(MBED)/library/md.c $(MBED)/library/md_wrap.c \
         $(MBED)/library/md5.c \
         $(MBED)/library/sha1.c \
         $(MBED)/library/platform_util.c

ASM_SRC = startup_stm32f429xx.s

# --------------------------------------------------------------- includes ---
INC = -ICore/Inc -ILWIP/Target \
      -I$(CMSIS)/Include -I$(CMSIS)/Device/ST/STM32F4xx/Include \
      -I$(HAL)/Inc -I$(HAL)/Inc/Legacy \
      -I$(LWIP)/src/include -I$(LWIP)/system -I$(LWIP)/system/arch \
      -I$(LAN) \
      -I$(MBED)/include

# ------------------------------------------------------------------ flags ---
DEFS = -DSTM32F429xx -DUSE_HAL_DRIVER
# mbedTLS is pointed at a trimmed config holding only what lwIP's SNMPv3 backend
# calls. Table placement is the one knob -- see ROMTABLES above.
DEFS += -DMBEDTLS_CONFIG_FILE='"mbedtls_config.h"'
ifeq ($(ROMTABLES),1)
DEFS += -DMBEDTLS_AES_ROM_TABLES
endif
ifeq ($(INSTRUMENT),1)
DEFS += -DVICTIM_INSTRUMENT
endif
ifeq ($(LWIPDEBUG),1)
DEFS += -DVICTIM_LWIP_DEBUG
C_SRC += Core/Src/debug_io.c
TARGET := $(TARGET)_dbg
BUILD  := $(BUILD)/dbg
endif

# Experiment knobs, e.g. make EXTRA_DEFS="-DETH_TX_DESC_CNT=8U"
DEFS += $(EXTRA_DEFS)

OPT      = -O2
CFLAGS   = $(CPU) $(DEFS) $(INC) $(OPT) -g -Wall -fdata-sections -ffunction-sections \
           -std=gnu11 -Wno-unused-parameter -Wno-sign-compare
ASFLAGS  = $(CPU) -g -Wall -fdata-sections -ffunction-sections
LDSCRIPT = STM32F429ZITX_FLASH.ld
# Bytes of padding ahead of .rodata, which moves the AES tables within the
# flash line without touching any code. `make ROMTABLES=1 PAD=8`. Read the
# resulting FSb address out of the build's own table print; do not assume.
PAD     ?= 0
# Stamped into the image so a RUNNING board can say which arm it is. The
# link-time table print below says where that pad put FSb; the banner says
# which pad is executing. Neither alone identifies a board.
CFLAGS  += -DBUILD_RODATA_PAD=$(PAD)
LDFLAGS  = $(CPU) -T$(LDSCRIPT) -Wl,--defsym=RODATA_PAD=$(PAD) \
           --specs=nano.specs --specs=nosys.specs \
           -Wl,-Map=$(BUILD)/$(TARGET).map,--cref -Wl,--gc-sections -lc -lm

OBJ  = $(addprefix $(BUILD)/,$(notdir $(C_SRC:.c=.o)))
vpath %.c $(sort $(dir $(C_SRC)))
OBJ += $(addprefix $(BUILD)/,$(notdir $(ASM_SRC:.s=.o)))
vpath %.s $(sort $(dir $(ASM_SRC)))

all: $(BUILD)/$(TARGET).bin

$(BUILD)/%.o: %.c Makefile | $(BUILD)
	$(CC) -c $(CFLAGS) $< -o $@

$(BUILD)/%.o: %.s Makefile | $(BUILD)
	$(AS) -c $(ASFLAGS) $< -o $@

$(BUILD)/$(TARGET).elf: $(OBJ) Makefile
	$(CC) $(OBJ) $(LDFLAGS) -o $@
	$(SZ) $@
	@echo "--- where are the AES tables? ---"
	@$(CROSS)nm -S $@ | grep -iE " (FSb|FT0|RSb|RT0)$$" || true

$(BUILD)/$(TARGET).bin: $(BUILD)/$(TARGET).elf
	$(CP) -O binary -S $< $@

$(BUILD):
	mkdir -p $@

-include $(OBJ:.o=.d)

clean:
	rm -rf Build
