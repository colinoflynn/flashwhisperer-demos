# HTTPS flash-timing victim -- NUCLEO-F429ZI. Build in WSL (arm-none-eabi-gcc).
#
#   make                 stock mbedTLS: AES tables in RAM  -> Build/https_victim.bin
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

TARGET = https_victim
BUILD  = Build
ifeq ($(INSTRUMENT),1)
TARGET := $(TARGET)_inst
BUILD  := Build/inst
endif
# mbedTLS computes its AES tables into RAM at startup unless this is set;
# MBEDTLS_AES_ROM_TABLES is commented out in its shipped config.h. Setting it is
# routine on MCUs because it saves ~8 KB of RAM, and it is what puts the tables
# in flash -- i.e. what this whole attack needs. Both builds are measured.
ifeq ($(ROMTABLES),1)
TARGET := $(TARGET)_romtab
BUILD  := $(BUILD)/romtab
endif

CPU    = -mcpu=cortex-m4 -mthumb -mfpu=fpv4-sp-d16 -mfloat-abi=hard

HAL    = $(CUBE)/Drivers/STM32F4xx_HAL_Driver
CMSIS  = $(CUBE)/Drivers/CMSIS
LWIP   = $(CUBE)/Middlewares/Third_Party/LwIP
LAN    = $(CUBE)/Drivers/BSP/Components/lan8742

# ---------------------------------------------------------------- sources ---
C_SRC = \
  Core/Src/main.c \
  Core/Src/https_server.c \
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

# lwIP's own web server and its TLS layer, compiled as shipped.
C_SRC += $(LWIP)/src/apps/http/httpd.c $(LWIP)/src/apps/http/fs.c \
         $(wildcard $(LWIP)/src/apps/altcp_tls/*.c)

# mbedTLS: the AES under test plus everything TLS 1.2 needs for an RSA
# certificate. Compiled as shipped; only the config header selects features.
MBED_SRC = aes cipher cipher_wrap md md_wrap md5 sha1 sha256 platform \
           platform_util bignum rsa rsa_internal oid pk pk_wrap pkparse \
           pkwrite asn1parse asn1write base64 pem error entropy entropy_poll \
           memory_buffer_alloc ctr_drbg x509 x509_crt ssl_tls ssl_srv ssl_cli ssl_ciphersuites \
           ssl_cookie ssl_cache ssl_ticket debug
C_SRC += $(foreach m,$(MBED_SRC),$(MBED)/library/$(m).c)

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
# lwIP's altcp_tls references mbedTLS's *socket layer* error codes even though it
# never uses the socket layer -- they live in net_sockets.h behind MBEDTLS_NET_C,
# which would drag in POSIX sockets. Supplying the four constants is cleaner than
# either enabling that or patching lwIP. Values from mbedtls/net_sockets.h.
DEFS += -DMBEDTLS_ERR_NET_CONN_RESET=-0x0050         -DMBEDTLS_ERR_NET_INVALID_CONTEXT=-0x0045         -DMBEDTLS_ERR_NET_SEND_FAILED=-0x004E         -DMBEDTLS_ERR_NET_RECV_FAILED=-0x004C
ifeq ($(ROMTABLES),1)
DEFS += -DMBEDTLS_AES_ROM_TABLES
endif
ifeq ($(INSTRUMENT),1)
DEFS += -DVICTIM_INSTRUMENT
endif
ifeq ($(LWIPDEBUG),1)
DEFS += -DVICTIM_LWIP_DEBUG
# httpd's debug messages call lwip_strerr(), which lives in api/err.c -- the one
# file outside src/core that a NO_SYS build otherwise never needs.
C_SRC += Core/Src/debug_io.c $(LWIP)/src/api/err.c
TARGET := $(TARGET)_dbg
BUILD  := $(BUILD)/dbg
endif

# Experiment knobs, e.g. make EXTRA_DEFS="-DETH_TX_DESC_CNT=8U"
DEFS += $(EXTRA_DEFS)

OPT      = -O2
CFLAGS   = $(CPU) $(DEFS) $(INC) $(OPT) -g -Wall -fdata-sections -ffunction-sections \
           -std=gnu11 -Wno-unused-parameter -Wno-sign-compare -MMD -MP
ASFLAGS  = $(CPU) -g -Wall -fdata-sections -ffunction-sections
LDSCRIPT = STM32F429ZITX_FLASH.ld
LDFLAGS  = $(CPU) -T$(LDSCRIPT) --specs=nano.specs --specs=nosys.specs \
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

-include $(OBJ:.o=.d)

clean:
	rm -rf Build
