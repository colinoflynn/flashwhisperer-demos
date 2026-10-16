# NUCLEO-F303RE bus-side chip-select timer for the SAM D21 SBSFU oracle.
#
# Built in WSL -- arm-none-eabi-gcc is WSL-only on this host:
#
#   wsl -- bash -lc 'cd <this dir> && make'
#
# FLASHED BY COPYING fw.bin ONTO THE ST-LINK MASS-STORAGE VOLUME, which is
# labelled NOD_F303RE.  RESOLVE IT BY LABEL, NEVER BY DRIVE LETTER -- it was
# E: on 2026-09-23 and that is not a stable property.  pyocd 0.45.1 on this
# host has no stm32f303 target and no pack for one; the generic cortex_m
# target is enough for halted register reads (rigs/host/spitimer_wiring.py
# uses exactly that) but cannot program the part.
#
# -O2 and nothing else.  This firmware is the INSTRUMENT, not the subject:
# no part of the measurement depends on how its own code is laid out,
# because every timestamp is latched by the timer in hardware and moved by
# DMA.  The placement axes that rigs/fw_f303_aes carries would be noise here.
CROSS  = arm-none-eabi-
CPU    = -mcpu=cortex-m4 -mthumb -mfloat-abi=soft
OPT   ?= -O2

CFLAGS = $(CPU) $(OPT) -g -ffreestanding -fno-common -Wall -Wextra -I.
LDFLAGS = $(CPU) -T link.ld -nostartfiles --specs=nano.specs --specs=nosys.specs \
          -Wl,-Map=fw.map

OBJ = startup.o main.o

all: fw.bin

%.o: %.c
	$(CROSS)gcc $(CFLAGS) -c $< -o $@

fw.elf: $(OBJ) link.ld
	$(CROSS)gcc $(LDFLAGS) $(OBJ) -o $@
	$(CROSS)size $@

fw.bin: fw.elf
	$(CROSS)objcopy -O binary $< $@

clean:
	rm -f *.o fw.elf fw.bin fw.map

.PHONY: all clean
