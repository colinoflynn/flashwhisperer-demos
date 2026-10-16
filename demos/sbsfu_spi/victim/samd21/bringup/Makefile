# Bring-up self-test for the SAM D21 SBSFU port's HAL and serial-flash BSP.
#
# Built in WSL -- arm-none-eabi-gcc is WSL-only on this host, the same as
# fw_samd21_aes, fw_xmc1_aes, fw_nrf_aes and fw_ra2_aes:
#
#   wsl -- bash -lc 'cd <this dir> && make'
#
# It compiles the SAME SAMD21_XPRO/HAL and SAMD21_XPRO/BSP sources the
# bootloader does -- reached sibling-relative, not copied -- so a green
# self-test is a statement about the code that will actually run, not about a
# fork of it.  That is the whole value of the image; if these ever diverge the
# test stops meaning anything.
#
# It needs no SBSFU checkout: the HAL and BSP are this port's own code, and
# only the bootloader proper pulls in ST's tree.
CROSS  = arm-none-eabi-
CPU    = -mcpu=cortex-m0plus -mthumb
PORT   = ../SAMD21_XPRO
CMSIS  = ../../cmsis

OPT   ?= -O2
CFLAGS = $(CPU) $(OPT) -g -ffreestanding -fno-common -Wall -Wextra \
         -D__SAMD21J18A__ \
         -I. -I$(CMSIS) -I$(CMSIS)/samd21 -I$(PORT)/HAL -I$(PORT)/BSP
LDFLAGS = $(CPU) -T link.ld -nostartfiles --specs=nano.specs --specs=nosys.specs \
          -Wl,-Map=fw.map

OBJ = startup.o main.o samd21_hal.o samd21_xpro_spif.o

all: fw.bin

startup.o: startup.c
	$(CROSS)gcc $(CFLAGS) -c $< -o $@

main.o: main.c
	$(CROSS)gcc $(CFLAGS) -c $< -o $@

samd21_hal.o: $(PORT)/HAL/samd21_hal.c
	$(CROSS)gcc $(CFLAGS) -c $< -o $@

samd21_xpro_spif.o: $(PORT)/BSP/samd21_xpro_spif.c
	$(CROSS)gcc $(CFLAGS) -c $< -o $@

fw.elf: $(OBJ) link.ld
	$(CROSS)gcc $(LDFLAGS) $(OBJ) -o $@
	$(CROSS)size $@

fw.bin: fw.elf
	$(CROSS)objcopy -O binary --gap-fill 0xFF $< $@

clean:
	rm -f *.o fw.elf fw.bin fw.map

.PHONY: all clean
