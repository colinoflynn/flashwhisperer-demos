# Bring-up self-test for the NUCLEO-L152RE SBSFU port's serial-flash BSP.
#
# Built in WSL -- arm-none-eabi-gcc is WSL-only on this host, the same as
# every other rig here:
#
#   wsl -- bash -lc 'cd <this dir> && make'
#
# It compiles the SAME NUCLEO_L152RE/BSP source the bootloader does, reached
# sibling-relative rather than copied, so a green self-test is a statement
# about the code that will actually run.
#
# Unlike the SAM D21 bring-up next door, this one DOES need a vendor
# checkout: the HAL under the BSP is ST's real STM32L1xx_HAL_Driver, not a
# shim written here.  Run ../fetch_cubel1.sh first, or pass CUBEL1_ROOT.
CROSS   = arm-none-eabi-
CPU     = -mcpu=cortex-m3 -mthumb -mfloat-abi=soft

CUBEL1_ROOT ?= $(abspath ../../../../cubel1-src)
HAL      = $(CUBEL1_ROOT)/Drivers/STM32L1xx_HAL_Driver
CMSIS_D  = $(CUBEL1_ROOT)/Drivers/CMSIS/Device/ST/STM32L1xx
CMSIS_C  = $(CUBEL1_ROOT)/Drivers/CMSIS/Include

PORT     = ../NUCLEO_L152RE
CONF     = $(PORT)/2_Images_SBSFU/Core/Inc

# STM32L152RE: 512 KB flash, 80 KB SRAM, Cortex-M3.  The device header is
# selected by this define and nothing else -- getting it wrong gives a build
# that compiles against another die's peripheral map.
DEVICE  = -DSTM32L152xE -DUSE_HAL_DRIVER

OPT    ?= -O2
CFLAGS  = $(CPU) $(OPT) -g -ffreestanding -fno-common -Wall -Wextra \
          $(DEVICE) \
          -I. -I$(CONF) -I$(PORT)/BSP \
          -I$(HAL)/Inc -I$(CMSIS_D)/Include -I$(CMSIS_C)
LDFLAGS = $(CPU) -T link.ld --specs=nano.specs --specs=nosys.specs \
          -Wl,--gc-sections -Wl,-Map=fw.map

# Only the HAL modules this image actually calls.  ST's shipped
# stm32l1xx_hal_conf.h enables every module in the package; that decides
# which HEADERS are visible, not which objects are linked, so the subset
# here is a build-time choice and not a deviation from ST's configuration.
HAL_SRC = stm32l1xx_hal.c stm32l1xx_hal_cortex.c stm32l1xx_hal_rcc.c \
          stm32l1xx_hal_rcc_ex.c stm32l1xx_hal_gpio.c stm32l1xx_hal_pwr.c \
          stm32l1xx_hal_pwr_ex.c stm32l1xx_hal_spi.c stm32l1xx_hal_uart.c \
          stm32l1xx_hal_flash.c stm32l1xx_hal_flash_ex.c \
          stm32l1xx_hal_flash_ramfunc.c stm32l1xx_hal_dma.c

OBJ = startup.o system_stm32l1xx.o main.o l152_nucleo_spif.o \
      $(HAL_SRC:.c=.o)

all: fw.bin

startup.o: $(CMSIS_D)/Source/Templates/gcc/startup_stm32l152xe.s
	$(CROSS)gcc $(CPU) -c -x assembler-with-cpp $< -o $@

system_stm32l1xx.o: $(CMSIS_D)/Source/Templates/system_stm32l1xx.c
	$(CROSS)gcc $(CFLAGS) -c $< -o $@

main.o: main.c
	$(CROSS)gcc $(CFLAGS) -c $< -o $@

l152_nucleo_spif.o: $(PORT)/BSP/l152_nucleo_spif.c $(PORT)/BSP/l152_nucleo_spif.h
	$(CROSS)gcc $(CFLAGS) -c $< -o $@

%.o: $(HAL)/Src/%.c
	$(CROSS)gcc $(CFLAGS) -c $< -o $@

fw.elf: $(OBJ) link.ld
	@test -d $(HAL)/Src || { \
	  echo "No STM32CubeL1 checkout at $(CUBEL1_ROOT)."; \
	  echo "Run ../fetch_cubel1.sh, or pass CUBEL1_ROOT=<path>."; exit 1; }
	$(CROSS)gcc $(LDFLAGS) $(OBJ) -o $@
	$(CROSS)size $@

fw.bin: fw.elf
	$(CROSS)objcopy -O binary $< $@

clean:
	rm -f *.o fw.elf fw.bin fw.map

.PHONY: all clean
