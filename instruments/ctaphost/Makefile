# Build flashsim HIL firmware for NUCLEO-F429ZI (run in WSL).
CROSS  = arm-none-eabi-
CPU    = -mcpu=cortex-m4 -mthumb -mfloat-abi=hard -mfpu=fpv4-sp-d16
CFLAGS = $(CPU) -DSTM32F429xx -O2 -g -ffreestanding -fno-common -Wall -Wextra -I../cmsis -I.
LDFLAGS= $(CPU) -T link.ld -nostartfiles --specs=nano.specs --specs=nosys.specs \
         -Wl,--gc-sections -Wl,-Map=fw.map
OBJ = startup.o main.o

all: fw.bin

%.o: %.c
	$(CROSS)gcc $(CFLAGS) -c $< -o $@

fw.elf: $(OBJ)
	$(CROSS)gcc $(LDFLAGS) $(OBJ) -o $@
	$(CROSS)size $@

fw.bin: fw.elf
	$(CROSS)objcopy -O binary $< $@

clean:
	rm -f *.o fw.elf fw.bin fw.map
