# Rijndael-256 T-table Board Test — STM32F407

CC      = arm-none-eabi-gcc
OBJCOPY = arm-none-eabi-objcopy
SIZE    = arm-none-eabi-size

COMMON  = ../../../common
BOARD   = ../../board_setup

CFLAGS  = -mcpu=cortex-m4 -mthumb -O3 -Wall -I$(COMMON)
LDFLAGS = -T$(BOARD)/linker.ld -nostartfiles -specs=nano.specs

TARGET  = test

STARTUP = $(BOARD)/startup.c
C_SRCS  = main.c ../rijndael256_ttable.c

all: $(TARGET).bin
	$(SIZE) $(TARGET).elf

$(TARGET).elf: $(STARTUP) $(C_SRCS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(STARTUP) $(C_SRCS)

$(TARGET).bin: $(TARGET).elf
	$(OBJCOPY) -O binary $< $@

flash: $(TARGET).bin
	st-flash --reset write $(TARGET).bin 0x08000000

RESULT_BIN = /tmp/r256_result_$(shell whoami).bin

read:
	@st-flash read $(RESULT_BIN) 0x20001000 72
	@python3 parse_result.py $(RESULT_BIN)

run: flash
	@sleep 1
	@$(MAKE) read

size: $(TARGET).elf
	$(SIZE) -A $< | grep -E '\.text|\.rodata|\.data|\.bss|Total'

rijndael256_ttable.o: ../rijndael256_ttable.c
	$(CC) $(CFLAGS) -c -o $@ $<

code_size: rijndael256_ttable.o
	@$(SIZE) rijndael256_ttable.o

clean:
	rm -f $(TARGET).elf $(TARGET).bin rijndael256_ttable.o

.PHONY: all flash read run clean size code_size
