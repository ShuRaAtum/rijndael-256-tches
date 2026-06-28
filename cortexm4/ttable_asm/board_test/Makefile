# Rijndael-256 T-table ASM Board Test — STM32F407

CC      = arm-none-eabi-gcc
AS      = arm-none-eabi-as
OBJCOPY = arm-none-eabi-objcopy
SIZE    = arm-none-eabi-size

COMMON  = ../../../common
BOARD   = ../../board_setup

CFLAGS  = -mcpu=cortex-m4 -mthumb -O3 -Wall -I$(COMMON)
LDFLAGS = -T$(BOARD)/linker.ld -nostartfiles -specs=nano.specs

TARGET  = test

all: $(TARGET).bin
	$(SIZE) $(TARGET).elf

encrypt.o: ../rijndael256_encrypt.s
	$(AS) -mcpu=cortex-m4 -mthumb -o $@ $<

$(TARGET).elf: $(BOARD)/startup.c main.c ../rijndael256_impl.c encrypt.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(BOARD)/startup.c main.c ../rijndael256_impl.c encrypt.o

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

rijndael256_impl.o: ../rijndael256_impl.c
	$(CC) $(CFLAGS) -c -o $@ $<

code_size: encrypt.o rijndael256_impl.o
	@echo "--- ASM Encrypt ---"
	@$(SIZE) encrypt.o
	@echo "--- C Impl ---"
	@$(SIZE) rijndael256_impl.o

clean:
	rm -f $(TARGET).elf $(TARGET).bin encrypt.o rijndael256_impl.o

.PHONY: all flash read run clean size code_size
