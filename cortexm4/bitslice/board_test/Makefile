# Rijndael-256 Bitsliced ASM Board Test — STM32F407
#
# Tests both encrypt and decrypt ASM.
#
# Usage:
#   make          - Build
#   make run      - Flash and read result
#   make flash    - Flash only
#   make read     - Read result only
#   make clean    - Remove build files

CC      = arm-none-eabi-gcc
AS      = arm-none-eabi-as
OBJCOPY = arm-none-eabi-objcopy
SIZE    = arm-none-eabi-size

COMMON  = ../../../common
BOARD   = ../../board_setup

CFLAGS  = -mcpu=cortex-m4 -mthumb -O3 -Wall -I.. -I$(COMMON)
ASFLAGS = -mcpu=cortex-m4 -mthumb
LDFLAGS = -T$(BOARD)/linker.ld -nostartfiles -specs=nano.specs

TARGET  = test

# Sources
STARTUP = $(BOARD)/startup.c
C_SRCS  = main.c ../rijndael256_keysched.c
ASM_SRCS = ../rijndael256_encrypt.s ../rijndael256_decrypt.s

all: $(TARGET).bin
	$(SIZE) $(TARGET).elf

encrypt.o: ../rijndael256_encrypt.s
	$(AS) $(ASFLAGS) -o $@ $<

decrypt.o: ../rijndael256_decrypt.s
	$(AS) $(ASFLAGS) -o $@ $<

$(TARGET).elf: $(STARTUP) $(C_SRCS) encrypt.o decrypt.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(STARTUP) $(C_SRCS) encrypt.o decrypt.o

$(TARGET).bin: $(TARGET).elf
	$(OBJCOPY) -O binary $< $@

flash: $(TARGET).bin
	st-flash --reset write $(TARGET).bin 0x08000000

RESULT_BIN = /tmp/r256_result_$(shell whoami).bin

read:
	@st-flash read $(RESULT_BIN) 0x20001000 108
	@python3 parse_result.py $(RESULT_BIN)

run: flash
	@sleep 1
	@$(MAKE) read

clean:
	rm -f $(TARGET).elf $(TARGET).bin encrypt.o decrypt.o

size: $(TARGET).elf
	$(SIZE) -A $< | grep -E '\.text|\.rodata|\.data|\.bss|Total'

code_size: encrypt.o decrypt.o
	@echo "--- Encrypt ---"
	@$(SIZE) encrypt.o
	@echo "--- Decrypt ---"
	@$(SIZE) decrypt.o

.PHONY: all flash read run clean size code_size
