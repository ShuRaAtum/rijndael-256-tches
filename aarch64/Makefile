# Rijndael-256 ARM Implementation Makefile
#
# Target: Apple Silicon (ARM64)
#
# Supports implementations:
# - Native C (reference)
# - T-table (lookup table optimization)
# - NEON SIMD (software, 4-block parallel)
# - ARM Crypto Extension (hardware accelerated)

CC = clang
AS = clang

# Architecture flags for Apple Silicon (ARM64)
ARCH_FLAGS = -arch arm64
CRYPTO_FLAGS = -march=armv8-a+crypto

# Compiler flags (-I. so benchmark/ can find aes_baseline_arm.h)
CFLAGS = -O3 -Wall -Wextra -I../common -I. $(ARCH_FLAGS)
CFLAGS_BENCH = -O3 -Wall -Wextra -I../common -I. $(ARCH_FLAGS)
ASFLAGS = $(ARCH_FLAGS) $(CRYPTO_FLAGS)

# Platform-specific source directory
PLATFORM_DIR = platform/apple

# Source files
COMMON_SRC = rijndael256_keyschedule.c
REF_SRC = rijndael256_ref.c
TTABLE_SRC = rijndael256_ttable.c
AES_BASE_SRC = aes_baseline_arm.c
FOLDED_SRC = rijndael256_folded_arm.c
ARM_SRC = $(PLATFORM_DIR)/rijndael256_arm.S
NEON_SRC = $(PLATFORM_DIR)/rijndael256_neon.S
NEON_IL_SRC = $(PLATFORM_DIR)/rijndael256_neon_interleaved.S

TEST_SRC = test/test_main.c
BENCH_SRC = benchmark/benchmark.c

# Object files
COMMON_OBJ = $(COMMON_SRC:.c=.o)
REF_OBJ = $(REF_SRC:.c=.o)
TTABLE_OBJ = $(TTABLE_SRC:.c=.o)
AES_BASE_OBJ = $(AES_BASE_SRC:.c=.o)
FOLDED_OBJ = $(FOLDED_SRC:.c=.o)
ARM_OBJ = $(ARM_SRC:.S=.o)
NEON_OBJ = $(NEON_SRC:.S=.o)
NEON_IL_OBJ = $(NEON_IL_SRC:.S=.o)

TEST_OBJ = $(TEST_SRC:.c=.o)
BENCH_OBJ = $(BENCH_SRC:.c=.o)

# All implementation objects
IMPL_OBJ = $(COMMON_OBJ) $(REF_OBJ) $(TTABLE_OBJ) $(AES_BASE_OBJ) $(FOLDED_OBJ) $(ARM_OBJ) $(NEON_OBJ) $(NEON_IL_OBJ)

# Targets
TEST_TARGET = rijndael256_test
BENCH_TARGET = rijndael256_benchmark
DIT_TARGET = rijndael256_bench_dit

# Default target
.PHONY: all clean test benchmark bench_dit

all: $(TEST_TARGET)

# Build test executable
$(TEST_TARGET): $(TEST_OBJ) $(IMPL_OBJ)
	$(CC) $(CFLAGS) -o $@ $^

# Build benchmark executable
$(BENCH_TARGET): $(BENCH_OBJ) $(IMPL_OBJ)
	$(CC) $(CFLAGS_BENCH) -o $@ $^

# Compile C sources
%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Compile benchmark with -O3
benchmark/benchmark.o: benchmark/benchmark.c
	$(CC) $(CFLAGS_BENCH) -c -o $@ $<

# Compile ARM assembly (with crypto extension)
$(PLATFORM_DIR)/rijndael256_arm.o: $(PLATFORM_DIR)/rijndael256_arm.S
	$(AS) $(ASFLAGS) -c -o $@ $<

# Compile NEON assembly (without crypto extension)
$(PLATFORM_DIR)/rijndael256_neon.o: $(PLATFORM_DIR)/rijndael256_neon.S
	$(AS) $(ARCH_FLAGS) -c -o $@ $<

# Compile NEON interleaved assembly
$(PLATFORM_DIR)/rijndael256_neon_interleaved.o: $(PLATFORM_DIR)/rijndael256_neon_interleaved.S
	$(AS) $(ARCH_FLAGS) -c -o $@ $<

# Run tests
test: $(TEST_TARGET)
	./$(TEST_TARGET)

# Run benchmark
benchmark: $(BENCH_TARGET)
	./$(BENCH_TARGET)

# FEAT_DIT on/off A/B micro-benchmark (needs armv8.4-a for the DIT system register)
$(DIT_TARGET): bench_dit.c $(IMPL_OBJ)
	$(CC) -O3 -Wall -I../common -I. -arch arm64 -march=armv8.4-a+crypto -o $@ bench_dit.c $(IMPL_OBJ)

bench_dit: $(DIT_TARGET)
	./$(DIT_TARGET)

# Clean build artifacts
clean:
	rm -f $(IMPL_OBJ) $(TEST_OBJ) $(BENCH_OBJ)
	rm -f $(TEST_TARGET) $(BENCH_TARGET) $(DIT_TARGET)

# Debug build
debug: CFLAGS += -g -O0
debug: $(TEST_TARGET)

# Help
help:
	@echo "Rijndael-256 ARM Implementation (Apple Silicon)"
	@echo ""
	@echo "Targets:"
	@echo "  all       - Build test executable (default)"
	@echo "  test      - Build and run tests"
	@echo "  benchmark - Build and run benchmark"
	@echo "  clean     - Remove build artifacts"
	@echo "  debug     - Build with debug symbols"
	@echo "  help      - Show this help message"
	@echo ""
	@echo "Implementations:"
	@echo "  - Native C (reference)"
	@echo "  - T-table (lookup table)"
	@echo "  - NEON SIMD (4-block parallel)"
	@echo "  - ARM Crypto Extension"
	@echo ""
	@echo "For Raspberry Pi 4, use: make -f Makefile.rpi4"
