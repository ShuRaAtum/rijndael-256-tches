# Rijndael-256 on x86-64 (AES-NI + blend/pshufb pre-shuffle)
#
# Build natively on an x86-64 machine with AES-NI (run KAT + benchmark there).
#   make            # build test + benchmark
#   make test       # KAT vs portable reference
#   make benchmark  # throughput + cycles/byte vs AES-128/AES-256
#
# Reuses the portable reference and key schedule from ../aarch64.

CC = cc
CFLAGS = -O3 -Wall -Wextra -I../common -maes -mavx -mssse3 -msse4.1
# For best AES-NI throughput on the host, also try: -march=native

# VAES-512 build: needs AVX-512 F/BW/VBMI + VAES. -march=native is simplest on
# the host; the explicit flag list documents the minimum required ISA.
VAESFLAGS = -O3 -Wall -Wextra -I../common -march=native \
            -mavx512f -mavx512bw -mavx512vbmi -mvaes -mvpclmulqdq

COMMON = ../aarch64/rijndael256_keyschedule.c ../aarch64/rijndael256_ref.c
IMPL   = rijndael256_aesni.c
VIMPL  = rijndael256_vaes512.c

.PHONY: all test benchmark vaes_test vaes_benchmark vaes clean

all: rijndael256_test rijndael256_benchmark

rijndael256_test: test/test_kat.c $(IMPL) $(COMMON)
	$(CC) $(CFLAGS) -o $@ $^

rijndael256_benchmark: benchmark/benchmark.c $(IMPL) $(COMMON)
	$(CC) $(CFLAGS) -o $@ $^

test: rijndael256_test
	./rijndael256_test

benchmark: rijndael256_benchmark
	./rijndael256_benchmark

# ---- VAES-512 paths ----
rijndael256_vaes_test: test/test_kat_vaes.c $(VIMPL) $(COMMON)
	$(CC) $(VAESFLAGS) -o $@ $^

rijndael256_vaes_benchmark: benchmark/benchmark_vaes.c $(VIMPL) $(IMPL) $(COMMON)
	$(CC) $(VAESFLAGS) -o $@ $^

vaes_test: rijndael256_vaes_test
	./rijndael256_vaes_test

vaes_benchmark: rijndael256_vaes_benchmark
	./rijndael256_vaes_benchmark

vaes: vaes_test vaes_benchmark

clean:
	rm -f rijndael256_test rijndael256_benchmark \
	      rijndael256_vaes_test rijndael256_vaes_benchmark
