# ============================================================================
# Mirath tcith_3a_fast  --  Makefile with ARM Rijndael-256 support
#
# Build targets:
#   make                     -> default (reference on x86, arm_crypto on AArch64)
#   make arm_crypto          -> ARM Crypto Extension (AESE/AESMC)
#   make neon                -> NEON TBL/TBX software path
#   make ref                 -> portable reference (original)
# ============================================================================

MIRATH = .
COMMON = $(MIRATH)/common
RIJNDAEL = $(COMMON)/rijndael
PARAMETERS = $(MIRATH)/parameters
ARITH = $(MIRATH)/arith
ARITH_X = $(ARITH)/q_16
ARITH_MU = $(ARITH_X)/mu_fast

INCLUDES = -I$(PARAMETERS) -I$(ARITH_MU) -I$(ARITH_X) -I$(ARITH) -I$(RIJNDAEL) -I$(COMMON) -I$(MIRATH)

LIBS = -lcrypto

# ---------- platform detection ----------
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

ifeq ($(UNAME_S),Darwin)
    OPENSSL_PREFIX := $(shell brew --prefix openssl 2>/dev/null || brew --prefix openssl@3 2>/dev/null || echo /opt/homebrew/opt/openssl@3)
    INCLUDES += -I$(OPENSSL_PREFIX)/include
    LIBS += -L$(OPENSSL_PREFIX)/lib
endif

# ---------- base CFLAGS (no arch-specific flags yet) ----------
CFLAGS_BASE = -std=c11 -Wall -Wextra -pedantic -O2

# ---------- object files common to all builds ----------
TMP=rng.o $(subst common/random.o, ,$(patsubst common/%.c,common/%.o,$(wildcard common/*.c)))
OBJ_BASE=$(subst common/KeccakP-1600-times4-SIMD256.o, ,$(TMP))
OBJ_BASE+=$(patsubst %.c,%.o,$(wildcard *.c))

VPATH = $(PARAMETERS):$(ARITH_MU):$(ARITH_X):$(ARITH):$(RIJNDAEL):$(COMMON):$(MIRATH)

# ============================================================================
# Reference build (original x86)
# ============================================================================
ifeq ($(filter arm% aarch64%, $(UNAME_M)),)
ref: CFLAGS = $(CFLAGS_BASE) -mavx -mavx2 -mbmi -mbmi2 -maes
else
ref: CFLAGS = $(CFLAGS_BASE)
endif
ref: OBJ = $(OBJ_BASE)
ref: OBJ_MAIN = $(filter-out PQCgenKAT_sign.o, $(OBJ))
ref: OBJ_KATS = $(filter-out main.o, $(OBJ))
ref: mirath_3a_f_ref

mirath_3a_f_ref: $(filter-out PQCgenKAT_sign.o, $(OBJ_BASE))
	$(CC) -o mirath_3a_f $^ $(LIBS)

# ============================================================================
# ARM Crypto Extension build (AESE/AESMC hardware path)
# ============================================================================
ARM_ASM_OBJ = common/rijndael/rijndael256_arm.o common/rijndael/rijndael256_keyschedule.o
ARM_CFLAGS = $(CFLAGS_BASE) -DUSE_ARM_CRYPTO -march=armv8-a+crypto

arm_crypto: CFLAGS = $(ARM_CFLAGS)
arm_crypto: mirath_3a_f_arm

mirath_3a_f_arm: $(filter-out PQCgenKAT_sign.o, $(OBJ_BASE)) $(ARM_ASM_OBJ)
	$(CC) -o mirath_3a_f $^ $(LIBS)

# ============================================================================
# ARM Crypto + AddRoundKey-folded build (Kpre pre-shuffle; folded AESE path)
# Same hardware path as arm_crypto, but round keys are pre-shuffled per key and
# the per-round EORs are folded into AESE. folded_setup runs per key expansion.
# ============================================================================
FOLDED_OBJ = common/rijndael/rijndael256_folded_arm.o common/rijndael/rijndael256_keyschedule.o
ARM_FOLDED_CFLAGS = $(CFLAGS_BASE) -DUSE_ARM_FOLDED -DUSE_ARM_CRYPTO -march=armv8-a+crypto

arm_folded: CFLAGS = $(ARM_FOLDED_CFLAGS)
arm_folded: mirath_3a_f_folded

mirath_3a_f_folded: $(filter-out PQCgenKAT_sign.o, $(OBJ_BASE)) $(FOLDED_OBJ)
	$(CC) -o mirath_3a_f $^ $(LIBS)

common/rijndael/rijndael256_folded_arm.o: common/rijndael/rijndael256_folded_arm.c
	$(CC) -D_SHA3_ $(INCLUDES) -c -o $@ $< $(CFLAGS)

# ============================================================================
# NEON TBL/TBX build (software SIMD, no crypto extension needed)
# ============================================================================
NEON_ASM_OBJ = common/rijndael/rijndael256_neon.o common/rijndael/rijndael256_neon_interleaved.o common/rijndael/rijndael256_keyschedule.o
NEON_CFLAGS = $(CFLAGS_BASE) -DUSE_NEON -march=armv8-a

neon: CFLAGS = $(NEON_CFLAGS)
neon: mirath_3a_f_neon

mirath_3a_f_neon: $(filter-out PQCgenKAT_sign.o, $(OBJ_BASE)) $(NEON_ASM_OBJ)
	$(CC) -o mirath_3a_f $^ $(LIBS)

# ============================================================================
# Default target -- auto-select based on architecture
# ============================================================================
ifeq ($(filter arm% aarch64%, $(UNAME_M)),)
    # x86 -- use reference
    CFLAGS = $(CFLAGS_BASE) -mavx -mavx2 -mbmi -mbmi2 -maes
    OBJ = $(OBJ_BASE)
    all: mirath_3a_f PQCgenKAT_sign
else
    # AArch64 -- use ARM Crypto Extension
    CFLAGS = $(ARM_CFLAGS)
    OBJ = $(OBJ_BASE)
    ASM_EXTRA = $(ARM_ASM_OBJ)
    all: mirath_3a_f PQCgenKAT_sign
endif

OBJ_MAIN = $(filter-out PQCgenKAT_sign.o, $(OBJ))
OBJ_KATS = $(filter-out main.o, $(OBJ))

# ============================================================================
# Compile rules
# ============================================================================
%.o: %.c
	$(CC) -D_SHA3_ $(INCLUDES) -c -o $@ $< $(CFLAGS)

rng.o: rng.c
	$(CC) -c $(CFLAGS) $(INCLUDES) -o $@ $<

# Assembly rules for ARM
common/rijndael/rijndael256_arm.o: common/rijndael/rijndael256_arm.S
	$(CC) -c -o $@ $< $(CFLAGS)

common/rijndael/rijndael256_neon.o: common/rijndael/rijndael256_neon.S
	$(CC) -c -o $@ $< $(CFLAGS)

common/rijndael/rijndael256_neon_interleaved.o: common/rijndael/rijndael256_neon_interleaved.S
	$(CC) -c -o $@ $< $(CFLAGS)

common/rijndael/rijndael256_keyschedule.o: common/rijndael/rijndael256_keyschedule.c
	$(CC) -D_SHA3_ $(INCLUDES) -c -o $@ $< $(CFLAGS)

# ============================================================================
# Link targets
# ============================================================================
mirath_3a_f: main.o sign.o $(OBJ_MAIN) $(ASM_EXTRA)
	$(CC) -o $@ $^ $(LIBS)

PQCgenKAT_sign: PQCgenKAT_sign.o sign.o $(OBJ_KATS) $(ASM_EXTRA)
	$(CC) -o $@ $^ $(LIBS)

run: PQCgenKAT_sign
	./PQCgenKAT_sign

.PHONY: clean all ref arm_crypto arm_folded neon run

clean:
	rm -f *.o *.su
	rm -f common/*.o
	rm -f common/rijndael/*.o
	rm -f mirath_3a_f
	rm -f PQCgenKAT_sign
	rm -f PQCsignKAT_*.req
	rm -f PQCsignKAT_*.rsp
