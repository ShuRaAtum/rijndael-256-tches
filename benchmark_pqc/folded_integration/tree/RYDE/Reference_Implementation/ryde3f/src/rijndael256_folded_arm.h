/*
 * Rijndael-256 ARM-Crypto "AddRoundKey-folded" variant.
 *
 * The shipped path (rijndael256_encrypt_arm) feeds a zero key to AESE and
 * applies AddRoundKey as a separate post-AESMC EOR (x86-AESENC-style).
 *
 * This variant folds AddRoundKey back INTO AESE by pre-shuffling each round
 * key with the SAME byte permutation used to pre-shuffle the state:
 *
 *   AESE(x,k) = SubBytes(ShiftRows(x ^ k))            (HW ShiftRows 0,1,2,3)
 *   TBL distributes over XOR (byte gather), so
 *   AESE(TBL(state), TBL(rk)) = SubBytes(HW_SR(TBL(state ^ rk)))
 *                             = SubBytes(R256_ShiftRows(state ^ rk))
 *
 * i.e. AddRoundKey is performed inside AESE at zero extra runtime cost; only a
 * one-time key pre-shuffle (Kpre[k] = TBL(rk[k])) is needed. The initial and
 * all per-round EORs disappear; only the final round key remains a natural
 * EOR. Round keys rk[0..Nr-1] are consumed pre-shuffled by AESE; rk[Nr] is the
 * natural-order final AddRoundKey (canonical AESE round-key alignment).
 */
#ifndef RIJNDAEL256_FOLDED_ARM_H
#define RIJNDAEL256_FOLDED_ARM_H

#include <stdint.h>
#include "rijndael256_opt.h"

/* Pre-shuffled key schedule for the folded variant. */
typedef struct {
    uint8_t kpre[14 * 32];   /* Kpre[0..Nr-1], each 32B = KpreL(16) || KpreR(16) */
    uint8_t rk_final[32];    /* rk[Nr], natural order (final AddRoundKey)         */
    int rounds;              /* Nr (14) */
} R256FoldedKey;

/* 1 if the folded variant (crypto) was compiled in. */
int  rijndael256_folded_available(void);

/* Build the pre-shuffled key schedule from a standard R256 key context. */
void rijndael256_folded_setup(const Rijndael256Key *ctx, R256FoldedKey *fk);

/* Encrypt one 32-byte block with the folded ARM-Crypto path. */
void rijndael256_encrypt_arm_folded(const R256FoldedKey *fk,
                                    const uint8_t *pt, uint8_t *ct);

/* Interleaved (multi-block) folded encryption: N independent blocks per call.
 * 2N independent AESE chains (L/R per block) hide AESE/TBL latency. Same
 * pre-shuffle/Kpre as the single-block path. in/out hold N*32 bytes. */
void rijndael256_encrypt_arm_folded_x2(const R256FoldedKey *fk, const uint8_t *pt, uint8_t *ct);
void rijndael256_encrypt_arm_folded_x4(const R256FoldedKey *fk, const uint8_t *pt, uint8_t *ct);
void rijndael256_encrypt_arm_folded_x8(const R256FoldedKey *fk, const uint8_t *pt, uint8_t *ct);

/* KAT vs the portable reference (key 128/192/256 + 1000-block sweep).
 * Returns 0 on success; nonzero identifies the failing case. */
int  rijndael256_folded_selftest(void);

#endif /* RIJNDAEL256_FOLDED_ARM_H */
