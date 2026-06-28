/*
 * Standard AES-128 / AES-256 hardware baseline (ARMv8 Crypto Extension).
 *
 * Purpose: provide AES-128 (10 rounds) and AES-256 (14 rounds, round-matched
 * to Rijndael-256) encryption on the SAME AESE/AESMC instructions used by the
 * R256 ARM-Crypto path, so the AES->R256 per-byte slowdown can be measured in
 * the identical single-block benchmark harness (benchmark_impl).
 *
 * Guarded by __ARM_FEATURE_CRYPTO/__ARM_FEATURE_AES: on cores without the CE
 * the encrypt functions are no-ops and aes_baseline_available() returns 0.
 */
#ifndef AES_BASELINE_ARM_H
#define AES_BASELINE_ARM_H

#include <stdint.h>

/* Expanded AES key: up to 15 round keys (AES-256) of 16 bytes each. */
typedef struct {
    uint8_t roundKeys[15 * 16];
    int rounds;            /* 10 (AES-128) or 14 (AES-256) */
} AesKey;

/* 1 if the AES-NI/CE baseline was compiled in (crypto available), else 0. */
int  aes_baseline_available(void);

/* Standard AES key expansion. keyBits in {128,192,256}. Returns 0 on success. */
int  aes_key_expand(const uint8_t *key, int keyBits, AesKey *ks);

/* AES encryption (single 16-byte block) via AESE/AESMC. */
void aes128_encrypt_arm(const AesKey *ks, const uint8_t *in, uint8_t *out);
void aes256_encrypt_arm(const AesKey *ks, const uint8_t *in, uint8_t *out);

/* Interleaved AES: N independent 16-byte blocks per call (in/out hold N*16 B).
 * Same key, same harness as the folded R256 interleaved path, for a
 * batched-vs-batched AES->R256 comparison at matched N. */
void aes128_encrypt_arm_x2(const AesKey *ks, const uint8_t *in, uint8_t *out);
void aes128_encrypt_arm_x4(const AesKey *ks, const uint8_t *in, uint8_t *out);
void aes128_encrypt_arm_x8(const AesKey *ks, const uint8_t *in, uint8_t *out);
void aes256_encrypt_arm_x2(const AesKey *ks, const uint8_t *in, uint8_t *out);
void aes256_encrypt_arm_x4(const AesKey *ks, const uint8_t *in, uint8_t *out);
void aes256_encrypt_arm_x8(const AesKey *ks, const uint8_t *in, uint8_t *out);

/* FIPS-197 known-answer self-test for AES-128 and AES-256.
 * Returns 0 on success; nonzero identifies the failing vector. */
int  aes_baseline_selftest(void);

#endif /* AES_BASELINE_ARM_H */
