/*
 * Rijndael-256 Cipher Implementation
 * Block Size: 256 bits (32 bytes)
 * Key Sizes: 128, 192, 256 bits
 *
 * This header provides a common interface for three implementations:
 * - Native C (reference)
 * - T-table (lookup table optimization)
 * - ARM Crypto Extension (hardware accelerated)
 */

#ifndef RIJNDAEL256_H
#define RIJNDAEL256_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Constants */
#define RIJNDAEL256_BLOCK_SIZE 32       /* 256 bits = 32 bytes */
#define RIJNDAEL256_MAX_ROUNDS 14       /* Maximum rounds for all key sizes */
#define RIJNDAEL256_NB 8                /* Number of 32-bit words in block */

/* Key context structure (aligned for SIMD operations) */
typedef struct __attribute__((aligned(16))) {
    uint8_t roundKeys[(RIJNDAEL256_MAX_ROUNDS + 1) * RIJNDAEL256_BLOCK_SIZE];  /* 480 bytes */
    int rounds;
} Rijndael256Key;

/* T-table key structure (word-based for T-table implementation) */
typedef struct {
    uint32_t roundKey[120];  /* Max: (14+1) * 8 = 120 words */
    int rounds;
} Rijndael256KeyTTable;

/*
 * Key Setup Functions
 * Returns 0 on success, -1 on invalid key size
 */

/* Setup key for reference and ARM implementations (byte-based round keys) */
int rijndael256_setup_key(const uint8_t *key, int keyBits, Rijndael256Key *ctx);

/* Setup key for T-table implementation (word-based round keys) */
int rijndael256_setup_key_ttable(const uint8_t *key, int keyBits, Rijndael256KeyTTable *ctx);

/*
 * Encryption Functions
 * All take 32-byte plaintext and produce 32-byte ciphertext
 */

/* Native C implementation (reference, portable) */
void rijndael256_encrypt_ref(const Rijndael256Key *ctx, const uint8_t *pt, uint8_t *ct);

/* T-table implementation (optimized lookup tables) */
void rijndael256_encrypt_ttable(const Rijndael256KeyTTable *ctx, const uint8_t *pt, uint8_t *ct);

/* ARM Crypto Extension implementation (hardware accelerated) */
void rijndael256_encrypt_arm(const Rijndael256Key *ctx, const uint8_t *pt, uint8_t *ct);

/* NEON SIMD implementation (TBL/TBX based, no hardware AES) */
void rijndael256_encrypt_neon(const Rijndael256Key *ctx, const uint8_t *pt, uint8_t *ct);

/* NEON SIMD 4-block parallel implementation */
void rijndael256_encrypt_neon_4pt(const Rijndael256Key *ctx, const uint8_t *pt, uint8_t *ct);

/* NEON SIMD interleaved 4-block parallel implementation (for performance comparison) */
void rijndael256_encrypt_neon_il_4pt(const Rijndael256Key *ctx, const uint8_t *pt, uint8_t *ct);

/*
 * Decryption Functions
 * All take 32-byte ciphertext and produce 32-byte plaintext
 */

/* Native C implementation */
void rijndael256_decrypt_ref(const Rijndael256Key *ctx, const uint8_t *ct, uint8_t *pt);

/* T-table implementation */
void rijndael256_decrypt_ttable(const Rijndael256KeyTTable *ctx, const uint8_t *ct, uint8_t *pt);

/* ARM Crypto Extension implementation */
void rijndael256_decrypt_arm(const Rijndael256Key *ctx, const uint8_t *ct, uint8_t *pt);

/*
 * Runtime Detection
 */

/* Check if ARM Crypto Extension is available */
int rijndael256_has_arm_crypto(void);

#ifdef __cplusplus
}
#endif

#endif /* RIJNDAEL256_H */
