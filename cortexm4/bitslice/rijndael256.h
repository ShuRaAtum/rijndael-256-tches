/*
 * Rijndael-256 Bitsliced Implementation Header
 * Block Size: 256 bits (Nb = 8), Nr = 14 for all key sizes
 *
 * Round keys are stored in bitplane-packed form (8 planes per round key).
 */

#ifndef R256_BITSLICE_H
#define R256_BITSLICE_H

#include <stdint.h>

#define R256_NB     8
#define R256_MAX_NR 14

typedef struct {
    uint32_t roundKey[(R256_MAX_NR + 1) * R256_NB]; /* 120 words */
    int rounds;
} R256Key;

void r256_pack(const uint8_t bytes[32], uint32_t state[8]);
int  r256_setup_key(const uint8_t *key, int keyBits, R256Key *rk);
int  r256_setup_decrypt_key(const uint8_t *key, int keyBits, R256Key *rk);
void rijndael256_decrypt_ref(const R256Key *rk, const uint8_t *ct, uint8_t *pt);

#endif /* R256_BITSLICE_H */
