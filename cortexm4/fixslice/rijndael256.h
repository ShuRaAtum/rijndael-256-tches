/*
 * Rijndael-256 Fixsliced Implementation Header
 * Block Size: 256 bits (Nb = 8), Nr = 14 for all key sizes
 *
 * Round keys are stored in bitplane-packed form with position rotation
 * applied to inner round keys (K1..K(Nr-1)).
 */

#ifndef R256_FIXSLICE_H
#define R256_FIXSLICE_H

#include <stdint.h>

#define R256_NB     8
#define R256_MAX_NR 14

typedef struct {
    uint32_t roundKey[(R256_MAX_NR + 1) * R256_NB]; /* 120 words */
    int rounds;
} R256Key;

void r256_pack(const uint8_t bytes[32], uint32_t state[8]);
int  r256_setup_key(const uint8_t *key, int keyBits, R256Key *rk);

#endif /* R256_FIXSLICE_H */
