/*
 * Rijndael-256 T-table Implementation Header
 * Block Size: 256 bits (Nb = 8), Nr = 14 for all key sizes
 *
 * WARNING: NOT constant-time. Vulnerable to cache-timing attacks.
 */

#ifndef RIJNDAEL256_TTABLE_H
#define RIJNDAEL256_TTABLE_H

#include <stdint.h>

#define R256_BLOCK_SIZE 32
#define R256_NB         8
#define R256_MAX_NR     14

typedef struct {
    uint32_t roundKey[120]; /* (14+1) * 8 = 120 words max */
    int rounds;
} R256TtableKey;

int  r256_ttable_setup_key(const uint8_t *key, int keyBits, R256TtableKey *rk);
void r256_ttable_encrypt(const R256TtableKey *rk, const uint8_t *pt, uint8_t *ct);
void r256_ttable_decrypt(const R256TtableKey *rk, const uint8_t *ct, uint8_t *pt);

#endif /* RIJNDAEL256_TTABLE_H */
