/*
 * Rijndael-256 T-Table Implementation
 *
 * Block Size: 256 bits (32 bytes)
 * Key Sizes: 128, 192, 256 bits
 *
 * Uses pre-computed T-tables to combine SubBytes, ShiftRows, and MixColumns
 * into single table lookups for better performance.
 */

#include "rijndael256.h"
#include "rijndael256_tables.h"
#include <string.h>

#define Nb 8  /* Number of 32-bit words in block */

/* Helper: Load 32-bit big-endian word */
static uint32_t get_word_be(const uint8_t *b) {
    return ((uint32_t)b[0] << 24) |
           ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8)  |
           (uint32_t)b[3];
}

/* Helper: Store 32-bit big-endian word */
static void put_word_be(uint32_t w, uint8_t *b) {
    b[0] = (w >> 24) & 0xFF;
    b[1] = (w >> 16) & 0xFF;
    b[2] = (w >> 8) & 0xFF;
    b[3] = w & 0xFF;
}

/* Apply InvMixColumns to a single word (for decryption key transformation) */
static uint32_t InvMixColumnWord(uint32_t w) {
    return InvMix0[(w >> 24) & 0xFF] ^
           InvMix1[(w >> 16) & 0xFF] ^
           InvMix2[(w >> 8) & 0xFF]  ^
           InvMix3[w & 0xFF];
}

/*
 * Rijndael-256 Encryption using T-Tables
 *
 * Rijndael-256 ShiftRows pattern: (0, 1, 3, 4)
 * - Column i, Row 0: takes from column i
 * - Column i, Row 1: takes from column (i+1) mod 8
 * - Column i, Row 2: takes from column (i+3) mod 8
 * - Column i, Row 3: takes from column (i+4) mod 8
 */
void rijndael256_encrypt_ttable(const Rijndael256KeyTTable *ctx, const uint8_t *pt, uint8_t *ct) {
    uint32_t s[Nb];
    uint32_t t[Nb];
    int Nr = ctx->rounds;

    /* Load plaintext into state */
    for (int i = 0; i < Nb; i++) {
        s[i] = get_word_be(pt + 4 * i);
    }

    /* Initial AddRoundKey */
    for (int i = 0; i < Nb; i++) {
        s[i] ^= ctx->roundKey[i];
    }

    /* Main rounds 1 to Nr-1 */
    const uint32_t *w = ctx->roundKey + Nb;
    for (int r = 1; r < Nr; r++) {
        for (int i = 0; i < Nb; i++) {
            /* T-table lookup combines SubBytes + ShiftRows + MixColumns */
            /* ShiftRows offsets for Rijndael-256: 0, 1, 3, 4 */
            t[i] = Te0[(s[i] >> 24) & 0xFF] ^
                   Te1[(s[(i + 1) % Nb] >> 16) & 0xFF] ^
                   Te2[(s[(i + 3) % Nb] >> 8) & 0xFF] ^
                   Te3[(s[(i + 4) % Nb]) & 0xFF] ^
                   w[i];
        }
        memcpy(s, t, sizeof(s));
        w += Nb;
    }

    /* Final round (no MixColumns, use S-Box directly) */
    for (int i = 0; i < Nb; i++) {
        uint8_t b0 = SBox[(s[i] >> 24) & 0xFF];
        uint8_t b1 = SBox[(s[(i + 1) % Nb] >> 16) & 0xFF];
        uint8_t b2 = SBox[(s[(i + 3) % Nb] >> 8) & 0xFF];
        uint8_t b3 = SBox[(s[(i + 4) % Nb]) & 0xFF];

        t[i] = ((uint32_t)b0 << 24) |
               ((uint32_t)b1 << 16) |
               ((uint32_t)b2 << 8)  |
               (uint32_t)b3;

        t[i] ^= w[i];
    }

    /* Store ciphertext */
    for (int i = 0; i < Nb; i++) {
        put_word_be(t[i], ct + 4 * i);
    }
}

/*
 * Rijndael-256 Decryption using T-Tables
 *
 * Inverse ShiftRows pattern: (0, 7, 5, 4) mod 8
 * - Column i, Row 0: takes from column i
 * - Column i, Row 1: takes from column (i+7) mod 8 = (i-1) mod 8
 * - Column i, Row 2: takes from column (i+5) mod 8 = (i-3) mod 8
 * - Column i, Row 3: takes from column (i+4) mod 8 = (i-4) mod 8
 */
void rijndael256_decrypt_ttable(const Rijndael256KeyTTable *ctx, const uint8_t *ct, uint8_t *pt) {
    uint32_t s[Nb];
    uint32_t t[Nb];
    int Nr = ctx->rounds;

    /* Prepare decryption keys: transform middle round keys with InvMixColumns */
    uint32_t decKeys[120];
    for (int i = 0; i < (Nr + 1) * Nb; i++) {
        decKeys[i] = ctx->roundKey[i];
    }
    for (int r = 1; r < Nr; r++) {
        for (int i = 0; i < Nb; i++) {
            decKeys[r * Nb + i] = InvMixColumnWord(decKeys[r * Nb + i]);
        }
    }

    /* Load ciphertext into state */
    for (int i = 0; i < Nb; i++) {
        s[i] = get_word_be(ct + 4 * i);
    }

    /* Initial AddRoundKey (with last round key) */
    const uint32_t *w = decKeys + Nr * Nb;
    for (int i = 0; i < Nb; i++) {
        s[i] ^= w[i];
    }
    w -= Nb;

    /* Main rounds Nr-1 down to 1 */
    for (int r = Nr - 1; r >= 1; r--) {
        for (int i = 0; i < Nb; i++) {
            /* T-table lookup combines InvSubBytes + InvShiftRows + InvMixColumns */
            /* Inverse ShiftRows offsets: 0, 7, 5, 4 */
            t[i] = Td0[(s[i] >> 24) & 0xFF] ^
                   Td1[(s[(i + 7) % Nb] >> 16) & 0xFF] ^
                   Td2[(s[(i + 5) % Nb] >> 8) & 0xFF] ^
                   Td3[(s[(i + 4) % Nb]) & 0xFF] ^
                   w[i];
        }
        memcpy(s, t, sizeof(s));
        w -= Nb;
    }

    /* Final round (no InvMixColumns, use InvSBox directly) */
    for (int i = 0; i < Nb; i++) {
        uint8_t b0 = InvSBox[(s[i] >> 24) & 0xFF];
        uint8_t b1 = InvSBox[(s[(i + 7) % Nb] >> 16) & 0xFF];
        uint8_t b2 = InvSBox[(s[(i + 5) % Nb] >> 8) & 0xFF];
        uint8_t b3 = InvSBox[(s[(i + 4) % Nb]) & 0xFF];

        t[i] = ((uint32_t)b0 << 24) |
               ((uint32_t)b1 << 16) |
               ((uint32_t)b2 << 8)  |
               (uint32_t)b3;

        t[i] ^= w[i];
    }

    /* Store plaintext */
    for (int i = 0; i < Nb; i++) {
        put_word_be(t[i], pt + 4 * i);
    }
}
