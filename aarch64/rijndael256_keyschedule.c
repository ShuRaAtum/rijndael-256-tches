/*
 * Rijndael-256 Key Schedule
 *
 * Supports key sizes: 128, 192, 256 bits
 * Block size: 256 bits (Nb = 8)
 */

#include "rijndael256.h"
#include "rijndael256_tables.h"
#include <string.h>

#define Nb 8  /* Number of 32-bit words in block (256/32 = 8) */

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

/* Apply S-Box to each byte of a word */
static uint32_t SubWord(uint32_t w) {
    return ((uint32_t)SBox[(w >> 24) & 0xFF] << 24) |
           ((uint32_t)SBox[(w >> 16) & 0xFF] << 16) |
           ((uint32_t)SBox[(w >> 8) & 0xFF] << 8)  |
           (uint32_t)SBox[w & 0xFF];
}

/* Rotate word left by 8 bits */
static uint32_t RotWord(uint32_t w) {
    return (w << 8) | (w >> 24);
}

/*
 * Setup key for byte-based implementations (reference, ARM)
 * Round keys stored as bytes in big-endian format
 */
int rijndael256_setup_key(const uint8_t *key, int keyBits, Rijndael256Key *ctx) {
    if (keyBits != 128 && keyBits != 192 && keyBits != 256) {
        return -1;
    }

    int Nk = keyBits / 32;  /* Number of 32-bit words in key */
    int Nr = (Nk > Nb ? Nk : Nb) + 6;  /* Number of rounds: max(Nk, 8) + 6 = 14 */
    ctx->rounds = Nr;

    /* Temporary storage for key words */
    uint32_t W[120];  /* Max: (14+1) * 8 = 120 words */

    /* Load initial key words */
    int i = 0;
    while (i < Nk) {
        W[i] = get_word_be(key + 4 * i);
        i++;
    }

    /* Key expansion */
    uint32_t temp;
    while (i < (Nr + 1) * Nb) {
        temp = W[i - 1];
        if (i % Nk == 0) {
            temp = SubWord(RotWord(temp)) ^ Rcon[i / Nk];
        } else if (Nk > 6 && (i % Nk == 4)) {
            temp = SubWord(temp);
        }
        W[i] = W[i - Nk] ^ temp;
        i++;
    }

    /* Store round keys as bytes (big-endian) */
    for (int r = 0; r <= Nr; r++) {
        for (int j = 0; j < Nb; j++) {
            put_word_be(W[r * Nb + j], ctx->roundKeys + r * 32 + j * 4);
        }
    }

    return 0;
}

/*
 * Setup key for T-table implementation
 * Round keys stored as 32-bit words
 */
int rijndael256_setup_key_ttable(const uint8_t *key, int keyBits, Rijndael256KeyTTable *ctx) {
    if (keyBits != 128 && keyBits != 192 && keyBits != 256) {
        return -1;
    }

    int Nk = keyBits / 32;
    int Nr = (Nk > Nb ? Nk : Nb) + 6;
    ctx->rounds = Nr;

    /* Load initial key words */
    int i = 0;
    while (i < Nk) {
        ctx->roundKey[i] = get_word_be(key + 4 * i);
        i++;
    }

    /* Key expansion */
    uint32_t temp;
    while (i < (Nr + 1) * Nb) {
        temp = ctx->roundKey[i - 1];
        if (i % Nk == 0) {
            temp = SubWord(RotWord(temp)) ^ Rcon[i / Nk];
        } else if (Nk > 6 && (i % Nk == 4)) {
            temp = SubWord(temp);
        }
        ctx->roundKey[i] = ctx->roundKey[i - Nk] ^ temp;
        i++;
    }

    return 0;
}
