/*
 * Rijndael-256 T-table Implementation
 * Block Size: 256 bits (Nb = 8)
 * ShiftRows pattern: (0, 1, 3, 4) for 256-bit block
 *
 * WARNING: This implementation is NOT constant-time and is vulnerable
 * to cache-timing attacks. Use bitslice or fixslicing for secure applications.
 */

#include "rijndael256_ttable.h"
#include "rijndael256_tables.h"
#include <string.h>

#define Nb 8  /* Number of 32-bit words in block */

/* Load 32-bit big-endian word */
static inline uint32_t get_word_be(const uint8_t *b) {
    return ((uint32_t)b[0] << 24) |
           ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8)  |
           (uint32_t)b[3];
}

/* Store 32-bit big-endian word */
static inline void put_word_be(uint32_t w, uint8_t *b) {
    b[0] = (uint8_t)(w >> 24);
    b[1] = (uint8_t)(w >> 16);
    b[2] = (uint8_t)(w >> 8);
    b[3] = (uint8_t)w;
}

/* SubWord: apply S-box to each byte of a word */
static inline uint32_t SubWord(uint32_t w) {
    return ((uint32_t)SBox[(w >> 24) & 0xFF] << 24) |
           ((uint32_t)SBox[(w >> 16) & 0xFF] << 16) |
           ((uint32_t)SBox[(w >> 8) & 0xFF] << 8)   |
           (uint32_t)SBox[w & 0xFF];
}

/* RotWord: rotate word left by 8 bits */
static inline uint32_t RotWord(uint32_t w) {
    return (w << 8) | (w >> 24);
}

/* InvMixColumn for a single word using InvMix tables */
static inline uint32_t InvMixColumnWord(uint32_t w) {
    return InvMix0[(w >> 24) & 0xFF] ^
           InvMix1[(w >> 16) & 0xFF] ^
           InvMix2[(w >> 8) & 0xFF]  ^
           InvMix3[w & 0xFF];
}

/*
 * Key expansion (same as native implementation)
 */
int r256_ttable_setup_key(const uint8_t *key, int keyBits, R256TtableKey *rk) {
    if (keyBits != 128 && keyBits != 192 && keyBits != 256) {
        return -1;
    }

    int Nk = keyBits / 32;
    int Nr = (Nk > Nb ? Nk : Nb) + 6;
    rk->rounds = Nr;

    int i = 0;
    while (i < Nk) {
        rk->roundKey[i] = get_word_be(key + 4 * i);
        i++;
    }

    uint32_t temp;
    while (i < (Nr + 1) * Nb) {
        temp = rk->roundKey[i - 1];
        if (i % Nk == 0) {
            temp = SubWord(RotWord(temp)) ^ Rcon[i / Nk];
        } else if (Nk > 6 && (i % Nk == 4)) {
            temp = SubWord(temp);
        }
        rk->roundKey[i] = rk->roundKey[i - Nk] ^ temp;
        i++;
    }

    return 0;
}

/*
 * T-table encryption
 * ShiftRows for 256-bit block: (0, 1, 3, 4)
 *
 * Each T-table lookup combines SubBytes + ShiftRows + MixColumns for one column
 */
void r256_ttable_encrypt(const R256TtableKey *rk, const uint8_t *pt, uint8_t *ct) {
    uint32_t s[Nb];
    uint32_t t[Nb];
    int Nr = rk->rounds;

    /* Load plaintext and apply initial AddRoundKey */
    for (int i = 0; i < Nb; i++) {
        s[i] = get_word_be(pt + 4 * i) ^ rk->roundKey[i];
    }

    /* Main rounds with T-tables */
    const uint32_t *w = rk->roundKey + Nb;
    for (int round = 1; round < Nr; round++) {
        /*
         * T-table lookup: Te[i] combines SubBytes, partial ShiftRows, and MixColumns
         * ShiftRows pattern for 256-bit: (0, 1, 3, 4)
         * Row 0: no shift
         * Row 1: shift by 1
         * Row 2: shift by 3
         * Row 3: shift by 4
         */
        for (int i = 0; i < Nb; i++) {
            t[i] = Te0[(s[i] >> 24) & 0xFF] ^
                   Te1[(s[(i + 1) % Nb] >> 16) & 0xFF] ^
                   Te2[(s[(i + 3) % Nb] >> 8) & 0xFF]  ^
                   Te3[(s[(i + 4) % Nb]) & 0xFF]       ^
                   w[i];
        }
        memcpy(s, t, sizeof(s));
        w += Nb;
    }

    /* Final round (no MixColumns) */
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
 * T-table decryption
 * InvShiftRows for 256-bit block: (0, 7, 5, 4)
 */
void r256_ttable_decrypt(const R256TtableKey *rk, const uint8_t *ct, uint8_t *pt) {
    uint32_t s[Nb];
    uint32_t t[Nb];
    int Nr = rk->rounds;

    /* Prepare transformed decryption keys */
    uint32_t decKeys[120];
    for (int i = 0; i < (Nr + 1) * Nb; i++) {
        decKeys[i] = rk->roundKey[i];
    }

    /* Transform middle round keys with InvMixColumns */
    for (int r = 1; r < Nr; r++) {
        for (int i = 0; i < Nb; i++) {
            decKeys[r * Nb + i] = InvMixColumnWord(decKeys[r * Nb + i]);
        }
    }

    /* Load ciphertext and apply initial AddRoundKey (last round key) */
    const uint32_t *w = decKeys + Nr * Nb;
    for (int i = 0; i < Nb; i++) {
        s[i] = get_word_be(ct + 4 * i) ^ w[i];
    }
    w -= Nb;

    /* Main rounds with T-tables (reverse) */
    for (int round = Nr - 1; round >= 1; round--) {
        /*
         * Inverse T-table lookup
         * InvShiftRows pattern for 256-bit: (0, 7, 5, 4)
         * Row 0: no shift
         * Row 1: shift by -1 mod 8 = 7
         * Row 2: shift by -3 mod 8 = 5
         * Row 3: shift by -4 mod 8 = 4
         */
        for (int i = 0; i < Nb; i++) {
            t[i] = Td0[(s[i] >> 24) & 0xFF] ^
                   Td1[(s[(i + 7) % Nb] >> 16) & 0xFF] ^
                   Td2[(s[(i + 5) % Nb] >> 8) & 0xFF]  ^
                   Td3[(s[(i + 4) % Nb]) & 0xFF]       ^
                   w[i];
        }
        memcpy(s, t, sizeof(s));
        w -= Nb;
    }

    /* Final round (no InvMixColumns) */
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
