/*
 * Rijndael-256 Native C Implementation (Baseline)
 * Block Size: 256 bits (Nb = 8)
 * ShiftRows pattern: (0, 1, 3, 4) for 256-bit block
 */

#include "rijndael256_native.h"
#include "rijndael256_sbox.h"
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

/* InvSubWord: apply inverse S-box to each byte of a word */
static inline uint32_t InvSubWord(uint32_t w) {
    return ((uint32_t)InvSBox[(w >> 24) & 0xFF] << 24) |
           ((uint32_t)InvSBox[(w >> 16) & 0xFF] << 16) |
           ((uint32_t)InvSBox[(w >> 8) & 0xFF] << 8)   |
           (uint32_t)InvSBox[w & 0xFF];
}

/* RotWord: rotate word left by 8 bits */
static inline uint32_t RotWord(uint32_t w) {
    return (w << 8) | (w >> 24);
}

/* xtime: multiply by x (i.e., 0x02) in GF(2^8) */
static inline uint8_t xtime(uint8_t x) {
    return (x << 1) ^ (((x >> 7) & 1) * 0x1b);
}

/* Multiply two bytes in GF(2^8) */
static inline uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        uint8_t hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

/*
 * Key expansion for Rijndael-256
 * Nr = max(Nk, Nb) + 6 = max(Nk, 8) + 6
 * For Nk=4 (128-bit): Nr = 14
 * For Nk=6 (192-bit): Nr = 14
 * For Nk=8 (256-bit): Nr = 14
 */
int r256_native_setup_key(const uint8_t *key, int keyBits, R256NativeKey *rk) {
    if (keyBits != 128 && keyBits != 192 && keyBits != 256) {
        return -1;
    }

    int Nk = keyBits / 32;  /* 4, 6, or 8 */
    int Nr = (Nk > Nb ? Nk : Nb) + 6;  /* Always 14 for 256-bit block */
    rk->rounds = Nr;

    /* Copy key bytes to first Nk words */
    int i = 0;
    while (i < Nk) {
        rk->roundKey[i] = get_word_be(key + 4 * i);
        i++;
    }

    /* Expand key */
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
 * Rijndael-256 encryption
 * ShiftRows for 256-bit block: row shifts are (0, 1, 3, 4)
 */
void r256_native_encrypt(const R256NativeKey *rk, const uint8_t *pt, uint8_t *ct) {
    uint8_t state[4][Nb];
    int Nr = rk->rounds;

    /* Load plaintext into state (column-major) */
    for (int c = 0; c < Nb; c++) {
        state[0][c] = pt[4*c + 0];
        state[1][c] = pt[4*c + 1];
        state[2][c] = pt[4*c + 2];
        state[3][c] = pt[4*c + 3];
    }

    /* Initial AddRoundKey */
    for (int c = 0; c < Nb; c++) {
        uint32_t w = rk->roundKey[c];
        state[0][c] ^= (w >> 24) & 0xFF;
        state[1][c] ^= (w >> 16) & 0xFF;
        state[2][c] ^= (w >> 8) & 0xFF;
        state[3][c] ^= w & 0xFF;
    }

    /* Main rounds */
    for (int round = 1; round < Nr; round++) {
        uint8_t tmp[4][Nb];

        /* SubBytes */
        for (int c = 0; c < Nb; c++) {
            for (int r = 0; r < 4; r++) {
                tmp[r][c] = SBox[state[r][c]];
            }
        }

        /* ShiftRows: (0, 1, 3, 4) for 256-bit block */
        uint8_t shifted[4][Nb];
        for (int c = 0; c < Nb; c++) {
            shifted[0][c] = tmp[0][c];                    /* Row 0: no shift */
            shifted[1][c] = tmp[1][(c + 1) % Nb];        /* Row 1: shift 1 */
            shifted[2][c] = tmp[2][(c + 3) % Nb];        /* Row 2: shift 3 */
            shifted[3][c] = tmp[3][(c + 4) % Nb];        /* Row 3: shift 4 */
        }

        /* MixColumns */
        for (int c = 0; c < Nb; c++) {
            uint8_t s0 = shifted[0][c];
            uint8_t s1 = shifted[1][c];
            uint8_t s2 = shifted[2][c];
            uint8_t s3 = shifted[3][c];

            state[0][c] = xtime(s0) ^ xtime(s1) ^ s1 ^ s2 ^ s3;
            state[1][c] = s0 ^ xtime(s1) ^ xtime(s2) ^ s2 ^ s3;
            state[2][c] = s0 ^ s1 ^ xtime(s2) ^ xtime(s3) ^ s3;
            state[3][c] = xtime(s0) ^ s0 ^ s1 ^ s2 ^ xtime(s3);
        }

        /* AddRoundKey */
        const uint32_t *w = rk->roundKey + round * Nb;
        for (int c = 0; c < Nb; c++) {
            state[0][c] ^= (w[c] >> 24) & 0xFF;
            state[1][c] ^= (w[c] >> 16) & 0xFF;
            state[2][c] ^= (w[c] >> 8) & 0xFF;
            state[3][c] ^= w[c] & 0xFF;
        }
    }

    /* Final round (no MixColumns) */
    uint8_t tmp[4][Nb];

    /* SubBytes */
    for (int c = 0; c < Nb; c++) {
        for (int r = 0; r < 4; r++) {
            tmp[r][c] = SBox[state[r][c]];
        }
    }

    /* ShiftRows */
    for (int c = 0; c < Nb; c++) {
        state[0][c] = tmp[0][c];
        state[1][c] = tmp[1][(c + 1) % Nb];
        state[2][c] = tmp[2][(c + 3) % Nb];
        state[3][c] = tmp[3][(c + 4) % Nb];
    }

    /* AddRoundKey */
    const uint32_t *w = rk->roundKey + Nr * Nb;
    for (int c = 0; c < Nb; c++) {
        state[0][c] ^= (w[c] >> 24) & 0xFF;
        state[1][c] ^= (w[c] >> 16) & 0xFF;
        state[2][c] ^= (w[c] >> 8) & 0xFF;
        state[3][c] ^= w[c] & 0xFF;
    }

    /* Store ciphertext */
    for (int c = 0; c < Nb; c++) {
        ct[4*c + 0] = state[0][c];
        ct[4*c + 1] = state[1][c];
        ct[4*c + 2] = state[2][c];
        ct[4*c + 3] = state[3][c];
    }
}

/*
 * Rijndael-256 decryption
 * InvShiftRows for 256-bit block: row shifts are (0, 7, 5, 4)
 */
void r256_native_decrypt(const R256NativeKey *rk, const uint8_t *ct, uint8_t *pt) {
    uint8_t state[4][Nb];
    int Nr = rk->rounds;

    /* Load ciphertext into state */
    for (int c = 0; c < Nb; c++) {
        state[0][c] = ct[4*c + 0];
        state[1][c] = ct[4*c + 1];
        state[2][c] = ct[4*c + 2];
        state[3][c] = ct[4*c + 3];
    }

    /* Initial AddRoundKey (last round key) */
    const uint32_t *w = rk->roundKey + Nr * Nb;
    for (int c = 0; c < Nb; c++) {
        state[0][c] ^= (w[c] >> 24) & 0xFF;
        state[1][c] ^= (w[c] >> 16) & 0xFF;
        state[2][c] ^= (w[c] >> 8) & 0xFF;
        state[3][c] ^= w[c] & 0xFF;
    }

    /* Main rounds (reverse order) */
    for (int round = Nr - 1; round >= 1; round--) {
        uint8_t tmp[4][Nb];

        /* InvShiftRows: (0, 7, 5, 4) = inverse of (0, 1, 3, 4) */
        for (int c = 0; c < Nb; c++) {
            tmp[0][c] = state[0][c];
            tmp[1][c] = state[1][(c + 7) % Nb];  /* -1 mod 8 = 7 */
            tmp[2][c] = state[2][(c + 5) % Nb];  /* -3 mod 8 = 5 */
            tmp[3][c] = state[3][(c + 4) % Nb];  /* -4 mod 8 = 4 */
        }

        /* InvSubBytes */
        for (int c = 0; c < Nb; c++) {
            for (int r = 0; r < 4; r++) {
                state[r][c] = InvSBox[tmp[r][c]];
            }
        }

        /* AddRoundKey */
        w = rk->roundKey + round * Nb;
        for (int c = 0; c < Nb; c++) {
            state[0][c] ^= (w[c] >> 24) & 0xFF;
            state[1][c] ^= (w[c] >> 16) & 0xFF;
            state[2][c] ^= (w[c] >> 8) & 0xFF;
            state[3][c] ^= w[c] & 0xFF;
        }

        /* InvMixColumns */
        for (int c = 0; c < Nb; c++) {
            uint8_t s0 = state[0][c];
            uint8_t s1 = state[1][c];
            uint8_t s2 = state[2][c];
            uint8_t s3 = state[3][c];

            state[0][c] = gmul(s0, 0x0e) ^ gmul(s1, 0x0b) ^ gmul(s2, 0x0d) ^ gmul(s3, 0x09);
            state[1][c] = gmul(s0, 0x09) ^ gmul(s1, 0x0e) ^ gmul(s2, 0x0b) ^ gmul(s3, 0x0d);
            state[2][c] = gmul(s0, 0x0d) ^ gmul(s1, 0x09) ^ gmul(s2, 0x0e) ^ gmul(s3, 0x0b);
            state[3][c] = gmul(s0, 0x0b) ^ gmul(s1, 0x0d) ^ gmul(s2, 0x09) ^ gmul(s3, 0x0e);
        }
    }

    /* Final round (no InvMixColumns) */
    uint8_t tmp[4][Nb];

    /* InvShiftRows */
    for (int c = 0; c < Nb; c++) {
        tmp[0][c] = state[0][c];
        tmp[1][c] = state[1][(c + 7) % Nb];
        tmp[2][c] = state[2][(c + 5) % Nb];
        tmp[3][c] = state[3][(c + 4) % Nb];
    }

    /* InvSubBytes */
    for (int c = 0; c < Nb; c++) {
        for (int r = 0; r < 4; r++) {
            state[r][c] = InvSBox[tmp[r][c]];
        }
    }

    /* AddRoundKey (first round key) */
    w = rk->roundKey;
    for (int c = 0; c < Nb; c++) {
        state[0][c] ^= (w[c] >> 24) & 0xFF;
        state[1][c] ^= (w[c] >> 16) & 0xFF;
        state[2][c] ^= (w[c] >> 8) & 0xFF;
        state[3][c] ^= w[c] & 0xFF;
    }

    /* Store plaintext */
    for (int c = 0; c < Nb; c++) {
        pt[4*c + 0] = state[0][c];
        pt[4*c + 1] = state[1][c];
        pt[4*c + 2] = state[2][c];
        pt[4*c + 3] = state[3][c];
    }
}
