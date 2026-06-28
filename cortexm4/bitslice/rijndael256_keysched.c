/*
 * Rijndael-256 Bitsliced Key Schedule
 *
 * Produces bitplane-packed round keys in canonical form
 * (no position rotation, used by both bitslice ASM and reference).
 */

#include "rijndael256.h"
#include <string.h>

static const uint8_t SBox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
};

static const uint32_t Rcon[30] = {
    0x00000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000,
    0x36000000, 0x6c000000, 0xd8000000, 0xab000000, 0x4d000000,
    0x9a000000, 0x2f000000, 0x5e000000, 0xbc000000, 0x63000000,
    0xc6000000, 0x97000000, 0x35000000, 0x6a000000, 0xd4000000,
    0xb3000000, 0x7d000000, 0xfa000000, 0xef000000, 0xc5000000,
};

#define SWAPMOVE(a, b, mask, n) do { \
    uint32_t t = ((b) ^ ((a) >> (n))) & (mask); \
    (b) ^= t; \
    (a) ^= t << (n); \
} while(0)

static inline uint32_t get_word_be(const uint8_t *b) {
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8) | (uint32_t)b[3];
}

static inline void put_word_be(uint32_t w, uint8_t *b) {
    b[0] = (uint8_t)(w >> 24); b[1] = (uint8_t)(w >> 16);
    b[2] = (uint8_t)(w >> 8);  b[3] = (uint8_t)w;
}

static inline uint32_t SubWord(uint32_t w) {
    return ((uint32_t)SBox[(w >> 24) & 0xFF] << 24) |
           ((uint32_t)SBox[(w >> 16) & 0xFF] << 16) |
           ((uint32_t)SBox[(w >> 8) & 0xFF] << 8) |
           (uint32_t)SBox[w & 0xFF];
}

static inline uint32_t RotWord(uint32_t w) {
    return (w << 8) | (w >> 24);
}

void r256_pack(const uint8_t bytes[32], uint32_t state[8])
{
    for (int i = 0; i < 8; i++)
        state[i] = get_word_be(bytes + 4 * i);

    SWAPMOVE(state[1], state[0], 0x55555555, 1);
    SWAPMOVE(state[3], state[2], 0x55555555, 1);
    SWAPMOVE(state[5], state[4], 0x55555555, 1);
    SWAPMOVE(state[7], state[6], 0x55555555, 1);

    SWAPMOVE(state[2], state[0], 0x33333333, 2);
    SWAPMOVE(state[3], state[1], 0x33333333, 2);
    SWAPMOVE(state[6], state[4], 0x33333333, 2);
    SWAPMOVE(state[7], state[5], 0x33333333, 2);

    SWAPMOVE(state[4], state[0], 0x0f0f0f0f, 4);
    SWAPMOVE(state[5], state[1], 0x0f0f0f0f, 4);
    SWAPMOVE(state[6], state[2], 0x0f0f0f0f, 4);
    SWAPMOVE(state[7], state[3], 0x0f0f0f0f, 4);
}

int r256_setup_key(const uint8_t *key, int keyBits, R256Key *rk)
{
    if (keyBits != 128 && keyBits != 192 && keyBits != 256)
        return -1;

    int Nk = keyBits / 32;
    int Nr = (Nk > R256_NB ? Nk : R256_NB) + 6;
    rk->rounds = Nr;

    uint32_t W[(R256_MAX_NR + 1) * R256_NB];
    int i = 0;
    while (i < Nk) {
        W[i] = get_word_be(key + 4 * i);
        i++;
    }
    while (i < (Nr + 1) * R256_NB) {
        uint32_t temp = W[i - 1];
        if (i % Nk == 0)
            temp = SubWord(RotWord(temp)) ^ Rcon[i / Nk];
        else if (Nk > 6 && (i % Nk == 4))
            temp = SubWord(temp);
        W[i] = W[i - Nk] ^ temp;
        i++;
    }

    for (int r = 0; r <= Nr; r++) {
        uint8_t rk_bytes[32];
        for (int j = 0; j < R256_NB; j++)
            put_word_be(W[r * R256_NB + j], rk_bytes + 4 * j);
        r256_pack(rk_bytes, &rk->roundKey[r * R256_NB]);
    }

    return 0;
}

/* GF(2^8) multiply by 2 (xtime) */
static inline uint8_t xtime(uint8_t a) {
    return (uint8_t)((a << 1) ^ ((a >> 7) * 0x1b));
}

/* GF(2^8) InvMixColumns on a single 32-bit word (big-endian) */
static uint32_t InvMixColumnWord(uint32_t w) {
    uint8_t b0 = (uint8_t)(w >> 24), b1 = (uint8_t)(w >> 16);
    uint8_t b2 = (uint8_t)(w >> 8),  b3 = (uint8_t)w;
    /* {0e}*bi = x8^x4^x2, {0b}*bi = x8^x2^x1, {0d}*bi = x8^x4^x1, {09}*bi = x8^x1 */
    uint8_t x2[4] = { xtime(b0), xtime(b1), xtime(b2), xtime(b3) };
    uint8_t x4[4] = { xtime(x2[0]), xtime(x2[1]), xtime(x2[2]), xtime(x2[3]) };
    uint8_t x8[4] = { xtime(x4[0]), xtime(x4[1]), xtime(x4[2]), xtime(x4[3]) };
    uint8_t d0 = (x8[0]^x4[0]^x2[0]) ^ (x8[1]^x2[1]^b1) ^ (x8[2]^x4[2]^b2) ^ (x8[3]^b3);
    uint8_t d1 = (x8[0]^b0) ^ (x8[1]^x4[1]^x2[1]) ^ (x8[2]^x2[2]^b2) ^ (x8[3]^x4[3]^b3);
    uint8_t d2 = (x8[0]^x4[0]^b0) ^ (x8[1]^b1) ^ (x8[2]^x4[2]^x2[2]) ^ (x8[3]^x2[3]^b3);
    uint8_t d3 = (x8[0]^x2[0]^b0) ^ (x8[1]^x4[1]^b1) ^ (x8[2]^b2) ^ (x8[3]^x4[3]^x2[3]);
    return ((uint32_t)d0 << 24) | ((uint32_t)d1 << 16) | ((uint32_t)d2 << 8) | d3;
}

/*
 * Decrypt key schedule: Equivalent Inverse Cipher
 *
 * - Reverse key order: decrypt round r uses encrypt key (Nr-r)
 * - Apply InvMixColumns to middle keys (byte domain) for rounds 1..Nr-1
 * - Absorb inverse S-box NOT (plane 7) into keys 0..Nr-1
 */
int r256_setup_decrypt_key(const uint8_t *key, int keyBits, R256Key *rk)
{
    if (keyBits != 128 && keyBits != 192 && keyBits != 256)
        return -1;

    int Nk = keyBits / 32;
    int Nr = (Nk > R256_NB ? Nk : R256_NB) + 6;
    rk->rounds = Nr;

    /* Standard key expansion */
    uint32_t W[(R256_MAX_NR + 1) * R256_NB];
    int i = 0;
    while (i < Nk) {
        W[i] = get_word_be(key + 4 * i);
        i++;
    }
    while (i < (Nr + 1) * R256_NB) {
        uint32_t temp = W[i - 1];
        if (i % Nk == 0)
            temp = SubWord(RotWord(temp)) ^ Rcon[i / Nk];
        else if (Nk > 6 && (i % Nk == 4))
            temp = SubWord(temp);
        W[i] = W[i - Nk] ^ temp;
        i++;
    }

    /* Build decrypt round keys in reversed order */
    for (int r = 0; r <= Nr; r++) {
        int enc_r = Nr - r;  /* encrypt key index */
        uint8_t rk_bytes[32];
        uint32_t bp[8];

        if (r >= 1 && r <= Nr - 1) {
            /* Middle keys: apply InvMixColumns (byte domain) then pack */
            for (int j = 0; j < R256_NB; j++) {
                uint32_t w = W[enc_r * R256_NB + j];
                put_word_be(InvMixColumnWord(w), rk_bytes + 4 * j);
            }
        } else {
            /* First and last keys: no InvMixColumns */
            for (int j = 0; j < R256_NB; j++)
                put_word_be(W[enc_r * R256_NB + j], rk_bytes + 4 * j);
        }

        r256_pack(rk_bytes, bp);

        /* Absorb inverse S-box constants into key schedule.
         *
         * InvSBox = InvAffine ∘ ForwardSBox ∘ InvAffine
         * The first InvAffine has constant d=0x05 (2 NOTs on planes 5,7).
         * ForwardSBox has constant c=0x63 (4 XNORs on planes 1,2,6,7).
         * The second InvAffine has constant d=0x05.
         * Since A*d = c, all constants cancel if we absorb A*d = 0x63
         * into the round key: flip planes 1,2,6,7 for keys 0..Nr-1.
         */
        if (r < Nr) {
            bp[1] ^= 0xFFFFFFFF;
            bp[2] ^= 0xFFFFFFFF;
            bp[6] ^= 0xFFFFFFFF;
            bp[7] ^= 0xFFFFFFFF;
        }

        for (int j = 0; j < 8; j++)
            rk->roundKey[r * R256_NB + j] = bp[j];
    }

    return 0;
}
