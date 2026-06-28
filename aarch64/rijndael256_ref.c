/*
 * Rijndael-256 Native C Reference Implementation
 *
 * Block Size: 256 bits (32 bytes)
 * Key Sizes: 128, 192, 256 bits
 *
 * This is a straightforward implementation without optimizations,
 * intended as a reference for correctness verification.
 */

#include "rijndael256.h"
#include "rijndael256_tables.h"
#include <string.h>

#define Nb 8  /* Number of 32-bit words in state */

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

/* GF(2^8) multiplication by 2 */
static uint8_t xtime(uint8_t x) {
    return (x << 1) ^ ((x >> 7) * 0x1b);
}

/* GF(2^8) multiplication */
static uint8_t gmul(uint8_t a, uint8_t b) {
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
 * SubBytes: Apply S-Box to each byte of state
 */
static void SubBytes(uint8_t state[4][Nb]) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < Nb; j++) {
            state[i][j] = SBox[state[i][j]];
        }
    }
}

/*
 * InvSubBytes: Apply inverse S-Box to each byte of state
 */
static void InvSubBytes(uint8_t state[4][Nb]) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < Nb; j++) {
            state[i][j] = InvSBox[state[i][j]];
        }
    }
}

/*
 * ShiftRows for Rijndael-256: shifts are (0, 1, 3, 4)
 * - Row 0: no shift
 * - Row 1: shift left by 1
 * - Row 2: shift left by 3
 * - Row 3: shift left by 4
 */
static void ShiftRows(uint8_t state[4][Nb]) {
    uint8_t temp[Nb];

    /* Row 1: shift left by 1 */
    for (int j = 0; j < Nb; j++) temp[j] = state[1][(j + 1) % Nb];
    for (int j = 0; j < Nb; j++) state[1][j] = temp[j];

    /* Row 2: shift left by 3 */
    for (int j = 0; j < Nb; j++) temp[j] = state[2][(j + 3) % Nb];
    for (int j = 0; j < Nb; j++) state[2][j] = temp[j];

    /* Row 3: shift left by 4 */
    for (int j = 0; j < Nb; j++) temp[j] = state[3][(j + 4) % Nb];
    for (int j = 0; j < Nb; j++) state[3][j] = temp[j];
}

/*
 * InvShiftRows for Rijndael-256: inverse shifts are (0, 7, 5, 4) mod 8
 * - Row 0: no shift
 * - Row 1: shift right by 1 = shift left by 7
 * - Row 2: shift right by 3 = shift left by 5
 * - Row 3: shift right by 4 = shift left by 4
 */
static void InvShiftRows(uint8_t state[4][Nb]) {
    uint8_t temp[Nb];

    /* Row 1: shift left by 7 (right by 1) */
    for (int j = 0; j < Nb; j++) temp[j] = state[1][(j + 7) % Nb];
    for (int j = 0; j < Nb; j++) state[1][j] = temp[j];

    /* Row 2: shift left by 5 (right by 3) */
    for (int j = 0; j < Nb; j++) temp[j] = state[2][(j + 5) % Nb];
    for (int j = 0; j < Nb; j++) state[2][j] = temp[j];

    /* Row 3: shift left by 4 (right by 4) */
    for (int j = 0; j < Nb; j++) temp[j] = state[3][(j + 4) % Nb];
    for (int j = 0; j < Nb; j++) state[3][j] = temp[j];
}

/*
 * MixColumns: Mix each column using matrix multiplication in GF(2^8)
 * Matrix: [2 3 1 1]
 *         [1 2 3 1]
 *         [1 1 2 3]
 *         [3 1 1 2]
 */
static void MixColumns(uint8_t state[4][Nb]) {
    for (int j = 0; j < Nb; j++) {
        uint8_t a0 = state[0][j];
        uint8_t a1 = state[1][j];
        uint8_t a2 = state[2][j];
        uint8_t a3 = state[3][j];

        state[0][j] = xtime(a0) ^ xtime(a1) ^ a1 ^ a2 ^ a3;
        state[1][j] = a0 ^ xtime(a1) ^ xtime(a2) ^ a2 ^ a3;
        state[2][j] = a0 ^ a1 ^ xtime(a2) ^ xtime(a3) ^ a3;
        state[3][j] = xtime(a0) ^ a0 ^ a1 ^ a2 ^ xtime(a3);
    }
}

/*
 * InvMixColumns: Inverse mix columns
 * Matrix: [0e 0b 0d 09]
 *         [09 0e 0b 0d]
 *         [0d 09 0e 0b]
 *         [0b 0d 09 0e]
 */
static void InvMixColumns(uint8_t state[4][Nb]) {
    for (int j = 0; j < Nb; j++) {
        uint8_t a0 = state[0][j];
        uint8_t a1 = state[1][j];
        uint8_t a2 = state[2][j];
        uint8_t a3 = state[3][j];

        state[0][j] = gmul(a0, 0x0e) ^ gmul(a1, 0x0b) ^ gmul(a2, 0x0d) ^ gmul(a3, 0x09);
        state[1][j] = gmul(a0, 0x09) ^ gmul(a1, 0x0e) ^ gmul(a2, 0x0b) ^ gmul(a3, 0x0d);
        state[2][j] = gmul(a0, 0x0d) ^ gmul(a1, 0x09) ^ gmul(a2, 0x0e) ^ gmul(a3, 0x0b);
        state[3][j] = gmul(a0, 0x0b) ^ gmul(a1, 0x0d) ^ gmul(a2, 0x09) ^ gmul(a3, 0x0e);
    }
}

/*
 * AddRoundKey: XOR state with round key
 */
static void AddRoundKey(uint8_t state[4][Nb], const uint8_t *roundKey) {
    for (int j = 0; j < Nb; j++) {
        state[0][j] ^= roundKey[j * 4 + 0];
        state[1][j] ^= roundKey[j * 4 + 1];
        state[2][j] ^= roundKey[j * 4 + 2];
        state[3][j] ^= roundKey[j * 4 + 3];
    }
}

/*
 * Rijndael-256 Encryption (Reference Implementation)
 */
void rijndael256_encrypt_ref(const Rijndael256Key *ctx, const uint8_t *pt, uint8_t *ct) {
    uint8_t state[4][Nb];
    int Nr = ctx->rounds;

    /* Load plaintext into state (column-major) */
    for (int j = 0; j < Nb; j++) {
        state[0][j] = pt[j * 4 + 0];
        state[1][j] = pt[j * 4 + 1];
        state[2][j] = pt[j * 4 + 2];
        state[3][j] = pt[j * 4 + 3];
    }

    /* Initial AddRoundKey */
    AddRoundKey(state, ctx->roundKeys);

    /* Main rounds */
    for (int r = 1; r < Nr; r++) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, ctx->roundKeys + r * 32);
    }

    /* Final round (no MixColumns) */
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, ctx->roundKeys + Nr * 32);

    /* Store state to ciphertext */
    for (int j = 0; j < Nb; j++) {
        ct[j * 4 + 0] = state[0][j];
        ct[j * 4 + 1] = state[1][j];
        ct[j * 4 + 2] = state[2][j];
        ct[j * 4 + 3] = state[3][j];
    }
}

/*
 * Rijndael-256 Decryption (Reference Implementation)
 */
void rijndael256_decrypt_ref(const Rijndael256Key *ctx, const uint8_t *ct, uint8_t *pt) {
    uint8_t state[4][Nb];
    int Nr = ctx->rounds;

    /* Load ciphertext into state (column-major) */
    for (int j = 0; j < Nb; j++) {
        state[0][j] = ct[j * 4 + 0];
        state[1][j] = ct[j * 4 + 1];
        state[2][j] = ct[j * 4 + 2];
        state[3][j] = ct[j * 4 + 3];
    }

    /* Initial AddRoundKey (with last round key) */
    AddRoundKey(state, ctx->roundKeys + Nr * 32);

    /* Main rounds (in reverse) */
    for (int r = Nr - 1; r >= 1; r--) {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, ctx->roundKeys + r * 32);
        InvMixColumns(state);
    }

    /* Final round (no InvMixColumns) */
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, ctx->roundKeys);

    /* Store state to plaintext */
    for (int j = 0; j < Nb; j++) {
        pt[j * 4 + 0] = state[0][j];
        pt[j * 4 + 1] = state[1][j];
        pt[j * 4 + 2] = state[2][j];
        pt[j * 4 + 3] = state[3][j];
    }
}
