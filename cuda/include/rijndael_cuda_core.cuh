#ifndef RIJNDAEL_CUDA_CORE_CUH
#define RIJNDAEL_CUDA_CORE_CUH

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <cuda_runtime.h>
#include "rijndael.h"

/*
 * Rijndael-256 CUDA Core
 *
 * Device-level encrypt/decrypt block functions for V2 and V3 kernels.
 * V2: 4 separate T-tables in shared memory (8 KiB)
 * V3: single Te0/Td0 replicated across 32 banks (32 KiB), derive Te1-Te3
 *     via __byte_perm rotation
 *
 * ShiftRows offsets (Nb = 8):
 *   Encrypt: (0, 1, 3, 4)
 *   Decrypt (inverse): (0, 7, 5, 4)
 */

#define Nb 8
#define SHARED_MEM_BANK_SIZE 32

/* ====================================================================
 * Error checking macro
 * ==================================================================== */

#define CUDA_CHECK(call) \
    do { \
        cudaError_t err = (call); \
        if (err != cudaSuccess) { \
            fprintf(stderr, "CUDA error at %s:%d: %s\n", \
                    __FILE__, __LINE__, cudaGetErrorString(err)); \
            exit(EXIT_FAILURE); \
        } \
    } while(0)

/* ====================================================================
 * Grid size helper
 * ==================================================================== */

static inline int rijndael_checked_grid_size(size_t numBlocks,
                                             int threadsPerBlock,
                                             const char *context)
{
    if (threadsPerBlock <= 0) {
        fprintf(stderr, "%s: threadsPerBlock must be positive\n", context);
        exit(EXIT_FAILURE);
    }
    size_t grid = (numBlocks + (size_t)threadsPerBlock - 1) /
                  (size_t)threadsPerBlock;
    if (grid > (size_t)INT32_MAX) {
        fprintf(stderr, "%s: grid size overflow\n", context);
        exit(EXIT_FAILURE);
    }
    return (int)grid;
}

/* ====================================================================
 * Device helpers: big-endian word load/store
 * ==================================================================== */

__device__ __forceinline__ uint32_t dev_get_word_be(const uint8_t *b)
{
    return ((uint32_t)b[0] << 24) |
           ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] <<  8) |
           (uint32_t)b[3];
}

__device__ __forceinline__ void dev_put_word_be(uint32_t w, uint8_t *b)
{
    b[0] = (uint8_t)(w >> 24);
    b[1] = (uint8_t)(w >> 16);
    b[2] = (uint8_t)(w >>  8);
    b[3] = (uint8_t)(w);
}

/* ====================================================================
 * V2 Encrypt Block: 4 separate T-tables in shared memory
 *
 * Te0..Te3 for main rounds, T4_0..T4_3 for final round.
 * ShiftRows (0, 1, 3, 4) is encoded in the column index offsets.
 * ==================================================================== */

__device__ __forceinline__ void rijndael256_encrypt_block_v2(
    const uint32_t in[8], uint32_t out[8],
    const uint32_t *roundKey, int Nr,
    const uint32_t *Te0_s, const uint32_t *Te1_s,
    const uint32_t *Te2_s, const uint32_t *Te3_s,
    const uint32_t *T4_0_s, const uint32_t *T4_1_s,
    const uint32_t *T4_2_s, const uint32_t *T4_3_s)
{
    uint32_t s[8], t[8];

    /* AddRoundKey (round 0) */
    #pragma unroll
    for (int i = 0; i < 8; i++) s[i] = in[i] ^ roundKey[i];

    const uint32_t *rk = roundKey + Nb;

    /* Rounds 1 .. Nr-1: SubBytes + ShiftRows(0,1,3,4) + MixColumns + ARK */
    for (int r = 1; r < Nr; r++) {
        #pragma unroll
        for (int i = 0; i < 8; i++) {
            t[i] = Te0_s[(s[i]              >> 24) & 0xFF] ^
                   Te1_s[(s[(i + 1) & 7] >> 16) & 0xFF] ^
                   Te2_s[(s[(i + 3) & 7] >>  8) & 0xFF] ^
                   Te3_s[(s[(i + 4) & 7]      ) & 0xFF] ^
                   rk[i];
        }
        #pragma unroll
        for (int i = 0; i < 8; i++) s[i] = t[i];
        rk += Nb;
    }

    /* Final round: SubBytes + ShiftRows + ARK (no MixColumns) */
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        out[i] = T4_0_s[(s[i]              >> 24) & 0xFF] ^
                 T4_1_s[(s[(i + 1) & 7] >> 16) & 0xFF] ^
                 T4_2_s[(s[(i + 3) & 7] >>  8) & 0xFF] ^
                 T4_3_s[(s[(i + 4) & 7]      ) & 0xFF] ^
                 rk[i];
    }
}

/* ====================================================================
 * V2 Decrypt Block: 4 separate inverse T-tables
 *
 * InvShiftRows (0, 7, 5, 4) encoded in column index offsets.
 * Uses decryption keys with InvMixColumns pre-applied to middle rounds.
 * ==================================================================== */

__device__ __forceinline__ void rijndael256_decrypt_block_v2(
    const uint32_t in[8], uint32_t out[8],
    const uint32_t *roundKey, int Nr,
    const uint32_t *Td0_s, const uint32_t *Td1_s,
    const uint32_t *Td2_s, const uint32_t *Td3_s,
    const uint32_t *T4i_0_s, const uint32_t *T4i_1_s,
    const uint32_t *T4i_2_s, const uint32_t *T4i_3_s)
{
    uint32_t s[8], t[8];

    /* AddRoundKey (round Nr) */
    const uint32_t *rk = roundKey + Nr * Nb;
    #pragma unroll
    for (int i = 0; i < 8; i++) s[i] = in[i] ^ rk[i];

    rk -= Nb;

    /* Rounds Nr-1 .. 1: InvSub + InvShift(0,7,5,4) + InvMix + ARK */
    for (int r = Nr - 1; r >= 1; r--) {
        #pragma unroll
        for (int i = 0; i < 8; i++) {
            t[i] = Td0_s[(s[i]              >> 24) & 0xFF] ^
                   Td1_s[(s[(i + 7) & 7] >> 16) & 0xFF] ^
                   Td2_s[(s[(i + 5) & 7] >>  8) & 0xFF] ^
                   Td3_s[(s[(i + 4) & 7]      ) & 0xFF] ^
                   rk[i];
        }
        #pragma unroll
        for (int i = 0; i < 8; i++) s[i] = t[i];
        rk -= Nb;
    }

    /* Final round: InvSubBytes + InvShiftRows + ARK (no InvMixColumns) */
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        out[i] = T4i_0_s[(s[i]              >> 24) & 0xFF] ^
                 T4i_1_s[(s[(i + 7) & 7] >> 16) & 0xFF] ^
                 T4i_2_s[(s[(i + 5) & 7] >>  8) & 0xFF] ^
                 T4i_3_s[(s[(i + 4) & 7]      ) & 0xFF] ^
                 rk[i];
    }
}

/* ====================================================================
 * V3 Encrypt Block: Bank-conflict-free Te0[256][32]
 *
 * Only Te0 is stored (replicated across 32 banks).
 * Te1(x) = ROR(Te0(x), 8), Te2(x) = ROR(Te0(x), 16), etc.
 * Rotation is done via __byte_perm intrinsic:
 *   __byte_perm(w, 0, 0x0321) = ROR(w, 8)   (Te1)
 *   __byte_perm(w, 0, 0x1032) = ROR(w, 16)  (Te2)
 *   __byte_perm(w, 0, 0x2103) = ROR(w, 24)  (Te3)
 *
 * Each thread accesses Te0_s[idx][warpThreadIndex], guaranteeing that
 * threads in the same warp hit different banks.
 * ==================================================================== */

__device__ __forceinline__ void rijndael256_encrypt_block_v3(
    const uint32_t in[8], uint32_t out[8],
    const uint32_t *roundKey, int Nr,
    const uint32_t Te0_s[][SHARED_MEM_BANK_SIZE],
    const uint32_t *T4_0_s, const uint32_t *T4_1_s,
    const uint32_t *T4_2_s, const uint32_t *T4_3_s,
    int warpThreadIndex)
{
    uint32_t s[8], t[8];

    #pragma unroll
    for (int i = 0; i < 8; i++) s[i] = in[i] ^ roundKey[i];

    const uint32_t *rk = roundKey + Nb;

    for (int r = 1; r < Nr; r++) {
        #pragma unroll
        for (int i = 0; i < 8; i++) {
            /* Te0: byte 0 (most significant) */
            uint32_t v0 = Te0_s[(s[i]              >> 24) & 0xFF][warpThreadIndex];
            /* Te1 = ROR(Te0, 8): byte 1 */
            uint32_t v1 = Te0_s[(s[(i + 1) & 7] >> 16) & 0xFF][warpThreadIndex];
            v1 = __byte_perm(v1, 0, 0x0321);
            /* Te2 = ROR(Te0, 16): byte 2 */
            uint32_t v2 = Te0_s[(s[(i + 3) & 7] >>  8) & 0xFF][warpThreadIndex];
            v2 = __byte_perm(v2, 0, 0x1032);
            /* Te3 = ROR(Te0, 24): byte 3 */
            uint32_t v3 = Te0_s[(s[(i + 4) & 7]      ) & 0xFF][warpThreadIndex];
            v3 = __byte_perm(v3, 0, 0x2103);

            t[i] = v0 ^ v1 ^ v2 ^ v3 ^ rk[i];
        }
        #pragma unroll
        for (int i = 0; i < 8; i++) s[i] = t[i];
        rk += Nb;
    }

    /* Final round: use plain T4 tables (1D, may have bank conflicts) */
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        out[i] = T4_0_s[(s[i]              >> 24) & 0xFF] ^
                 T4_1_s[(s[(i + 1) & 7] >> 16) & 0xFF] ^
                 T4_2_s[(s[(i + 3) & 7] >>  8) & 0xFF] ^
                 T4_3_s[(s[(i + 4) & 7]      ) & 0xFF] ^
                 rk[i];
    }
}

/* ====================================================================
 * V3 Decrypt Block: Bank-conflict-free Td0[256][32]
 *
 * Same principle as V3 encrypt but using inverse tables.
 * Td1(x) = ROR(Td0(x), 8), etc.
 * ==================================================================== */

__device__ __forceinline__ void rijndael256_decrypt_block_v3(
    const uint32_t in[8], uint32_t out[8],
    const uint32_t *roundKey, int Nr,
    const uint32_t Td0_s[][SHARED_MEM_BANK_SIZE],
    const uint32_t *T4i_0_s, const uint32_t *T4i_1_s,
    const uint32_t *T4i_2_s, const uint32_t *T4i_3_s,
    int warpThreadIndex)
{
    uint32_t s[8], t[8];

    const uint32_t *rk = roundKey + Nr * Nb;
    #pragma unroll
    for (int i = 0; i < 8; i++) s[i] = in[i] ^ rk[i];

    rk -= Nb;

    for (int r = Nr - 1; r >= 1; r--) {
        #pragma unroll
        for (int i = 0; i < 8; i++) {
            uint32_t v0 = Td0_s[(s[i]              >> 24) & 0xFF][warpThreadIndex];
            uint32_t v1 = Td0_s[(s[(i + 7) & 7] >> 16) & 0xFF][warpThreadIndex];
            v1 = __byte_perm(v1, 0, 0x0321);
            uint32_t v2 = Td0_s[(s[(i + 5) & 7] >>  8) & 0xFF][warpThreadIndex];
            v2 = __byte_perm(v2, 0, 0x1032);
            uint32_t v3 = Td0_s[(s[(i + 4) & 7]      ) & 0xFF][warpThreadIndex];
            v3 = __byte_perm(v3, 0, 0x2103);

            t[i] = v0 ^ v1 ^ v2 ^ v3 ^ rk[i];
        }
        #pragma unroll
        for (int i = 0; i < 8; i++) s[i] = t[i];
        rk -= Nb;
    }

    /* Final round: plain T4i tables */
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        out[i] = T4i_0_s[(s[i]              >> 24) & 0xFF] ^
                 T4i_1_s[(s[(i + 7) & 7] >> 16) & 0xFF] ^
                 T4i_2_s[(s[(i + 5) & 7] >>  8) & 0xFF] ^
                 T4i_3_s[(s[(i + 4) & 7]      ) & 0xFF] ^
                 rk[i];
    }
}

#endif /* RIJNDAEL_CUDA_CORE_CUH */
