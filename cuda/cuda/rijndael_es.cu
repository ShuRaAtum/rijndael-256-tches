#include "rijndael_es.cuh"
#include "rijndael_cuda_tables.cuh"
#include "rijndael_cuda_core.cuh"

/*
 * Rijndael-256 Exhaustive Search (ES) - V2 and V3 Kernels
 *
 * Searches key space by varying the lower 64 bits of the key.
 * Each thread: expand key -> encrypt known plaintext -> compare with known ciphertext
 * Early termination: first compare ct[0] only, then full comparison.
 */

/* Constant memory */
__constant__ uint32_t c_es_knownPt[8];   /* Known plaintext (8 words) */
__constant__ uint32_t c_es_knownCt[8];   /* Known ciphertext (8 words) */
__constant__ uint32_t c_es_baseKey[8];   /* Base key words (max 256-bit = 8 words) */
__constant__ uint32_t c_es_Rcon[30];     /* Round constants */

/* Device result: winner publishes result exactly once.
 * d_es_found is volatile so that early-exit reads in other thread blocks
 * always see the most recent write (avoids stale L1 cache). */
__device__ volatile int d_es_found;
__device__ uint64_t d_es_keyOffset;

static void es_fail(const char *context, const char *message)
{
    fprintf(stderr, "%s: %s\n", context, message);
    exit(EXIT_FAILURE);
}

static void es_require_ptr(const void *ptr, const char *name, const char *context)
{
    if (ptr == NULL) {
        fprintf(stderr, "%s: %s must not be NULL\n", context, name);
        exit(EXIT_FAILURE);
    }
}

static int es_checked_nk(int keyBits, const char *context)
{
    switch (keyBits) {
        case 128: return 4;
        case 192: return 6;
        case 256: return 8;
        default:
            fprintf(stderr, "%s: unsupported keyBits=%d (expected 128, 192, or 256)\n",
                    context, keyBits);
            exit(EXIT_FAILURE);
    }
}

static uint64_t es_checked_total_threads(int threadsPerBlock, int numCudaBlocks,
                                         const char *context)
{
    if (threadsPerBlock <= 0) {
        fprintf(stderr, "%s: threadsPerBlock must be positive\n", context);
        exit(EXIT_FAILURE);
    }
    if (numCudaBlocks <= 0) {
        fprintf(stderr, "%s: numCudaBlocks must be positive\n", context);
        exit(EXIT_FAILURE);
    }

    return (uint64_t)threadsPerBlock * (uint64_t)numCudaBlocks;
}

static uint64_t es_ceil_div_u64(uint64_t numerator, uint64_t denominator)
{
    return numerator / denominator + ((numerator % denominator) != 0);
}

static void es_validate_search_window(uint64_t baseOffset, uint64_t searchRange,
                                      const char *context)
{
    if (searchRange > UINT64_MAX - baseOffset) {
        es_fail(context, "baseOffset + searchRange overflows uint64_t");
    }
}

/* ====================================================================
 * Device: Key Expansion (per-thread)
 * ==================================================================== */

__device__ void dev_rijndael256_setup_key(
    uint32_t *rk, int Nk, int Nr,
    const uint8_t *SBox_s)
{
    uint32_t temp;
    int totalWords = (Nr + 1) * Nb;

    for (int i = Nk; i < totalWords; i++) {
        temp = rk[i - 1];
        if (i % Nk == 0) {
            /* RotWord + SubWord + Rcon */
            temp = (temp << 8) | (temp >> 24); /* RotWord */
            temp = ((uint32_t)SBox_s[(temp >> 24) & 0xFF] << 24) |
                   ((uint32_t)SBox_s[(temp >> 16) & 0xFF] << 16) |
                   ((uint32_t)SBox_s[(temp >>  8) & 0xFF] <<  8) |
                   ((uint32_t)SBox_s[(temp      ) & 0xFF]);
            temp ^= c_es_Rcon[i / Nk];
        } else if (Nk > 6 && (i % Nk == 4)) {
            /* SubWord only */
            temp = ((uint32_t)SBox_s[(temp >> 24) & 0xFF] << 24) |
                   ((uint32_t)SBox_s[(temp >> 16) & 0xFF] << 16) |
                   ((uint32_t)SBox_s[(temp >>  8) & 0xFF] <<  8) |
                   ((uint32_t)SBox_s[(temp      ) & 0xFF]);
        }
        rk[i] = rk[i - Nk] ^ temp;
    }
}

/* ====================================================================
 * V2 ES Kernel: Simple shared memory (8.25 KiB)
 *
 * Shared memory layout:
 *   Te0_s..Te3_s[256] + T4_0..T4_3_s[256] = 8 KiB (encryption tables)
 *   SBox_s[256] = 256 bytes (key expansion)
 *   Total: 8448 bytes = 8.25 KiB
 *
 * Per-thread register pressure: uint32_t rk[120] = 480 bytes.
 * This exceeds the per-thread register file (255 regs × 4B = 1020B)
 * and will spill to local memory (L1/L2-cached device memory).
 * ==================================================================== */

__global__ void rijndael256_es_kernel_v2(
    uint64_t baseOffset, uint64_t searchRange,
    int Nk, int Nr, uint64_t keysPerThread)
{
    /* Shared memory: Te0-Te3 (4 KiB) + T4 (4 KiB) + SBox (256 B) = 8.25 KiB */
    __shared__ uint32_t Te0_s[256], Te1_s[256], Te2_s[256], Te3_s[256];
    __shared__ uint32_t T4_0_s[256], T4_1_s[256], T4_2_s[256], T4_3_s[256];
    __shared__ uint8_t SBox_s[256];

    for (int i = threadIdx.x; i < 256; i += blockDim.x) {
        Te0_s[i] = d_Te0[i]; Te1_s[i] = d_Te1[i];
        Te2_s[i] = d_Te2[i]; Te3_s[i] = d_Te3[i];
        T4_0_s[i] = d_T4_0[i]; T4_1_s[i] = d_T4_1[i];
        T4_2_s[i] = d_T4_2[i]; T4_3_s[i] = d_T4_3[i];
        SBox_s[i] = d_SBox[i];
    }
    __syncthreads();

    uint64_t tid = (uint64_t)blockIdx.x * (uint64_t)blockDim.x +
                   (uint64_t)threadIdx.x;
    uint64_t activeThreads = searchRange / keysPerThread +
                             ((searchRange % keysPerThread) != 0);
    if (tid >= activeThreads) return;

    uint64_t startKey = baseOffset + tid * keysPerThread;
    uint64_t searchEnd = baseOffset + searchRange;

    for (uint64_t k = 0; k < keysPerThread; k++) {
        /* Early exit if another thread found the key */
        if (d_es_found) return;

        uint64_t keyIdx = startKey + k;
        if (keyIdx >= searchEnd) return;

        /* Build key: copy base key, modify lower 64 bits.
         * rk[120] = 480 bytes; will partially spill to local memory. */
        uint32_t rk[120];
        for (int i = 0; i < Nk; i++) rk[i] = c_es_baseKey[i];

        /* Inject keyIdx into lower 64 bits (last 2 words of key) */
        rk[Nk - 1] = (uint32_t)(keyIdx);
        rk[Nk - 2] = (uint32_t)(keyIdx >> 32);

        /* Key expansion */
        dev_rijndael256_setup_key(rk, Nk, Nr, SBox_s);

        /* Encrypt known plaintext */
        uint32_t ct[8];
        rijndael256_encrypt_block_v2(c_es_knownPt, ct, rk, Nr,
            Te0_s, Te1_s, Te2_s, Te3_s, T4_0_s, T4_1_s, T4_2_s, T4_3_s);

        /* Early comparison: check first word only */
        if (ct[0] != c_es_knownCt[0]) continue;

        /* Full comparison */
        int match = 1;
        for (int i = 1; i < 8; i++) {
            if (ct[i] != c_es_knownCt[i]) { match = 0; break; }
        }

        if (match) {
            if (atomicCAS((int *)&d_es_found, 0, 1) == 0) {
                atomicExch((unsigned long long *)&d_es_keyOffset,
                           (unsigned long long)keyIdx);
            }
            return;
        }
    }
}

/* ====================================================================
 * V3 ES Kernel: Bank-conflict-free main rounds (36.25 KiB shared memory)
 *
 * Shared memory layout:
 *   Te0_s[256][32] = 32 KiB (bank-conflict-free main-round table)
 *   T4_0..T4_3_s[256] = 4 KiB (final-round tables, NOT bank-conflict-free)
 *   SBox_s[256] = 256 bytes (key expansion)
 *   Total: 37120 bytes = 36.25 KiB
 *
 * NOTE: Final-round T4 tables remain plain 1D shared arrays and are
 * therefore still subject to bank conflicts.  This is standard practice
 * as the final round is a single iteration (Tezcan, TCHES 2021).
 *
 * Per-thread register pressure: uint32_t rk[120] = 480 bytes.
 * This exceeds the per-thread register file (255 regs × 4B = 1020B)
 * and will spill to local memory (L1/L2-cached device memory).
 * ==================================================================== */

__global__ void rijndael256_es_kernel_v3(
    uint64_t baseOffset, uint64_t searchRange,
    int Nk, int Nr, uint64_t keysPerThread)
{
    __shared__ uint32_t Te0_s[256][SHARED_MEM_BANK_SIZE];
    __shared__ uint32_t T4_0_s[256], T4_1_s[256], T4_2_s[256], T4_3_s[256];
    __shared__ uint8_t SBox_s[256];

    int warpThreadIndex = threadIdx.x & 31;

    for (int i = threadIdx.x; i < 256; i += blockDim.x) {
        T4_0_s[i] = d_T4_0[i]; T4_1_s[i] = d_T4_1[i];
        T4_2_s[i] = d_T4_2[i]; T4_3_s[i] = d_T4_3[i];
        SBox_s[i] = d_SBox[i];
        uint32_t te0_val = d_Te0[i];
        #pragma unroll
        for (int b = 0; b < 32; b++) Te0_s[i][(b + warpThreadIndex) & 31] = te0_val;
    }
    __syncthreads();

    uint64_t tid = (uint64_t)blockIdx.x * (uint64_t)blockDim.x +
                   (uint64_t)threadIdx.x;
    uint64_t activeThreads = searchRange / keysPerThread +
                             ((searchRange % keysPerThread) != 0);
    if (tid >= activeThreads) return;

    uint64_t startKey = baseOffset + tid * keysPerThread;
    uint64_t searchEnd = baseOffset + searchRange;

    for (uint64_t k = 0; k < keysPerThread; k++) {
        if (d_es_found) return;

        uint64_t keyIdx = startKey + k;
        if (keyIdx >= searchEnd) return;

        /* rk[120] = 480 bytes; will partially spill to local memory. */
        uint32_t rk[120];
        for (int i = 0; i < Nk; i++) rk[i] = c_es_baseKey[i];
        rk[Nk - 1] = (uint32_t)(keyIdx);
        rk[Nk - 2] = (uint32_t)(keyIdx >> 32);

        dev_rijndael256_setup_key(rk, Nk, Nr, SBox_s);

        uint32_t ct[8];
        rijndael256_encrypt_block_v3(c_es_knownPt, ct, rk, Nr,
            Te0_s, T4_0_s, T4_1_s, T4_2_s, T4_3_s, warpThreadIndex);

        if (ct[0] != c_es_knownCt[0]) continue;

        int match = 1;
        for (int i = 1; i < 8; i++) {
            if (ct[i] != c_es_knownCt[i]) { match = 0; break; }
        }

        if (match) {
            if (atomicCAS((int *)&d_es_found, 0, 1) == 0) {
                atomicExch((unsigned long long *)&d_es_keyOffset,
                           (unsigned long long)keyIdx);
            }
            return;
        }
    }
}

/* ====================================================================
 * Host: Common ES setup and launch
 * ==================================================================== */

static void es_setup(const uint8_t *knownPt, const uint8_t *knownCt,
                      const uint8_t *baseKey, int Nk)
{
    /* Convert plaintext/ciphertext to words */
    uint32_t ptWords[8], ctWords[8];
    for (int i = 0; i < 8; i++) {
        ptWords[i] = ((uint32_t)knownPt[4*i] << 24) |
                      ((uint32_t)knownPt[4*i+1] << 16) |
                      ((uint32_t)knownPt[4*i+2] << 8) |
                      (uint32_t)knownPt[4*i+3];
        ctWords[i] = ((uint32_t)knownCt[4*i] << 24) |
                      ((uint32_t)knownCt[4*i+1] << 16) |
                      ((uint32_t)knownCt[4*i+2] << 8) |
                      (uint32_t)knownCt[4*i+3];
    }
    CUDA_CHECK(cudaMemcpyToSymbol(c_es_knownPt, ptWords, sizeof(ptWords)));
    CUDA_CHECK(cudaMemcpyToSymbol(c_es_knownCt, ctWords, sizeof(ctWords)));

    /* Convert base key to words */
    uint32_t keyWords[8] = {0};
    for (int i = 0; i < Nk; i++) {
        keyWords[i] = ((uint32_t)baseKey[4*i] << 24) |
                       ((uint32_t)baseKey[4*i+1] << 16) |
                       ((uint32_t)baseKey[4*i+2] << 8) |
                       (uint32_t)baseKey[4*i+3];
    }
    CUDA_CHECK(cudaMemcpyToSymbol(c_es_baseKey, keyWords, sizeof(keyWords)));

    /* Rcon */
    static const uint32_t Rcon[30] = {
        0x00000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000,
        0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000,
        0x36000000, 0x6c000000, 0xd8000000, 0xab000000, 0x4d000000,
        0x9a000000, 0x2f000000, 0x5e000000, 0xbc000000, 0x63000000,
        0xc6000000, 0x97000000, 0x35000000, 0x6a000000, 0xd4000000,
        0xb3000000, 0x7d000000, 0xfa000000, 0xef000000, 0xc5000000,
    };
    CUDA_CHECK(cudaMemcpyToSymbol(c_es_Rcon, Rcon, sizeof(Rcon)));

    /* Reset found flag */
    int zero = 0;
    uint64_t zero64 = 0;
    CUDA_CHECK(cudaMemcpyToSymbol(d_es_found, &zero, sizeof(int)));
    CUDA_CHECK(cudaMemcpyToSymbol(d_es_keyOffset, &zero64, sizeof(uint64_t)));
}

static void es_get_result(ESResult *result) {
    CUDA_CHECK(cudaMemcpyFromSymbol(&result->found, d_es_found, sizeof(int)));
    if (result->found) {
        CUDA_CHECK(cudaMemcpyFromSymbol(&result->keyOffset, d_es_keyOffset,
                                         sizeof(uint64_t)));
    } else {
        result->keyOffset = 0;
    }
}

void rijndael256_es_setup(const uint8_t *knownPt, const uint8_t *knownCt,
                           const uint8_t *baseKey, int keyBits)
{
    const char *context = "rijndael256_es_setup";
    es_require_ptr(knownPt, "knownPt", context);
    es_require_ptr(knownCt, "knownCt", context);
    es_require_ptr(baseKey, "baseKey", context);

    int Nk = es_checked_nk(keyBits, context);
    es_setup(knownPt, knownCt, baseKey, Nk);
}

void rijndael256_es_get_result(ESResult *result)
{
    const char *context = "rijndael256_es_get_result";
    es_require_ptr(result, "result", context);
    es_get_result(result);
}

void rijndael256_es_launch_v2(int keyBits,
                               uint64_t baseOffset, uint64_t searchRange,
                               int threadsPerBlock, int numCudaBlocks)
{
    const char *context = "rijndael256_es_launch_v2";
    int Nk = es_checked_nk(keyBits, context);
    es_validate_search_window(baseOffset, searchRange, context);
    if (searchRange == 0) return;

    uint64_t totalThreads = es_checked_total_threads(
        threadsPerBlock, numCudaBlocks, context);
    uint64_t keysPerThread = es_ceil_div_u64(searchRange, totalThreads);
    int Nr = (Nk > Nb ? Nk : Nb) + 6;

    rijndael256_es_kernel_v2<<<numCudaBlocks, threadsPerBlock>>>(
        baseOffset, searchRange, Nk, Nr, keysPerThread);
    CUDA_CHECK(cudaGetLastError());
}

void rijndael256_es_launch_v3(int keyBits,
                               uint64_t baseOffset, uint64_t searchRange,
                               int threadsPerBlock, int numCudaBlocks)
{
    const char *context = "rijndael256_es_launch_v3";
    int Nk = es_checked_nk(keyBits, context);
    es_validate_search_window(baseOffset, searchRange, context);
    if (searchRange == 0) return;

    uint64_t totalThreads = es_checked_total_threads(
        threadsPerBlock, numCudaBlocks, context);
    uint64_t keysPerThread = es_ceil_div_u64(searchRange, totalThreads);
    int Nr = (Nk > Nb ? Nk : Nb) + 6;

    rijndael256_es_kernel_v3<<<numCudaBlocks, threadsPerBlock>>>(
        baseOffset, searchRange, Nk, Nr, keysPerThread);
    CUDA_CHECK(cudaGetLastError());
}

void rijndael256_es_search_v2(const uint8_t *knownPt, const uint8_t *knownCt,
                               const uint8_t *baseKey, int keyBits,
                               uint64_t baseOffset, uint64_t searchRange,
                               ESResult *result,
                               int threadsPerBlock, int numCudaBlocks)
{
    const char *context = "rijndael256_es_search_v2";
    es_require_ptr(knownPt, "knownPt", context);
    es_require_ptr(knownCt, "knownCt", context);
    es_require_ptr(baseKey, "baseKey", context);
    es_require_ptr(result, "result", context);

    (void)es_checked_nk(keyBits, context);
    es_validate_search_window(baseOffset, searchRange, context);

    result->found = 0;
    result->keyOffset = 0;
    if (searchRange == 0) return;

    rijndael256_es_setup(knownPt, knownCt, baseKey, keyBits);
    rijndael256_es_launch_v2(keyBits, baseOffset, searchRange,
                              threadsPerBlock, numCudaBlocks);
    CUDA_CHECK(cudaDeviceSynchronize());

    rijndael256_es_get_result(result);
}

void rijndael256_es_search_v3(const uint8_t *knownPt, const uint8_t *knownCt,
                               const uint8_t *baseKey, int keyBits,
                               uint64_t baseOffset, uint64_t searchRange,
                               ESResult *result,
                               int threadsPerBlock, int numCudaBlocks)
{
    const char *context = "rijndael256_es_search_v3";
    es_require_ptr(knownPt, "knownPt", context);
    es_require_ptr(knownCt, "knownCt", context);
    es_require_ptr(baseKey, "baseKey", context);
    es_require_ptr(result, "result", context);

    (void)es_checked_nk(keyBits, context);
    es_validate_search_window(baseOffset, searchRange, context);

    result->found = 0;
    result->keyOffset = 0;
    if (searchRange == 0) return;

    rijndael256_es_setup(knownPt, knownCt, baseKey, keyBits);
    rijndael256_es_launch_v3(keyBits, baseOffset, searchRange,
                              threadsPerBlock, numCudaBlocks);
    CUDA_CHECK(cudaDeviceSynchronize());

    rijndael256_es_get_result(result);
}
