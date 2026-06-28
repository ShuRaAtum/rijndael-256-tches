#include "rijndael_ctr.cuh"
#include "rijndael_cuda_tables.cuh"
#include "rijndael_cuda_core.cuh"

/*
 * Rijndael-256 CTR Mode - V2 and V3 Kernels
 *
 * 1 thread = 1 counter block
 * Counter: nonce + thread_id (256-bit, lower 64 bits incremented)
 * Encrypt(counter) XOR plaintext = ciphertext
 * If plaintext == NULL, output keystream only
 */

/* Constant memory */
__constant__ uint32_t c_ctr_encKey[120];
__constant__ uint32_t c_ctr_nonce[8]; /* 32 bytes = 8 words */

/* ====================================================================
 * Device: Build counter from nonce + thread index
 * ==================================================================== */

__device__ __forceinline__ void build_counter(uint32_t ctr[8], size_t tid) {
    #pragma unroll
    for (int i = 0; i < 8; i++) ctr[i] = c_ctr_nonce[i];

    /* Add tid to lower 64 bits (words 6 and 7, big-endian).
     * Carry beyond 64 bits (into words 0-5) is intentionally omitted:
     * 2^64 blocks × 32 B = 512 EiB, far exceeding practical data sizes.
     * This truncation matches the CPU reference implementation. */
    uint64_t low64 = ((uint64_t)ctr[6] << 32) | (uint64_t)ctr[7];
    low64 += (uint64_t)tid;
    ctr[7] = (uint32_t)low64;
    ctr[6] = (uint32_t)(low64 >> 32);
}

/* ====================================================================
 * V2 CTR Kernel: Simple shared memory (8 KiB)
 *
 * Shared memory layout:
 *   Te0_s..Te3_s[256] = 4 KiB (encryption tables)
 *   T4_0..T4_3_s[256] = 4 KiB (final-round tables)
 *   Total: 8192 bytes = 8 KiB
 * ==================================================================== */

__global__ void rijndael256_ctr_kernel_v2(
    const uint8_t *d_input, uint8_t *d_output,
    size_t numBlocks, int rounds, int hasInput)
{
    __shared__ uint32_t Te0_s[256], Te1_s[256], Te2_s[256], Te3_s[256];
    __shared__ uint32_t T4_0_s[256], T4_1_s[256], T4_2_s[256], T4_3_s[256];

    for (int i = threadIdx.x; i < 256; i += blockDim.x) {
        Te0_s[i] = d_Te0[i]; Te1_s[i] = d_Te1[i];
        Te2_s[i] = d_Te2[i]; Te3_s[i] = d_Te3[i];
        T4_0_s[i] = d_T4_0[i]; T4_1_s[i] = d_T4_1[i];
        T4_2_s[i] = d_T4_2[i]; T4_3_s[i] = d_T4_3[i];
    }
    __syncthreads();

    size_t tid = (size_t)blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= numBlocks) return;

    /* Build counter */
    uint32_t ctr[8];
    build_counter(ctr, tid);

    /* Encrypt counter */
    uint32_t keystream[8];
    rijndael256_encrypt_block_v2(ctr, keystream, c_ctr_encKey, rounds,
        Te0_s, Te1_s, Te2_s, Te3_s, T4_0_s, T4_1_s, T4_2_s, T4_3_s);

    /* XOR with plaintext (or output keystream) */
    size_t off = tid * RIJNDAEL256_BLOCK_SIZE;
    uint8_t *out = d_output + off;

    if (hasInput) {
        const uint8_t *in = d_input + off;
        #pragma unroll
        for (int i = 0; i < 8; i++) {
            uint32_t pt = dev_get_word_be(in + 4 * i);
            dev_put_word_be(keystream[i] ^ pt, out + 4 * i);
        }
    } else {
        #pragma unroll
        for (int i = 0; i < 8; i++) {
            dev_put_word_be(keystream[i], out + 4 * i);
        }
    }
}

/* ====================================================================
 * V3 CTR Kernel: Bank-conflict-free main rounds (36 KiB shared memory)
 *
 * Te0_s[256][32] is replicated across all 32 banks, eliminating bank
 * conflicts during main-round T-table lookups.  Te1/Te2/Te3 are derived
 * via __byte_perm() rotation of Te0.
 *
 * NOTE: Final-round T4 tables remain plain 1D shared arrays and are
 * therefore still subject to bank conflicts.  This is standard practice
 * as the final round is a single iteration (Tezcan, TCHES 2021).
 * ==================================================================== */

__global__ void rijndael256_ctr_kernel_v3(
    const uint8_t *d_input, uint8_t *d_output,
    size_t numBlocks, int rounds, int hasInput)
{
    __shared__ uint32_t Te0_s[256][SHARED_MEM_BANK_SIZE];
    __shared__ uint32_t T4_0_s[256], T4_1_s[256], T4_2_s[256], T4_3_s[256];

    int warpThreadIndex = threadIdx.x & 31;

    for (int i = threadIdx.x; i < 256; i += blockDim.x) {
        T4_0_s[i] = d_T4_0[i]; T4_1_s[i] = d_T4_1[i];
        T4_2_s[i] = d_T4_2[i]; T4_3_s[i] = d_T4_3[i];
        uint32_t te0_val = d_Te0[i];
        #pragma unroll
        for (int b = 0; b < 32; b++) Te0_s[i][(b + warpThreadIndex) & 31] = te0_val;
    }
    __syncthreads();

    size_t tid = (size_t)blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= numBlocks) return;

    uint32_t ctr[8];
    build_counter(ctr, tid);

    uint32_t keystream[8];
    rijndael256_encrypt_block_v3(ctr, keystream, c_ctr_encKey, rounds,
        Te0_s, T4_0_s, T4_1_s, T4_2_s, T4_3_s, warpThreadIndex);

    size_t off = tid * RIJNDAEL256_BLOCK_SIZE;
    uint8_t *out = d_output + off;

    if (hasInput) {
        const uint8_t *in = d_input + off;
        #pragma unroll
        for (int i = 0; i < 8; i++) {
            uint32_t pt = dev_get_word_be(in + 4 * i);
            dev_put_word_be(keystream[i] ^ pt, out + 4 * i);
        }
    } else {
        #pragma unroll
        for (int i = 0; i < 8; i++) {
            dev_put_word_be(keystream[i], out + 4 * i);
        }
    }
}

/* ====================================================================
 * Host Wrapper Functions
 * ==================================================================== */

void rijndael256_ctr_crypt_v2(const uint8_t *nonce,
                               const uint8_t *plaintext, uint8_t *output,
                               const RijndaelKey *rk, size_t numBlocks,
                               int threadsPerBlock)
{
    if (numBlocks == 0) return;
    size_t dataSize = numBlocks * RIJNDAEL256_BLOCK_SIZE;
    size_t keySize = (rk->rounds + 1) * Nb * sizeof(uint32_t);

    /* Copy keys and nonce to constant memory */
    CUDA_CHECK(cudaMemcpyToSymbol(c_ctr_encKey, rk->roundKey, keySize));

    uint32_t nonceWords[8];
    for (int i = 0; i < 8; i++) {
        nonceWords[i] = ((uint32_t)nonce[4*i] << 24) |
                         ((uint32_t)nonce[4*i+1] << 16) |
                         ((uint32_t)nonce[4*i+2] << 8) |
                         (uint32_t)nonce[4*i+3];
    }
    CUDA_CHECK(cudaMemcpyToSymbol(c_ctr_nonce, nonceWords, sizeof(nonceWords)));

    uint8_t *d_in = NULL, *d_out = NULL;
    int hasInput = (plaintext != NULL) ? 1 : 0;

    if (hasInput) {
        CUDA_CHECK(cudaMalloc(&d_in, dataSize));
        CUDA_CHECK(cudaMemcpy(d_in, plaintext, dataSize, cudaMemcpyHostToDevice));
    }
    CUDA_CHECK(cudaMalloc(&d_out, dataSize));

    int gridSize = rijndael_checked_grid_size(
        numBlocks, threadsPerBlock, "rijndael256_ctr_crypt_v2");
    rijndael256_ctr_kernel_v2<<<gridSize, threadsPerBlock>>>(
        d_in, d_out, numBlocks, rk->rounds, hasInput);
    CUDA_CHECK(cudaGetLastError());
    CUDA_CHECK(cudaDeviceSynchronize());

    CUDA_CHECK(cudaMemcpy(output, d_out, dataSize, cudaMemcpyDeviceToHost));
    if (d_in) CUDA_CHECK(cudaFree(d_in));
    CUDA_CHECK(cudaFree(d_out));
}

void rijndael256_ctr_crypt_v3(const uint8_t *nonce,
                               const uint8_t *plaintext, uint8_t *output,
                               const RijndaelKey *rk, size_t numBlocks,
                               int threadsPerBlock)
{
    if (numBlocks == 0) return;
    size_t dataSize = numBlocks * RIJNDAEL256_BLOCK_SIZE;
    size_t keySize = (rk->rounds + 1) * Nb * sizeof(uint32_t);

    CUDA_CHECK(cudaMemcpyToSymbol(c_ctr_encKey, rk->roundKey, keySize));

    uint32_t nonceWords[8];
    for (int i = 0; i < 8; i++) {
        nonceWords[i] = ((uint32_t)nonce[4*i] << 24) |
                         ((uint32_t)nonce[4*i+1] << 16) |
                         ((uint32_t)nonce[4*i+2] << 8) |
                         (uint32_t)nonce[4*i+3];
    }
    CUDA_CHECK(cudaMemcpyToSymbol(c_ctr_nonce, nonceWords, sizeof(nonceWords)));

    uint8_t *d_in = NULL, *d_out = NULL;
    int hasInput = (plaintext != NULL) ? 1 : 0;

    if (hasInput) {
        CUDA_CHECK(cudaMalloc(&d_in, dataSize));
        CUDA_CHECK(cudaMemcpy(d_in, plaintext, dataSize, cudaMemcpyHostToDevice));
    }
    CUDA_CHECK(cudaMalloc(&d_out, dataSize));

    int gridSize = rijndael_checked_grid_size(
        numBlocks, threadsPerBlock, "rijndael256_ctr_crypt_v3");
    rijndael256_ctr_kernel_v3<<<gridSize, threadsPerBlock>>>(
        d_in, d_out, numBlocks, rk->rounds, hasInput);
    CUDA_CHECK(cudaGetLastError());
    CUDA_CHECK(cudaDeviceSynchronize());

    CUDA_CHECK(cudaMemcpy(output, d_out, dataSize, cudaMemcpyDeviceToHost));
    if (d_in) CUDA_CHECK(cudaFree(d_in));
    CUDA_CHECK(cudaFree(d_out));
}

/* ====================================================================
 * Kernel-Only API: setup + launch on device pointers
 * ==================================================================== */

void rijndael256_ctr_setup(const uint8_t *nonce, const RijndaelKey *rk) {
    size_t keySize = (rk->rounds + 1) * Nb * sizeof(uint32_t);
    CUDA_CHECK(cudaMemcpyToSymbol(c_ctr_encKey, rk->roundKey, keySize));

    uint32_t nonceWords[8];
    for (int i = 0; i < 8; i++) {
        nonceWords[i] = ((uint32_t)nonce[4*i] << 24) |
                         ((uint32_t)nonce[4*i+1] << 16) |
                         ((uint32_t)nonce[4*i+2] << 8) |
                         (uint32_t)nonce[4*i+3];
    }
    CUDA_CHECK(cudaMemcpyToSymbol(c_ctr_nonce, nonceWords, sizeof(nonceWords)));
}

void rijndael256_ctr_launch_v2(uint8_t *d_in, uint8_t *d_out,
                                const RijndaelKey *rk, size_t numBlocks,
                                int threadsPerBlock)
{
    if (numBlocks == 0) return;
    int hasInput = (d_in != NULL) ? 1 : 0;
    int gridSize = rijndael_checked_grid_size(
        numBlocks, threadsPerBlock, "rijndael256_ctr_launch_v2");
    rijndael256_ctr_kernel_v2<<<gridSize, threadsPerBlock>>>(
        d_in, d_out, numBlocks, rk->rounds, hasInput);
    CUDA_CHECK(cudaGetLastError());
}

void rijndael256_ctr_launch_v3(uint8_t *d_in, uint8_t *d_out,
                                const RijndaelKey *rk, size_t numBlocks,
                                int threadsPerBlock)
{
    if (numBlocks == 0) return;
    int hasInput = (d_in != NULL) ? 1 : 0;
    int gridSize = rijndael_checked_grid_size(
        numBlocks, threadsPerBlock, "rijndael256_ctr_launch_v3");
    rijndael256_ctr_kernel_v3<<<gridSize, threadsPerBlock>>>(
        d_in, d_out, numBlocks, rk->rounds, hasInput);
    CUDA_CHECK(cudaGetLastError());
}
