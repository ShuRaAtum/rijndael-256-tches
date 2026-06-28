#include "rijndael_ecb.cuh"
#include "rijndael_cuda_tables.cuh"
#include "rijndael_cuda_core.cuh"
#include "rijndael_tables.h"

/*
 * Rijndael-256 ECB Mode - V2 and V3 Encrypt/Decrypt Kernels
 */

/* Constant memory for round keys */
__constant__ uint32_t c_ecb_encKey[120]; /* (14+1)*8 = 120 max */
__constant__ uint32_t c_ecb_decKey[120];

/* ====================================================================
 * Host: Prepare decryption round keys
 * ==================================================================== */

void rijndael256_prepare_dec_keys(const RijndaelKey *rk, uint32_t *decRk) {
    int Nr = rk->rounds;
    /* Copy all round keys first */
    for (int i = 0; i < (Nr + 1) * Nb; i++) {
        decRk[i] = rk->roundKey[i];
    }
    /* Apply InvMixColumns to middle round keys (rounds 1..Nr-1) */
    for (int r = 1; r < Nr; r++) {
        for (int i = 0; i < Nb; i++) {
            uint32_t w = decRk[r * Nb + i];
            decRk[r * Nb + i] =
                InvMix0[(w >> 24) & 0xFF] ^
                InvMix1[(w >> 16) & 0xFF] ^
                InvMix2[(w >>  8) & 0xFF] ^
                InvMix3[(w      ) & 0xFF];
        }
    }
}

/* ====================================================================
 * V2 Kernels: Simple Shared Memory (8 KiB)
 *
 * Shared memory layout:
 *   Te0_s..Te3_s[256] (or Td0..Td3 for decrypt) = 4 KiB
 *   T4_0..T4_3_s[256] (or T4i for decrypt) = 4 KiB
 *   Total: 8192 bytes = 8 KiB
 * ==================================================================== */

__global__ void rijndael256_ecb_encrypt_kernel_v2(
    const uint8_t *d_input, uint8_t *d_output,
    size_t numBlocks, int rounds)
{
    /* Shared memory: Te0-Te3 (4KB) + T4_0-T4_3 (4KB) = 8KB */
    __shared__ uint32_t Te0_s[256], Te1_s[256], Te2_s[256], Te3_s[256];
    __shared__ uint32_t T4_0_s[256], T4_1_s[256], T4_2_s[256], T4_3_s[256];

    /* Cooperative table loading */
    for (int i = threadIdx.x; i < 256; i += blockDim.x) {
        Te0_s[i] = d_Te0[i]; Te1_s[i] = d_Te1[i];
        Te2_s[i] = d_Te2[i]; Te3_s[i] = d_Te3[i];
        T4_0_s[i] = d_T4_0[i]; T4_1_s[i] = d_T4_1[i];
        T4_2_s[i] = d_T4_2[i]; T4_3_s[i] = d_T4_3[i];
    }
    __syncthreads();

    size_t tid = (size_t)blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= numBlocks) return;

    size_t off = tid * RIJNDAEL256_BLOCK_SIZE;
    const uint8_t *in = d_input + off;
    uint8_t *out = d_output + off;

    uint32_t state_in[8], state_out[8];
    #pragma unroll
    for (int i = 0; i < 8; i++) state_in[i] = dev_get_word_be(in + 4 * i);

    rijndael256_encrypt_block_v2(state_in, state_out, c_ecb_encKey, rounds,
        Te0_s, Te1_s, Te2_s, Te3_s, T4_0_s, T4_1_s, T4_2_s, T4_3_s);

    #pragma unroll
    for (int i = 0; i < 8; i++) dev_put_word_be(state_out[i], out + 4 * i);
}

__global__ void rijndael256_ecb_decrypt_kernel_v2(
    const uint8_t *d_input, uint8_t *d_output,
    size_t numBlocks, int rounds)
{
    __shared__ uint32_t Td0_s[256], Td1_s[256], Td2_s[256], Td3_s[256];
    __shared__ uint32_t T4i_0_s[256], T4i_1_s[256], T4i_2_s[256], T4i_3_s[256];

    for (int i = threadIdx.x; i < 256; i += blockDim.x) {
        Td0_s[i] = d_Td0[i]; Td1_s[i] = d_Td1[i];
        Td2_s[i] = d_Td2[i]; Td3_s[i] = d_Td3[i];
        T4i_0_s[i] = d_T4i_0[i]; T4i_1_s[i] = d_T4i_1[i];
        T4i_2_s[i] = d_T4i_2[i]; T4i_3_s[i] = d_T4i_3[i];
    }
    __syncthreads();

    size_t tid = (size_t)blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= numBlocks) return;

    size_t off = tid * RIJNDAEL256_BLOCK_SIZE;
    const uint8_t *in = d_input + off;
    uint8_t *out = d_output + off;

    uint32_t state_in[8], state_out[8];
    #pragma unroll
    for (int i = 0; i < 8; i++) state_in[i] = dev_get_word_be(in + 4 * i);

    rijndael256_decrypt_block_v2(state_in, state_out, c_ecb_decKey, rounds,
        Td0_s, Td1_s, Td2_s, Td3_s, T4i_0_s, T4i_1_s, T4i_2_s, T4i_3_s);

    #pragma unroll
    for (int i = 0; i < 8; i++) dev_put_word_be(state_out[i], out + 4 * i);
}

/* ====================================================================
 * V3 Kernels: Bank-conflict-free main rounds (36 KiB shared memory)
 *
 * Shared memory layout:
 *   Te0_s[256][32] (or Td0 for decrypt) = 32 KiB (bank-conflict-free)
 *   T4_0..T4_3_s[256] (or T4i for decrypt) = 4 KiB
 *   Total: 36864 bytes = 36 KiB
 *
 * NOTE: Final-round T4/T4i tables remain plain 1D shared arrays and are
 * therefore still subject to bank conflicts.  This is standard practice
 * as the final round is a single iteration (Tezcan, TCHES 2021).
 * ==================================================================== */

__global__ void rijndael256_ecb_encrypt_kernel_v3(
    const uint8_t *d_input, uint8_t *d_output,
    size_t numBlocks, int rounds)
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

    size_t off = tid * RIJNDAEL256_BLOCK_SIZE;
    const uint8_t *in = d_input + off;
    uint8_t *out = d_output + off;

    uint32_t state_in[8], state_out[8];
    #pragma unroll
    for (int i = 0; i < 8; i++) state_in[i] = dev_get_word_be(in + 4 * i);

    rijndael256_encrypt_block_v3(state_in, state_out, c_ecb_encKey, rounds,
        Te0_s, T4_0_s, T4_1_s, T4_2_s, T4_3_s, warpThreadIndex);

    #pragma unroll
    for (int i = 0; i < 8; i++) dev_put_word_be(state_out[i], out + 4 * i);
}

__global__ void rijndael256_ecb_decrypt_kernel_v3(
    const uint8_t *d_input, uint8_t *d_output,
    size_t numBlocks, int rounds)
{
    __shared__ uint32_t Td0_s[256][SHARED_MEM_BANK_SIZE];
    __shared__ uint32_t T4i_0_s[256], T4i_1_s[256], T4i_2_s[256], T4i_3_s[256];

    int warpThreadIndex = threadIdx.x & 31;

    for (int i = threadIdx.x; i < 256; i += blockDim.x) {
        T4i_0_s[i] = d_T4i_0[i]; T4i_1_s[i] = d_T4i_1[i];
        T4i_2_s[i] = d_T4i_2[i]; T4i_3_s[i] = d_T4i_3[i];
        uint32_t td0_val = d_Td0[i];
        #pragma unroll
        for (int b = 0; b < 32; b++) Td0_s[i][(b + warpThreadIndex) & 31] = td0_val;
    }
    __syncthreads();

    size_t tid = (size_t)blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= numBlocks) return;

    size_t off = tid * RIJNDAEL256_BLOCK_SIZE;
    const uint8_t *in = d_input + off;
    uint8_t *out = d_output + off;

    uint32_t state_in[8], state_out[8];
    #pragma unroll
    for (int i = 0; i < 8; i++) state_in[i] = dev_get_word_be(in + 4 * i);

    rijndael256_decrypt_block_v3(state_in, state_out, c_ecb_decKey, rounds,
        Td0_s, T4i_0_s, T4i_1_s, T4i_2_s, T4i_3_s, warpThreadIndex);

    #pragma unroll
    for (int i = 0; i < 8; i++) dev_put_word_be(state_out[i], out + 4 * i);
}

/* ====================================================================
 * Host Wrapper Functions
 * ==================================================================== */

static void ecb_setup_keys(const RijndaelKey *rk) {
    size_t keySize = (rk->rounds + 1) * Nb * sizeof(uint32_t);

    /* Encryption keys */
    CUDA_CHECK(cudaMemcpyToSymbol(c_ecb_encKey, rk->roundKey, keySize));

    /* Decryption keys (InvMixColumns applied to middle) */
    uint32_t decRk[120];
    rijndael256_prepare_dec_keys(rk, decRk);
    CUDA_CHECK(cudaMemcpyToSymbol(c_ecb_decKey, decRk, keySize));
}

void rijndael256_ecb_encrypt_v2(const uint8_t *plaintext, uint8_t *ciphertext,
                                 const RijndaelKey *rk, size_t numBlocks,
                                 int threadsPerBlock)
{
    if (numBlocks == 0) return;
    size_t dataSize = numBlocks * RIJNDAEL256_BLOCK_SIZE;
    uint8_t *d_in, *d_out;
    CUDA_CHECK(cudaMalloc(&d_in, dataSize));
    CUDA_CHECK(cudaMalloc(&d_out, dataSize));
    CUDA_CHECK(cudaMemcpy(d_in, plaintext, dataSize, cudaMemcpyHostToDevice));

    ecb_setup_keys(rk);

    int gridSize = rijndael_checked_grid_size(
        numBlocks, threadsPerBlock, "rijndael256_ecb_encrypt_v2");
    rijndael256_ecb_encrypt_kernel_v2<<<gridSize, threadsPerBlock>>>(
        d_in, d_out, numBlocks, rk->rounds);
    CUDA_CHECK(cudaGetLastError());
    CUDA_CHECK(cudaDeviceSynchronize());

    CUDA_CHECK(cudaMemcpy(ciphertext, d_out, dataSize, cudaMemcpyDeviceToHost));
    CUDA_CHECK(cudaFree(d_in));
    CUDA_CHECK(cudaFree(d_out));
}

void rijndael256_ecb_decrypt_v2(const uint8_t *ciphertext, uint8_t *plaintext,
                                 const RijndaelKey *rk, size_t numBlocks,
                                 int threadsPerBlock)
{
    if (numBlocks == 0) return;
    size_t dataSize = numBlocks * RIJNDAEL256_BLOCK_SIZE;
    uint8_t *d_in, *d_out;
    CUDA_CHECK(cudaMalloc(&d_in, dataSize));
    CUDA_CHECK(cudaMalloc(&d_out, dataSize));
    CUDA_CHECK(cudaMemcpy(d_in, ciphertext, dataSize, cudaMemcpyHostToDevice));

    ecb_setup_keys(rk);

    int gridSize = rijndael_checked_grid_size(
        numBlocks, threadsPerBlock, "rijndael256_ecb_decrypt_v2");
    rijndael256_ecb_decrypt_kernel_v2<<<gridSize, threadsPerBlock>>>(
        d_in, d_out, numBlocks, rk->rounds);
    CUDA_CHECK(cudaGetLastError());
    CUDA_CHECK(cudaDeviceSynchronize());

    CUDA_CHECK(cudaMemcpy(plaintext, d_out, dataSize, cudaMemcpyDeviceToHost));
    CUDA_CHECK(cudaFree(d_in));
    CUDA_CHECK(cudaFree(d_out));
}

void rijndael256_ecb_encrypt_v3(const uint8_t *plaintext, uint8_t *ciphertext,
                                 const RijndaelKey *rk, size_t numBlocks,
                                 int threadsPerBlock)
{
    if (numBlocks == 0) return;
    size_t dataSize = numBlocks * RIJNDAEL256_BLOCK_SIZE;
    uint8_t *d_in, *d_out;
    CUDA_CHECK(cudaMalloc(&d_in, dataSize));
    CUDA_CHECK(cudaMalloc(&d_out, dataSize));
    CUDA_CHECK(cudaMemcpy(d_in, plaintext, dataSize, cudaMemcpyHostToDevice));

    ecb_setup_keys(rk);

    int gridSize = rijndael_checked_grid_size(
        numBlocks, threadsPerBlock, "rijndael256_ecb_encrypt_v3");
    rijndael256_ecb_encrypt_kernel_v3<<<gridSize, threadsPerBlock>>>(
        d_in, d_out, numBlocks, rk->rounds);
    CUDA_CHECK(cudaGetLastError());
    CUDA_CHECK(cudaDeviceSynchronize());

    CUDA_CHECK(cudaMemcpy(ciphertext, d_out, dataSize, cudaMemcpyDeviceToHost));
    CUDA_CHECK(cudaFree(d_in));
    CUDA_CHECK(cudaFree(d_out));
}

void rijndael256_ecb_decrypt_v3(const uint8_t *ciphertext, uint8_t *plaintext,
                                 const RijndaelKey *rk, size_t numBlocks,
                                 int threadsPerBlock)
{
    if (numBlocks == 0) return;
    size_t dataSize = numBlocks * RIJNDAEL256_BLOCK_SIZE;
    uint8_t *d_in, *d_out;
    CUDA_CHECK(cudaMalloc(&d_in, dataSize));
    CUDA_CHECK(cudaMalloc(&d_out, dataSize));
    CUDA_CHECK(cudaMemcpy(d_in, ciphertext, dataSize, cudaMemcpyHostToDevice));

    ecb_setup_keys(rk);

    int gridSize = rijndael_checked_grid_size(
        numBlocks, threadsPerBlock, "rijndael256_ecb_decrypt_v3");
    rijndael256_ecb_decrypt_kernel_v3<<<gridSize, threadsPerBlock>>>(
        d_in, d_out, numBlocks, rk->rounds);
    CUDA_CHECK(cudaGetLastError());
    CUDA_CHECK(cudaDeviceSynchronize());

    CUDA_CHECK(cudaMemcpy(plaintext, d_out, dataSize, cudaMemcpyDeviceToHost));
    CUDA_CHECK(cudaFree(d_in));
    CUDA_CHECK(cudaFree(d_out));
}

/* ====================================================================
 * Kernel-Only API: setup keys + launch on device pointers
 * ==================================================================== */

void rijndael256_ecb_setup_keys(const RijndaelKey *rk) {
    ecb_setup_keys(rk);
}

void rijndael256_ecb_launch_encrypt_v2(uint8_t *d_in, uint8_t *d_out,
                                        const RijndaelKey *rk, size_t numBlocks,
                                        int threadsPerBlock)
{
    if (numBlocks == 0) return;
    int gridSize = rijndael_checked_grid_size(
        numBlocks, threadsPerBlock, "rijndael256_ecb_launch_encrypt_v2");
    rijndael256_ecb_encrypt_kernel_v2<<<gridSize, threadsPerBlock>>>(
        d_in, d_out, numBlocks, rk->rounds);
    CUDA_CHECK(cudaGetLastError());
}

void rijndael256_ecb_launch_decrypt_v2(uint8_t *d_in, uint8_t *d_out,
                                        const RijndaelKey *rk, size_t numBlocks,
                                        int threadsPerBlock)
{
    if (numBlocks == 0) return;
    int gridSize = rijndael_checked_grid_size(
        numBlocks, threadsPerBlock, "rijndael256_ecb_launch_decrypt_v2");
    rijndael256_ecb_decrypt_kernel_v2<<<gridSize, threadsPerBlock>>>(
        d_in, d_out, numBlocks, rk->rounds);
    CUDA_CHECK(cudaGetLastError());
}

void rijndael256_ecb_launch_encrypt_v3(uint8_t *d_in, uint8_t *d_out,
                                        const RijndaelKey *rk, size_t numBlocks,
                                        int threadsPerBlock)
{
    if (numBlocks == 0) return;
    int gridSize = rijndael_checked_grid_size(
        numBlocks, threadsPerBlock, "rijndael256_ecb_launch_encrypt_v3");
    rijndael256_ecb_encrypt_kernel_v3<<<gridSize, threadsPerBlock>>>(
        d_in, d_out, numBlocks, rk->rounds);
    CUDA_CHECK(cudaGetLastError());
}

void rijndael256_ecb_launch_decrypt_v3(uint8_t *d_in, uint8_t *d_out,
                                        const RijndaelKey *rk, size_t numBlocks,
                                        int threadsPerBlock)
{
    if (numBlocks == 0) return;
    int gridSize = rijndael_checked_grid_size(
        numBlocks, threadsPerBlock, "rijndael256_ecb_launch_decrypt_v3");
    rijndael256_ecb_decrypt_kernel_v3<<<gridSize, threadsPerBlock>>>(
        d_in, d_out, numBlocks, rk->rounds);
    CUDA_CHECK(cudaGetLastError());
}
