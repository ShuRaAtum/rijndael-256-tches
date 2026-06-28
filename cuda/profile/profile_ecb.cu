#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cuda_runtime.h>
#include "rijndael.h"
#include "rijndael_ecb.cuh"

/*
 * Profiling driver for ECB V2 (Compact, 8KiB) vs V3 (CF, 36KiB) kernels.
 * Tests both 128 and 256 threads-per-block configurations.
 * Designed for Nsight Compute: each kernel launch is a distinct profiling target.
 *
 * Usage:
 *   ./profile_ecb          # default: 1M blocks (32 MiB)
 *   ./profile_ecb <blocks> # custom block count (in units of 1024)
 */

static void run_profile(const RijndaelKey *rk,
                        uint8_t *d_in, uint8_t *d_out,
                        size_t numBlocks, int tpb, const char *label)
{
    printf("--- %s (tpb=%d, %zu blocks, %zu MiB) ---\n",
           label, tpb, numBlocks,
           numBlocks * RIJNDAEL256_BLOCK_SIZE / (1024 * 1024));

    /* Warmup (skipped by ncu --launch-skip if desired) */
    rijndael256_ecb_launch_encrypt_v2(d_in, d_out, rk, numBlocks, tpb);
    CUDA_CHECK(cudaDeviceSynchronize());
    rijndael256_ecb_launch_encrypt_v3(d_in, d_out, rk, numBlocks, tpb);
    CUDA_CHECK(cudaDeviceSynchronize());

    /* ---- Profiled encrypt launches ---- */
    rijndael256_ecb_launch_encrypt_v2(d_in, d_out, rk, numBlocks, tpb);
    CUDA_CHECK(cudaDeviceSynchronize());

    rijndael256_ecb_launch_encrypt_v3(d_in, d_out, rk, numBlocks, tpb);
    CUDA_CHECK(cudaDeviceSynchronize());

    /* ---- Profiled decrypt launches ---- */
    rijndael256_ecb_launch_decrypt_v2(d_in, d_out, rk, numBlocks, tpb);
    CUDA_CHECK(cudaDeviceSynchronize());

    rijndael256_ecb_launch_decrypt_v3(d_in, d_out, rk, numBlocks, tpb);
    CUDA_CHECK(cudaDeviceSynchronize());

    printf("--- %s done ---\n\n", label);
}

int main(int argc, char **argv) {
    size_t numK = 1024; /* default 1024K = 1M blocks */
    if (argc > 1)
        numK = (size_t)atol(argv[1]);

    const size_t numBlocks = numK * 1024;
    const size_t dataSize = numBlocks * RIJNDAEL256_BLOCK_SIZE;

    printf("Rijndael-256 ECB Profile: %zu blocks (%zu MiB)\n\n",
           numBlocks, dataSize / (1024 * 1024));

    /* Setup key (256-bit) */
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 0x11 + 0x0F);

    RijndaelKey rk;
    rijndaelSetupKey(key, 256, &rk);

    /* Allocate device memory */
    uint8_t *d_in, *d_out;
    CUDA_CHECK(cudaMalloc(&d_in, dataSize));
    CUDA_CHECK(cudaMalloc(&d_out, dataSize));
    CUDA_CHECK(cudaMemset(d_in, 0xA5, dataSize));

    /* Setup keys in constant memory */
    rijndael256_ecb_setup_keys(&rk);

    /* Pass 1: tpb=128 (optimal for V2 Compact) */
    run_profile(&rk, d_in, d_out, numBlocks, 128, "Pass 1");

    /* Pass 2: tpb=256 */
    run_profile(&rk, d_in, d_out, numBlocks, 256, "Pass 2");

    CUDA_CHECK(cudaFree(d_in));
    CUDA_CHECK(cudaFree(d_out));

    printf("All profile launches complete.\n");
    return 0;
}
