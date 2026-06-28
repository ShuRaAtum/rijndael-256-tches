#ifndef RIJNDAEL_CTR_CUH
#define RIJNDAEL_CTR_CUH

#include <stdint.h>
#include <stddef.h>
#include "rijndael.h"
#include "rijndael_cuda_core.cuh"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Rijndael-256 CTR Mode - CUDA Host API
 *
 * Counter: 256-bit nonce, lower 64 bits incremented by thread index.
 * If plaintext is NULL, outputs keystream only.
 * CTR is symmetric: encrypt == decrypt (XOR with keystream).
 */

/* ---- Host wrapper: allocate, copy, crypt, copy back ---- */
void rijndael256_ctr_crypt_v2(const uint8_t *nonce,
                              const uint8_t *plaintext, uint8_t *output,
                              const RijndaelKey *rk, size_t numBlocks,
                              int threadsPerBlock);

void rijndael256_ctr_crypt_v3(const uint8_t *nonce,
                              const uint8_t *plaintext, uint8_t *output,
                              const RijndaelKey *rk, size_t numBlocks,
                              int threadsPerBlock);

/* ---- Kernel-only API ---- */
void rijndael256_ctr_setup(const uint8_t *nonce, const RijndaelKey *rk);

void rijndael256_ctr_launch_v2(uint8_t *d_in, uint8_t *d_out,
                               const RijndaelKey *rk, size_t numBlocks,
                               int threadsPerBlock);

void rijndael256_ctr_launch_v3(uint8_t *d_in, uint8_t *d_out,
                               const RijndaelKey *rk, size_t numBlocks,
                               int threadsPerBlock);

#ifdef __cplusplus
}
#endif

#endif /* RIJNDAEL_CTR_CUH */
