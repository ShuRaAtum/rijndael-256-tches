#ifndef RIJNDAEL_ECB_CUH
#define RIJNDAEL_ECB_CUH

#include <stdint.h>
#include <stddef.h>
#include "rijndael.h"
#include "rijndael_cuda_core.cuh"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Rijndael-256 ECB Mode - CUDA Host API
 *
 * V2: Simple shared memory (8 KiB) - 4 T-tables + 4 final-round tables
 * V3: Bank-conflict-free (36 KiB) - Te0/Td0 replicated across 32 banks
 */

/* ---- Prepare decryption keys (InvMixColumns on middle rounds) ---- */
void rijndael256_prepare_dec_keys(const RijndaelKey *rk, uint32_t *decRk);

/* ---- Host wrapper: allocate GPU memory, copy, encrypt/decrypt, copy back ---- */
void rijndael256_ecb_encrypt_v2(const uint8_t *plaintext, uint8_t *ciphertext,
                                const RijndaelKey *rk, size_t numBlocks,
                                int threadsPerBlock);

void rijndael256_ecb_decrypt_v2(const uint8_t *ciphertext, uint8_t *plaintext,
                                const RijndaelKey *rk, size_t numBlocks,
                                int threadsPerBlock);

void rijndael256_ecb_encrypt_v3(const uint8_t *plaintext, uint8_t *ciphertext,
                                const RijndaelKey *rk, size_t numBlocks,
                                int threadsPerBlock);

void rijndael256_ecb_decrypt_v3(const uint8_t *ciphertext, uint8_t *plaintext,
                                const RijndaelKey *rk, size_t numBlocks,
                                int threadsPerBlock);

/* ---- Kernel-only API: setup keys + launch on pre-allocated device pointers ---- */
void rijndael256_ecb_setup_keys(const RijndaelKey *rk);

void rijndael256_ecb_launch_encrypt_v2(uint8_t *d_in, uint8_t *d_out,
                                       const RijndaelKey *rk, size_t numBlocks,
                                       int threadsPerBlock);

void rijndael256_ecb_launch_decrypt_v2(uint8_t *d_in, uint8_t *d_out,
                                       const RijndaelKey *rk, size_t numBlocks,
                                       int threadsPerBlock);

void rijndael256_ecb_launch_encrypt_v3(uint8_t *d_in, uint8_t *d_out,
                                       const RijndaelKey *rk, size_t numBlocks,
                                       int threadsPerBlock);

void rijndael256_ecb_launch_decrypt_v3(uint8_t *d_in, uint8_t *d_out,
                                       const RijndaelKey *rk, size_t numBlocks,
                                       int threadsPerBlock);

#ifdef __cplusplus
}
#endif

#endif /* RIJNDAEL_ECB_CUH */
