#ifndef RIJNDAEL_ES_CUH
#define RIJNDAEL_ES_CUH

#include <stdint.h>
#include <stddef.h>
#include "rijndael.h"
#include "rijndael_cuda_core.cuh"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Rijndael-256 Exhaustive Search (ES) - CUDA Host API
 *
 * Brute-force key search: vary lower 64 bits of the key.
 * Each thread: expand key -> encrypt known plaintext -> compare with known ciphertext.
 * Early termination via volatile device flag.
 */

typedef struct {
    int found;
    uint64_t keyOffset;
} ESResult;

/* ---- Full search: setup + launch + sync + get result ---- */
void rijndael256_es_search_v2(const uint8_t *knownPt, const uint8_t *knownCt,
                              const uint8_t *baseKey, int keyBits,
                              uint64_t baseOffset, uint64_t searchRange,
                              ESResult *result,
                              int threadsPerBlock, int numCudaBlocks);

void rijndael256_es_search_v3(const uint8_t *knownPt, const uint8_t *knownCt,
                              const uint8_t *baseKey, int keyBits,
                              uint64_t baseOffset, uint64_t searchRange,
                              ESResult *result,
                              int threadsPerBlock, int numCudaBlocks);

/* ---- Granular API: separate setup / launch / result retrieval ---- */
void rijndael256_es_setup(const uint8_t *knownPt, const uint8_t *knownCt,
                          const uint8_t *baseKey, int keyBits);

void rijndael256_es_launch_v2(int keyBits,
                              uint64_t baseOffset, uint64_t searchRange,
                              int threadsPerBlock, int numCudaBlocks);

void rijndael256_es_launch_v3(int keyBits,
                              uint64_t baseOffset, uint64_t searchRange,
                              int threadsPerBlock, int numCudaBlocks);

void rijndael256_es_get_result(ESResult *result);

#ifdef __cplusplus
}
#endif

#endif /* RIJNDAEL_ES_CUH */
