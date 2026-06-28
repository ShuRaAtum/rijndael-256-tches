#ifndef RIJNDAEL_CUDA_TABLES_CUH
#define RIJNDAEL_CUDA_TABLES_CUH

#include <stdint.h>

/*
 * Extern declarations for Rijndael-256 device T-tables.
 * Definitions are in rijndael_cuda_tables.cu.
 *
 * Encryption:
 *   d_Te0..d_Te3     - Main round T-tables (SubBytes + ShiftRows + MixColumns)
 *   d_T4_0..d_T4_3   - Final round tables (SubBytes only, shifted into position)
 *
 * Decryption:
 *   d_Td0..d_Td3     - Main round inverse T-tables
 *   d_T4i_0..d_T4i_3 - Final round inverse tables
 *
 * Key schedule:
 *   d_SBox, d_InvSBox - S-box tables
 */

/* Encryption T-tables */
extern __device__ uint32_t d_Te0[256];
extern __device__ uint32_t d_Te1[256];
extern __device__ uint32_t d_Te2[256];
extern __device__ uint32_t d_Te3[256];

/* Final round encryption tables */
extern __device__ uint32_t d_T4_0[256];
extern __device__ uint32_t d_T4_1[256];
extern __device__ uint32_t d_T4_2[256];
extern __device__ uint32_t d_T4_3[256];

/* S-Boxes */
extern __device__ uint8_t d_SBox[256];
extern __device__ uint8_t d_InvSBox[256];

/* Decryption T-tables */
extern __device__ uint32_t d_Td0[256];
extern __device__ uint32_t d_Td1[256];
extern __device__ uint32_t d_Td2[256];
extern __device__ uint32_t d_Td3[256];

/* Final round decryption tables */
extern __device__ uint32_t d_T4i_0[256];
extern __device__ uint32_t d_T4i_1[256];
extern __device__ uint32_t d_T4i_2[256];
extern __device__ uint32_t d_T4i_3[256];

#endif /* RIJNDAEL_CUDA_TABLES_CUH */
