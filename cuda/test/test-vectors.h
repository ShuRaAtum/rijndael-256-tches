#ifndef TEST_VECTORS_H
#define TEST_VECTORS_H

#include <stdint.h>

/**
 * Rijndael-256 Known Answer Test (KAT) Vectors
 *
 * Source: Rijndael specification document
 * All inputs (plaintext and key) are zero (all bytes = 0x00)
 * The hex strings represent the expected ciphertext output
 *
 * Format: {blockSize, keySize, plaintextHex, ciphertextHex}
 */

typedef struct {
    int blockSize;      // Block size in bits (always 256 for Rijndael-256)
    int keySize;        // Key size in bits (128, 192, or 256)
    const char* plaintext;   // Plaintext as hex string (64 chars = 32 bytes)
    const char* ciphertext;  // Expected ciphertext as hex string (64 chars = 32 bytes)
} RijndaelTestVector;

/**
 * Test vectors with all-zero input
 * Plaintext: 32 bytes of 0x00
 * Key: keySize/8 bytes of 0x00
 * Ciphertext: Expected output from Rijndael-256 specification
 */
static const RijndaelTestVector RIJNDAEL_256_TEST_VECTORS[] = {
    // Block length 256, Key length 128 -- all-zero
    {
        256,
        128,
        "00000000000000000000000000000000"
        "00000000000000000000000000000000",
        "A693B288DF7DAE5B1757640276439230"
        "DB77C4CD7A871E24D6162E54AF434891"
    },

    // Block length 256, Key length 192 -- all-zero
    {
        256,
        192,
        "00000000000000000000000000000000"
        "00000000000000000000000000000000",
        "F927363EF5B3B4984A9EB9109844152E"
        "C167F08102644E3F9028070433DF9F2A"
    },

    // Block length 256, Key length 256 -- all-zero
    {
        256,
        256,
        "00000000000000000000000000000000"
        "00000000000000000000000000000000",
        "C6227E7740B7E53B5CB77865278EAB07"
        "26F62366D9AABAD908936123A1FC8AF3"
    }
};

#define NUM_TEST_VECTORS (sizeof(RIJNDAEL_256_TEST_VECTORS) / sizeof(RijndaelTestVector))

/**
 * Non-trivial test vectors (non-zero key and plaintext)
 *
 * Key:  key[i] = i * 0x11 + 0x0F  (for i = 0..keySize/8 - 1)
 * PT:   pt[i]  = i * 0x07 + 0xA5  (for i = 0..31)
 * Ciphertexts generated from CPU reference implementation and
 * cross-verified against GPU V2/V3 outputs.
 */
typedef struct {
    int keySize;
    const char *key;
    const char *plaintext;
    const char *ciphertext;
} RijndaelNonTrivialVector;

static const RijndaelNonTrivialVector RIJNDAEL_256_NONTRIVIAL_VECTORS[] = {
    // 128-bit key, non-trivial
    {
        128,
        "0F2031425364758697A8B9CADBECFD0E",
        "A5ACB3BAC1C8CFD6DDE4EBF2F900070E"
        "151C232A31383F464D545B626970777E",
        "CC8109F1BE282CEFF4ECF9FDF2E79D79"
        "B5CF113D4715DA3367CE35E809400F0F"
    },

    // 192-bit key, non-trivial
    {
        192,
        "0F2031425364758697A8B9CADBECFD0E"
        "1F30415263748596",
        "A5ACB3BAC1C8CFD6DDE4EBF2F900070E"
        "151C232A31383F464D545B626970777E",
        "D797C5089BC526EE49C4B45A9376E47B"
        "75193E39ED5DDA85B6F2742662ED8CE6"
    },

    // 256-bit key, non-trivial
    {
        256,
        "0F2031425364758697A8B9CADBECFD0E"
        "1F30415263748596A7B8C9DAEBFC0D1E",
        "A5ACB3BAC1C8CFD6DDE4EBF2F900070E"
        "151C232A31383F464D545B626970777E",
        "933F71C1547B4513918E988E4854B047"
        "55A12CFE0538E249EFC20D2316CFFB86"
    }
};

#define NUM_NONTRIVIAL_VECTORS (sizeof(RIJNDAEL_256_NONTRIVIAL_VECTORS) / sizeof(RijndaelNonTrivialVector))

/**
 * Helper function to convert hex string to byte array
 *
 * @param hexStr Hex string (2 chars per byte, no 0x prefix)
 * @param bytes Output byte array (must be pre-allocated)
 * @param numBytes Number of bytes to convert
 *
 * Example: "A5B6" -> bytes[0]=0xA5, bytes[1]=0xB6
 */
static inline void hexStringToBytes(const char* hexStr, uint8_t* bytes, int numBytes) {
    for (int i = 0; i < numBytes; i++) {
        unsigned int byte;
        sscanf(hexStr + 2*i, "%2x", &byte);
        bytes[i] = (uint8_t)byte;
    }
}

/**
 * Helper function to convert byte array to hex string
 *
 * @param bytes Input byte array
 * @param numBytes Number of bytes to convert
 * @param hexStr Output hex string (must be pre-allocated, size >= 2*numBytes + 1)
 *
 * Example: bytes[0]=0xA5, bytes[1]=0xB6 -> "A5B6"
 */
static inline void bytesToHexString(const uint8_t* bytes, int numBytes, char* hexStr) {
    for (int i = 0; i < numBytes; i++) {
        sprintf(hexStr + 2*i, "%02X", bytes[i]);
    }
    hexStr[2*numBytes] = '\0';
}

/**
 * Helper function to compare two byte arrays
 *
 * @param a First byte array
 * @param b Second byte array
 * @param numBytes Number of bytes to compare
 * @return 1 if equal, 0 if different
 */
static inline int bytesEqual(const uint8_t* a, const uint8_t* b, int numBytes) {
    for (int i = 0; i < numBytes; i++) {
        if (a[i] != b[i]) return 0;
    }
    return 1;
}

#endif // TEST_VECTORS_H
