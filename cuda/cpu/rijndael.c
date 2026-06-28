#include "rijndael.h"
#include "rijndael_tables.h"
#include <string.h>

/*
 * Rijndael-256 implementation
 * Block Size: 256 bits (Nb = 8)
 * Key Sizes: 128, 192, 256 bits
 */

#define Nb 8

// Helper to load 32-bit big-endian word
static uint32_t get_word_be(const uint8_t *b) {
    return ((uint32_t)b[0] << 24) |
           ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8) |
           (uint32_t)b[3];
}

// Helper to store 32-bit big-endian word
static void put_word_be(uint32_t w, uint8_t *b) {
    b[0] = (w >> 24) & 0xFF;
    b[1] = (w >> 16) & 0xFF;
    b[2] = (w >> 8) & 0xFF;
    b[3] = w & 0xFF;
}

static uint32_t SubWord(uint32_t w) {
    return (SBox[(w >> 24) & 0xFF] << 24) |
           (SBox[(w >> 16) & 0xFF] << 16) |
           (SBox[(w >> 8) & 0xFF] << 8) |
           (SBox[w & 0xFF]);
}

static uint32_t RotWord(uint32_t w) {
    return (w << 8) | (w >> 24);
}

// Function to apply Inverse MixColumns to a word
static uint32_t InvMixColumnWord(uint32_t w) {
    return InvMix0[(w >> 24) & 0xFF] ^
           InvMix1[(w >> 16) & 0xFF] ^
           InvMix2[(w >> 8) & 0xFF] ^
           InvMix3[w & 0xFF];
}

int rijndaelSetupKey(const uint8_t *key, int keyBits, RijndaelKey *rk) {
    if (keyBits != 128 && keyBits != 192 && keyBits != 256) {
        return -1;
    }
    
    int Nk = keyBits / 32;
    int Nr = (Nk > Nb ? Nk : Nb) + 6;
    rk->rounds = Nr;

    int i = 0;
    while (i < Nk) {
        rk->roundKey[i] = get_word_be(key + 4 * i);
        i++;
    }

    uint32_t temp;
    while (i < (Nr + 1) * Nb) {
        temp = rk->roundKey[i - 1];
        if (i % Nk == 0) {
            temp = SubWord(RotWord(temp)) ^ Rcon[i / Nk];
        } else if (Nk > 6 && (i % Nk == 4)) {
            temp = SubWord(temp);
        }
        rk->roundKey[i] = rk->roundKey[i - Nk] ^ temp;
        i++;
    }
    return 0;
}

void rijndaelEncrypt(const RijndaelKey *rk, const uint8_t *pt, uint8_t *ct) {
    uint32_t s[Nb];
    uint32_t t[Nb];
    int Nr = rk->rounds;

    // Load state
    for (int i = 0; i < Nb; i++) {
        s[i] = get_word_be(pt + 4 * i);
    }

    // AddRoundKey (Initial)
    for (int i = 0; i < Nb; i++) {
        s[i] ^= rk->roundKey[i];
    }

    // Rounds 1 to Nr-1
    const uint32_t *w = rk->roundKey + Nb; // Points to start of round 1 key
    for (int r = 1; r < Nr; r++) {
        for (int i = 0; i < Nb; i++) {
            t[i] = Te0[(s[i] >> 24) & 0xFF] ^
                   Te1[(s[(i + 1) % Nb] >> 16) & 0xFF] ^
                   Te2[(s[(i + 3) % Nb] >> 8) & 0xFF] ^
                   Te3[(s[(i + 4) % Nb]) & 0xFF] ^
                   w[i];
        }
        memcpy(s, t, sizeof(s));
        w += Nb;
    }

    // Final Round
    for (int i = 0; i < Nb; i++) {
        uint8_t b0 = SBox[(s[i] >> 24) & 0xFF];
        uint8_t b1 = SBox[(s[(i + 1) % Nb] >> 16) & 0xFF];
        uint8_t b2 = SBox[(s[(i + 3) % Nb] >> 8) & 0xFF];
        uint8_t b3 = SBox[(s[(i + 4) % Nb]) & 0xFF];
        
        t[i] = ((uint32_t)b0 << 24) |
               ((uint32_t)b1 << 16) |
               ((uint32_t)b2 << 8) |
               (uint32_t)b3;
        
        t[i] ^= w[i];
    }

    // Output
    for (int i = 0; i < Nb; i++) {
        put_word_be(t[i], ct + 4 * i);
    }
}

void rijndaelDecrypt(const RijndaelKey *rk, const uint8_t *ct, uint8_t *pt) {
    uint32_t s[Nb];
    uint32_t t[Nb];
    int Nr = rk->rounds;

    // Use a large buffer for transformed keys.
    // Max rounds = 14. Max words = 15*8 = 120 words.
    uint32_t decKeys[120]; 

    // Prepare Decryption Keys:
    // First round key (Nr) is used as is (Initial AddRoundKey).
    // Middle round keys (Nr-1 to 1) must be transformed by InvMixColumns.
    // Last round key (0) is used as is.
    
    // Copy all first
    for(int i = 0; i < (Nr + 1) * Nb; i++) {
        decKeys[i] = rk->roundKey[i];
    }
    
    // Transform middle rounds
    for (int r = 1; r < Nr; r++) {
        for (int i = 0; i < Nb; i++) {
            decKeys[r * Nb + i] = InvMixColumnWord(decKeys[r * Nb + i]);
        }
    }

    // Load state
    for (int i = 0; i < Nb; i++) {
        s[i] = get_word_be(ct + 4 * i);
    }

    // Initial AddRoundKey (uses Round Nr key, which is the last block of keys)
    const uint32_t *w = decKeys + Nr * Nb;
    for (int i = 0; i < Nb; i++) {
        s[i] ^= w[i];
    }

    w -= Nb; // Point to start of previous round key

    // Rounds Nr-1 down to 1
    // Inverse ShiftRows: 0, 7, 5, 4
    for (int r = Nr - 1; r >= 1; r--) {
        for (int i = 0; i < Nb; i++) {
             t[i] = Td0[(s[i] >> 24) & 0xFF] ^
                    Td1[(s[(i + 7) % Nb] >> 16) & 0xFF] ^
                    Td2[(s[(i + 5) % Nb] >> 8) & 0xFF] ^
                    Td3[(s[(i + 4) % Nb]) & 0xFF] ^
                    w[i];
        }
        memcpy(s, t, sizeof(s));
        w -= Nb;
    }

    // Final Round (Inverse)
    // InvSubBytes + InvShiftRows + AddRoundKey (Round 0 key)
    for (int i = 0; i < Nb; i++) {
        uint8_t b0 = InvSBox[(s[i] >> 24) & 0xFF];
        uint8_t b1 = InvSBox[(s[(i + 7) % Nb] >> 16) & 0xFF];
        uint8_t b2 = InvSBox[(s[(i + 5) % Nb] >> 8) & 0xFF];
        uint8_t b3 = InvSBox[(s[(i + 4) % Nb]) & 0xFF];
        
        t[i] = ((uint32_t)b0 << 24) |
               ((uint32_t)b1 << 16) |
               ((uint32_t)b2 << 8) |
               (uint32_t)b3;
        
        t[i] ^= w[i];
    }

    // Output
    for (int i = 0; i < Nb; i++) {
        put_word_be(t[i], pt + 4 * i);
    }
}
