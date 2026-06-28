//
//  rijndael256_neon.S
//  Rijndael-256 ARM64 NEON SIMD Implementation
//
//  4-block parallel encryption using TBL/TBX based S-box lookup
//  Block size: 256 bits (32 bytes)
//  ShiftRows pattern: (0, 1, 3, 4) - different from AES-128
//

//=============================================================================
// Data Section
//=============================================================================
.section __DATA,__data
.align 4

// S-box lookup table (256 bytes) - AES forward S-box
.globl _rijndael256_sbox
_rijndael256_sbox:
rijndael256_sbox:
    .byte 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76
    .byte 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0
    .byte 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15
    .byte 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75
    .byte 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84
    .byte 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf
    .byte 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8
    .byte 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2
    .byte 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73
    .byte 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb
    .byte 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79
    .byte 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08
    .byte 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a
    .byte 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e
    .byte 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf
    .byte 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16

// ShiftRows mask for 256-bit block (column-major layout)
.align 4
mask_shiftrows_L:
    .byte 0, 5, 14, 19,   4, 9, 18, 23,   8, 13, 22, 27,   12, 17, 26, 31

.align 4
mask_shiftrows_R:
    .byte 16, 21, 30, 3,   20, 25, 2, 7,   24, 29, 6, 11,   28, 1, 10, 15

// MixColumns rotation masks (contiguous for single ld1)
.align 4
mixcol_masks:
mixcol_rot1:
    .byte 1, 2, 3, 0,  5, 6, 7, 4,  9, 10, 11, 8,  13, 14, 15, 12
mixcol_rot2:
    .byte 2, 3, 0, 1,  6, 7, 4, 5,  10, 11, 8, 9,  14, 15, 12, 13

//=============================================================================
// Text Section
//=============================================================================
.section __TEXT,__text
.align 4

/*
 * Register allocation for 4PT (4-block parallel):
 *
 * State registers (4 plaintexts, each 32 bytes = 2 regs):
 *   v0-v1:   PT0 (L: cols 0-3, R: cols 4-7)
 *   v2-v3:   PT1
 *   v4-v5:   PT2
 *   v6-v7:   PT3
 *
 * Callee-saved registers (must be preserved):
 *   v8-v11:  S-box 0-63 bytes (cached for TBL first stage)
 *   v12:     Constant 0x40 (for TBL index adjustment)
 *   v13:     ShiftRows mask L
 *   v14:     ShiftRows mask R
 *   v15:     MixColumns constant 0x1B
 *
 * Temporary registers:
 *   v16-v19: S-box 64-127 or MixColumns rotation masks
 *   v20-v23: S-box 128-191
 *   v24-v27: S-box 192-255
 *   v28-v29: Round key L/R
 *   v30-v31: Working temporaries
 */

//=============================================================================
// S-box lookup with TBL/TBX for indices 0-255
//=============================================================================
.macro sbox_byte16 reg
    sub.16b v30, \reg, v12           // indices - 64
    tbl.16b \reg, {v8-v11}, \reg     // lookup 0-63
    sub.16b v31, v30, v12            // indices - 128
    tbx.16b \reg, {v16-v19}, v30     // extend 64-127
    sub.16b v30, v31, v12            // indices - 192
    tbx.16b \reg, {v20-v23}, v31     // extend 128-191
    tbx.16b \reg, {v24-v27}, v30     // extend 192-255
.endm

//=============================================================================
// SubBytes for all 4 blocks
//=============================================================================
.macro subbytes_4pt sbox_addr
    add x4, \sbox_addr, #64
    ld1.16b {v16-v19}, [x4], #64
    ld1.16b {v20-v23}, [x4], #64
    ld1.16b {v24-v27}, [x4]

    sbox_byte16 v0
    sbox_byte16 v1
    sbox_byte16 v2
    sbox_byte16 v3
    sbox_byte16 v4
    sbox_byte16 v5
    sbox_byte16 v6
    sbox_byte16 v7
.endm

//=============================================================================
// ShiftRows for one 32-byte block
//=============================================================================
.macro shiftrows_block regL, regR
    mov.16b v30, \regL
    mov.16b v31, \regR
    tbl.16b \regL, {v30, v31}, v13
    tbl.16b \regR, {v30, v31}, v14
.endm

//=============================================================================
// ShiftRows for all 4 blocks
//=============================================================================
.macro shiftrows_4pt
    shiftrows_block v0, v1
    shiftrows_block v2, v3
    shiftrows_block v4, v5
    shiftrows_block v6, v7
.endm

//=============================================================================
// MixColumns for one 16-byte half-block
//=============================================================================
.macro mixcolumn_16b reg
    tbl.16b v28, {\reg}, v16         // rot1
    eor.16b v29, \reg, v28           // t2 = a ^ rot1(a)
    tbl.16b v30, {v29}, v17          // rot2(t2)
    eor.16b v31, v29, v30            // t_all

    sshr.16b v30, v29, #7
    shl.16b v29, v29, #1
    and.16b v30, v30, v15
    eor.16b v29, v29, v30            // xtime(t2)

    eor.16b \reg, \reg, v31
    eor.16b \reg, \reg, v29
.endm

//=============================================================================
// MixColumns for all 4 blocks
//=============================================================================
.macro mixcolumns_4pt
    mixcolumn_16b v0
    mixcolumn_16b v1
    mixcolumn_16b v2
    mixcolumn_16b v3
    mixcolumn_16b v4
    mixcolumn_16b v5
    mixcolumn_16b v6
    mixcolumn_16b v7
.endm

//=============================================================================
// AddRoundKey for all 4 blocks
//=============================================================================
.macro addroundkey_4pt rk_ptr
    ld1.16b {v28, v29}, [\rk_ptr], #32

    eor.16b v0, v0, v28
    eor.16b v1, v1, v29
    eor.16b v2, v2, v28
    eor.16b v3, v3, v29
    eor.16b v4, v4, v28
    eor.16b v5, v5, v29
    eor.16b v6, v6, v28
    eor.16b v7, v7, v29
.endm

//=============================================================================
// Main encryption function
//
// void rijndael256_encrypt_neon_4pt(const Rijndael256Key *ctx,
//                                    const uint8_t *pt,
//                                    uint8_t *ct);
//=============================================================================
.globl _rijndael256_encrypt_neon_4pt
.globl rijndael256_encrypt_neon_4pt
.align 4
_rijndael256_encrypt_neon_4pt:
rijndael256_encrypt_neon_4pt:
    // Save callee-saved registers
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    sub sp, sp, #128
    st1.16b {v8-v11}, [sp], #64
    st1.16b {v12-v15}, [sp], #64
    sub sp, sp, #128

    // Save arguments
    mov x5, x0                        // round key pointer
    mov x9, x2                        // ct output

    // Setup S-box address
    adrp x3, rijndael256_sbox@PAGE
    add x3, x3, rijndael256_sbox@PAGEOFF

    // Load S-box first 64 bytes
    ld1.16b {v8-v11}, [x3]

    // Setup constants
    movi.16b v12, #0x40
    movi.16b v15, #0x1b

    // Load ShiftRows masks
    adrp x4, mask_shiftrows_L@PAGE
    add x4, x4, mask_shiftrows_L@PAGEOFF
    ld1.16b {v13}, [x4]

    adrp x4, mask_shiftrows_R@PAGE
    add x4, x4, mask_shiftrows_R@PAGEOFF
    ld1.16b {v14}, [x4]

    // Cache MixColumns mask address in x8
    adrp x8, mixcol_masks@PAGE
    add x8, x8, mixcol_masks@PAGEOFF

    // Load 4 plaintext blocks
    ld1.16b {v0, v1}, [x1], #32
    ld1.16b {v2, v3}, [x1], #32
    ld1.16b {v4, v5}, [x1], #32
    ld1.16b {v6, v7}, [x1]

    // Initial AddRoundKey
    addroundkey_4pt x5

    // Rounds 1-13
    mov x6, #13

.Lround_loop:
    subbytes_4pt x3

    shiftrows_4pt

    // Load MixColumns rotation masks (both in one instruction)
    ld1.16b {v16, v17}, [x8]

    mixcolumns_4pt

    addroundkey_4pt x5

    subs x6, x6, #1
    b.ne .Lround_loop

    // Final round
    subbytes_4pt x3
    shiftrows_4pt
    addroundkey_4pt x5

    // Store ciphertext
    st1.16b {v0, v1}, [x9], #32
    st1.16b {v2, v3}, [x9], #32
    st1.16b {v4, v5}, [x9], #32
    st1.16b {v6, v7}, [x9]

    // Restore callee-saved registers
    ld1.16b {v8-v11}, [sp], #64
    ld1.16b {v12-v15}, [sp], #64
    mov sp, x29
    ldp x29, x30, [sp], #16

    ret

//=============================================================================
// Single block encryption wrapper
//=============================================================================
.globl _rijndael256_encrypt_neon
.globl rijndael256_encrypt_neon
.align 4
_rijndael256_encrypt_neon:
rijndael256_encrypt_neon:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    stp x19, x20, [sp, #-16]!
    sub sp, sp, #272

    mov x19, x2
    mov x20, x0

    // Replicate single block to 4 blocks
    ld1.16b {v0, v1}, [x1]
    mov x3, sp
    st1.16b {v0, v1}, [x3], #32
    st1.16b {v0, v1}, [x3], #32
    st1.16b {v0, v1}, [x3], #32
    st1.16b {v0, v1}, [x3]

    // Call 4PT function
    mov x0, x20
    mov x1, sp
    add x2, sp, #128
    bl _rijndael256_encrypt_neon_4pt

    // Copy first result block
    add x3, sp, #128
    ld1.16b {v0, v1}, [x3]
    st1.16b {v0, v1}, [x19]

    // Cleanup
    add sp, sp, #272
    ldp x19, x20, [sp], #16
    ldp x29, x30, [sp], #16
    ret
