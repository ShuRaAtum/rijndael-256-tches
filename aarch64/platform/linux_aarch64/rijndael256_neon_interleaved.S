//
//  rijndael256_neon_interleaved.S
//  Rijndael-256 ARM64 NEON SIMD Implementation - Interleaved Layout (Linux ELF)
//
//  True SIMD parallel encryption using column-interleaved data layout
//  Block size: 256 bits (32 bytes)
//  ShiftRows pattern: (0, 1, 3, 4) - different from AES-128
//
//  Data Layout:
//    v0: [A_col0 | B_col0 | C_col0 | D_col0]  (4 bytes each, 16 bytes total)
//    v1: [A_col1 | B_col1 | C_col1 | D_col1]
//    ...
//    v7: [A_col7 | B_col7 | C_col7 | D_col7]
//
//  This layout enables true SIMD parallelism for SubBytes and MixColumns

//=============================================================================
// Data Section
//=============================================================================
.section .data
.align 4

// S-box lookup table (256 bytes)
.globl rijndael256_sbox_il
rijndael256_sbox_il:
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

// Row masks for ShiftRows using BIT instruction
// BIT Vd, Vn, Vm: where Vm[i]=1, Vd[i]=Vn[i]; else Vd[i] unchanged
.align 4
sr_row_masks:
mask_row1:  // Select row 1: bytes 1, 5, 9, 13
    .byte 0x00, 0xFF, 0x00, 0x00,  0x00, 0xFF, 0x00, 0x00,  0x00, 0xFF, 0x00, 0x00,  0x00, 0xFF, 0x00, 0x00

mask_row2:  // Select row 2: bytes 2, 6, 10, 14
    .byte 0x00, 0x00, 0xFF, 0x00,  0x00, 0x00, 0xFF, 0x00,  0x00, 0x00, 0xFF, 0x00,  0x00, 0x00, 0xFF, 0x00

mask_row3:  // Select row 3: bytes 3, 7, 11, 15
    .byte 0x00, 0x00, 0x00, 0xFF,  0x00, 0x00, 0x00, 0xFF,  0x00, 0x00, 0x00, 0xFF,  0x00, 0x00, 0x00, 0xFF

// MixColumns rotation mask (rotate each 4-byte column by 1)
.align 4
mixcol_rot1_il:
    .byte 1, 2, 3, 0,  5, 6, 7, 4,  9, 10, 11, 8,  13, 14, 15, 12

// MixColumns rotation mask (rotate each 4-byte column by 2)
.align 4
mixcol_rot2_il:
    .byte 2, 3, 0, 1,  6, 7, 4, 5,  10, 11, 8, 9,  14, 15, 12, 13

//=============================================================================
// Text Section
//=============================================================================
.section .text
.align 4

/*
 * Register allocation for interleaved 4PT:
 *
 * State registers (column-interleaved):
 *   v0-v7:   Columns 0-7 (each holds same column from 4 blocks)
 *
 * Callee-saved registers:
 *   v8-v11:  S-box bytes 0-63 (cached)
 *   v12:     Constant 0x40 (for TBL index adjustment)
 *   v13:     MixColumns rotation mask 1
 *   v14:     MixColumns rotation mask 2
 *   v15:     MixColumns constant 0x1B
 *
 * Temporary registers:
 *   v16-v23: ShiftRows temps / S-box 64-255
 *   v24-v27: S-box 128-255
 *   v28-v31: Working temps / round key
 */

//=============================================================================
// S-box lookup macro for interleaved layout
//=============================================================================
.macro sbox_lookup_il reg
    sub v28.16b, \reg\().16b, v12.16b // indices - 64
    tbl \reg\().16b, {v8.16b-v11.16b}, \reg\().16b // lookup 0-63
    sub v29.16b, v28.16b, v12.16b // indices - 128
    tbx \reg\().16b, {v16.16b-v19.16b}, v28.16b // extend 64-127
    sub v28.16b, v29.16b, v12.16b // indices - 192
    tbx \reg\().16b, {v20.16b-v23.16b}, v29.16b // extend 128-191
    tbx \reg\().16b, {v24.16b-v27.16b}, v28.16b // extend 192-255
.endm

//=============================================================================
// SubBytes for all 8 column registers
//=============================================================================
.macro subbytes_il sbox_addr
    // Load S-box bytes 64-255 into temps
    add x4, \sbox_addr, #64
    ld1 {v16.16b-v19.16b}, [x4], #64
    ld1 {v20.16b-v23.16b}, [x4], #64
    ld1 {v24.16b-v27.16b}, [x4]

    // Apply S-box to all columns (true SIMD parallel)
    sbox_lookup_il v0
    sbox_lookup_il v1
    sbox_lookup_il v2
    sbox_lookup_il v3
    sbox_lookup_il v4
    sbox_lookup_il v5
    sbox_lookup_il v6
    sbox_lookup_il v7
.endm

//=============================================================================
// ShiftRows for interleaved layout using BIT instruction
//
// ShiftRows pattern (0, 1, 3, 4):
//   out[c] = (in[c].row0, in[(c+1)%8].row1, in[(c+3)%8].row2, in[(c+4)%8].row3)
//
// BIT Vd, Vn, Vm: where Vm[i]=1, Vd[i]=Vn[i]; else Vd[i] unchanged
//
// Loads masks from x7 (sr_row_masks address set in function prologue)
// Total: 41 instructions (1 ld1 + 8 MOV + 24 BIT + 8 MOV copy back)
// Output in v16-v23, then copy back to v0-v7
//=============================================================================
.macro shiftrows_il
    // Load row masks (v24=row1, v25=row2, v26=row3)
    ld1 {v24.16b, v25.16b, v26.16b}, [x7]

    // Phase 1: Initialize outputs with row0 (no shift)
    mov v16.16b, v0.16b // out0.row0 = v0
    mov v17.16b, v1.16b // out1.row0 = v1
    mov v18.16b, v2.16b // out2.row0 = v2
    mov v19.16b, v3.16b // out3.row0 = v3
    mov v20.16b, v4.16b // out4.row0 = v4
    mov v21.16b, v5.16b // out5.row0 = v5
    mov v22.16b, v6.16b // out6.row0 = v6
    mov v23.16b, v7.16b // out7.row0 = v7

    // Phase 2: Insert row1 (shift 1) - source is (c+1)%8
    bit v16.16b, v1.16b, v24.16b // out0.row1 = v1
    bit v17.16b, v2.16b, v24.16b // out1.row1 = v2
    bit v18.16b, v3.16b, v24.16b // out2.row1 = v3
    bit v19.16b, v4.16b, v24.16b // out3.row1 = v4
    bit v20.16b, v5.16b, v24.16b // out4.row1 = v5
    bit v21.16b, v6.16b, v24.16b // out5.row1 = v6
    bit v22.16b, v7.16b, v24.16b // out6.row1 = v7
    bit v23.16b, v0.16b, v24.16b // out7.row1 = v0

    // Phase 3: Insert row2 (shift 3) - source is (c+3)%8
    bit v16.16b, v3.16b, v25.16b // out0.row2 = v3
    bit v17.16b, v4.16b, v25.16b // out1.row2 = v4
    bit v18.16b, v5.16b, v25.16b // out2.row2 = v5
    bit v19.16b, v6.16b, v25.16b // out3.row2 = v6
    bit v20.16b, v7.16b, v25.16b // out4.row2 = v7
    bit v21.16b, v0.16b, v25.16b // out5.row2 = v0
    bit v22.16b, v1.16b, v25.16b // out6.row2 = v1
    bit v23.16b, v2.16b, v25.16b // out7.row2 = v2

    // Phase 4: Insert row3 (shift 4) - source is (c+4)%8
    bit v16.16b, v4.16b, v26.16b // out0.row3 = v4
    bit v17.16b, v5.16b, v26.16b // out1.row3 = v5
    bit v18.16b, v6.16b, v26.16b // out2.row3 = v6
    bit v19.16b, v7.16b, v26.16b // out3.row3 = v7
    bit v20.16b, v0.16b, v26.16b // out4.row3 = v0
    bit v21.16b, v1.16b, v26.16b // out5.row3 = v1
    bit v22.16b, v2.16b, v26.16b // out6.row3 = v2
    bit v23.16b, v3.16b, v26.16b // out7.row3 = v3

    // Phase 5: Copy results back to v0-v7
    mov v0.16b, v16.16b
    mov v1.16b, v17.16b
    mov v2.16b, v18.16b
    mov v3.16b, v19.16b
    mov v4.16b, v20.16b
    mov v5.16b, v21.16b
    mov v6.16b, v22.16b
    mov v7.16b, v23.16b
.endm

//=============================================================================
// MixColumns for one column register (true SIMD parallel)
//=============================================================================
.macro mixcolumn_il reg
    tbl v28.16b, {\reg\().16b}, v13.16b // rot1
    eor v29.16b, \reg\().16b, v28.16b // t2 = a ^ rot1(a)
    tbl v30.16b, {v29.16b}, v14.16b // rot2(t2)
    eor v31.16b, v29.16b, v30.16b // t_all

    sshr v30.16b, v29.16b, #7
    shl v29.16b, v29.16b, #1
    and v30.16b, v30.16b, v15.16b
    eor v29.16b, v29.16b, v30.16b // xtime(t2)

    eor \reg\().16b, \reg\().16b, v31.16b
    eor \reg\().16b, \reg\().16b, v29.16b
.endm

//=============================================================================
// MixColumns for all columns
//=============================================================================
.macro mixcolumns_il
    mixcolumn_il v0
    mixcolumn_il v1
    mixcolumn_il v2
    mixcolumn_il v3
    mixcolumn_il v4
    mixcolumn_il v5
    mixcolumn_il v6
    mixcolumn_il v7
.endm

//=============================================================================
// AddRoundKey for interleaved layout (broadcast each column)
//=============================================================================
.macro addroundkey_il rk_ptr
    ld1 {v28.16b, v29.16b}, [\rk_ptr], #32

    // Broadcast each 32-bit column and XOR
    dup v30.4s, v28.s[0]     // [c0, c0, c0, c0]
    eor v0.16b, v0.16b, v30.16b

    dup v30.4s, v28.s[1]     // [c1, c1, c1, c1]
    eor v1.16b, v1.16b, v30.16b

    dup v30.4s, v28.s[2]     // [c2, c2, c2, c2]
    eor v2.16b, v2.16b, v30.16b

    dup v30.4s, v28.s[3]     // [c3, c3, c3, c3]
    eor v3.16b, v3.16b, v30.16b

    dup v30.4s, v29.s[0]     // [c4, c4, c4, c4]
    eor v4.16b, v4.16b, v30.16b

    dup v30.4s, v29.s[1]     // [c5, c5, c5, c5]
    eor v5.16b, v5.16b, v30.16b

    dup v30.4s, v29.s[2]     // [c6, c6, c6, c6]
    eor v6.16b, v6.16b, v30.16b

    dup v30.4s, v29.s[3]     // [c7, c7, c7, c7]
    eor v7.16b, v7.16b, v30.16b
.endm

//=============================================================================
// Input conversion: sequential blocks to interleaved columns
// Uses 4x4 matrix transpose (twice for L and R halves)
//=============================================================================
.macro convert_to_interleaved
    // Input in v16-v23: v16,v17=PT0, v18,v19=PT1, v20,v21=PT2, v22,v23=PT3
    // Each PTx is 32 bytes in [L,R] format where L=[c0,c1,c2,c3], R=[c4,c5,c6,c7]

    // Transpose L halves (cols 0-3): v16, v18, v20, v22
    trn1 v0.4s, v16.4s, v18.4s // [A_c0, B_c0, A_c2, B_c2]
    trn2 v2.4s, v16.4s, v18.4s // [A_c1, B_c1, A_c3, B_c3]
    trn1 v28.4s, v20.4s, v22.4s // [C_c0, D_c0, C_c2, D_c2]
    trn2 v29.4s, v20.4s, v22.4s // [C_c1, D_c1, C_c3, D_c3]

    trn1 v16.2d, v0.2d, v28.2d // [A_c0, B_c0, C_c0, D_c0] -> col 0
    trn2 v18.2d, v0.2d, v28.2d // [A_c2, B_c2, C_c2, D_c2] -> col 2
    trn1 v30.2d, v2.2d, v29.2d // [A_c1, B_c1, C_c1, D_c1] -> col 1
    trn2 v31.2d, v2.2d, v29.2d // [A_c3, B_c3, C_c3, D_c3] -> col 3

    mov v0.16b, v16.16b // col 0
    mov v1.16b, v30.16b // col 1
    mov v2.16b, v18.16b // col 2
    mov v3.16b, v31.16b // col 3

    // Transpose R halves (cols 4-7): v17, v19, v21, v23
    trn1 v28.4s, v17.4s, v19.4s // [A_c4, B_c4, A_c6, B_c6]
    trn2 v29.4s, v17.4s, v19.4s // [A_c5, B_c5, A_c7, B_c7]
    trn1 v30.4s, v21.4s, v23.4s // [C_c4, D_c4, C_c6, D_c6]
    trn2 v31.4s, v21.4s, v23.4s // [C_c5, D_c5, C_c7, D_c7]

    trn1 v4.2d, v28.2d, v30.2d // [A_c4, B_c4, C_c4, D_c4] -> col 4
    trn2 v6.2d, v28.2d, v30.2d // [A_c6, B_c6, C_c6, D_c6] -> col 6
    trn1 v5.2d, v29.2d, v31.2d // [A_c5, B_c5, C_c5, D_c5] -> col 5
    trn2 v7.2d, v29.2d, v31.2d // [A_c7, B_c7, C_c7, D_c7] -> col 7
.endm

//=============================================================================
// Output conversion: interleaved columns back to sequential blocks
//=============================================================================
.macro convert_from_interleaved
    // Input: v0-v7 are columns
    // Output: v16-v23 as PT0-PT3 in [L,R] format

    // Reverse transpose for L halves (v0, v1, v2, v3 -> cols in each block)
    trn1 v28.2d, v0.2d, v2.2d // [A_c0, A_c2, C_c0, C_c2]
    trn2 v29.2d, v0.2d, v2.2d // [B_c0, B_c2, D_c0, D_c2]
    trn1 v30.2d, v1.2d, v3.2d // [A_c1, A_c3, C_c1, C_c3]
    trn2 v31.2d, v1.2d, v3.2d // [B_c1, B_c3, D_c1, D_c3]

    trn1 v16.4s, v28.4s, v30.4s // [A_c0, A_c1, A_c2, A_c3] -> PT0_L
    trn2 v20.4s, v28.4s, v30.4s // [C_c0, C_c1, C_c2, C_c3] -> PT2_L
    trn1 v18.4s, v29.4s, v31.4s // [B_c0, B_c1, B_c2, B_c3] -> PT1_L
    trn2 v22.4s, v29.4s, v31.4s // [D_c0, D_c1, D_c2, D_c3] -> PT3_L

    // Reverse transpose for R halves (v4, v5, v6, v7)
    trn1 v28.2d, v4.2d, v6.2d // [A_c4, A_c6, C_c4, C_c6]
    trn2 v29.2d, v4.2d, v6.2d // [B_c4, B_c6, D_c4, D_c6]
    trn1 v30.2d, v5.2d, v7.2d // [A_c5, A_c7, C_c5, C_c7]
    trn2 v31.2d, v5.2d, v7.2d // [B_c5, B_c7, D_c5, D_c7]

    trn1 v17.4s, v28.4s, v30.4s // [A_c4, A_c5, A_c6, A_c7] -> PT0_R
    trn2 v21.4s, v28.4s, v30.4s // [C_c4, C_c5, C_c6, C_c7] -> PT2_R
    trn1 v19.4s, v29.4s, v31.4s // [B_c4, B_c5, B_c6, B_c7] -> PT1_R
    trn2 v23.4s, v29.4s, v31.4s // [D_c4, D_c5, D_c6, D_c7] -> PT3_R
.endm

//=============================================================================
// Main encryption function - Interleaved 4PT
//
// void rijndael256_encrypt_neon_il_4pt(const Rijndael256Key *ctx,
//                                       const uint8_t *pt,
//                                       uint8_t *ct);
//=============================================================================
.globl rijndael256_encrypt_neon_il_4pt
.type rijndael256_encrypt_neon_il_4pt, %function
.align 4
rijndael256_encrypt_neon_il_4pt:
    // Save callee-saved registers
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    sub sp, sp, #128
    st1 {v8.16b-v11.16b}, [sp], #64
    st1 {v12.16b-v15.16b}, [sp], #64
    sub sp, sp, #128

    // Save arguments
    mov x5, x0                        // ctx (round key pointer)
    mov x9, x2                        // ct output

    // Setup S-box address
    adrp x3, rijndael256_sbox_il
    add x3, x3, :lo12:rijndael256_sbox_il

    // Load S-box first 64 bytes (cached)
    ld1 {v8.16b-v11.16b}, [x3]

    // Setup constants
    movi v12.16b, #0x40
    movi v15.16b, #0x1b

    // Load MixColumns rotation masks
    adrp x4, mixcol_rot1_il
    add x4, x4, :lo12:mixcol_rot1_il
    ld1 {v13.16b}, [x4]

    adrp x4, mixcol_rot2_il
    add x4, x4, :lo12:mixcol_rot2_il
    ld1 {v14.16b}, [x4]

    // Store ShiftRows row masks address in x7
    adrp x7, sr_row_masks
    add x7, x7, :lo12:sr_row_masks

    // Load 4 plaintext blocks into v16-v23
    ld1 {v16.16b, v17.16b}, [x1], #32 // PT0
    ld1 {v18.16b, v19.16b}, [x1], #32 // PT1
    ld1 {v20.16b, v21.16b}, [x1], #32 // PT2
    ld1 {v22.16b, v23.16b}, [x1] // PT3

    // Convert to interleaved layout
    convert_to_interleaved

    // Initial AddRoundKey
    addroundkey_il x5

    // Main rounds 1-13
    mov x6, #13

.Lround_loop_il:
    subbytes_il x3
    shiftrows_il
    mixcolumns_il
    addroundkey_il x5

    subs x6, x6, #1
    b.ne .Lround_loop_il

    // Final round (no MixColumns)
    subbytes_il x3
    shiftrows_il
    addroundkey_il x5

    // Convert back to sequential layout
    convert_from_interleaved

    // Store ciphertext
    st1 {v16.16b, v17.16b}, [x9], #32 // CT0
    st1 {v18.16b, v19.16b}, [x9], #32 // CT1
    st1 {v20.16b, v21.16b}, [x9], #32 // CT2
    st1 {v22.16b, v23.16b}, [x9] // CT3

    // Restore callee-saved registers
    ld1 {v8.16b-v11.16b}, [sp], #64
    ld1 {v12.16b-v15.16b}, [sp], #64
    mov sp, x29
    ldp x29, x30, [sp], #16

    ret
.size rijndael256_encrypt_neon_il_4pt, .-rijndael256_encrypt_neon_il_4pt
