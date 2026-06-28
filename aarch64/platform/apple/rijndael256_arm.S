/*
 * Rijndael-256 Encryption using ARM Cryptographic Extension
 *
 * Block size: 256 bits (32 bytes)
 * ShiftRows: (0, 1, 3, 4) - different from AES (0, 1, 2, 3)
 *
 * Strategy: Use TBL instruction to pre-shuffle state before AESE
 * so that ARM's built-in AES ShiftRows(0,1,2,3) produces the same
 * result as Rijndael-256's ShiftRows(0,1,3,4).
 *
 * Key insight: ARM TBL can use a 2-register table (32 bytes),
 * allowing us to combine bytes from both L and R halves in one instruction.
 * This is more efficient than x86's pshufb which requires separate masks + OR.
 */

.text
.align 4

/*
 * TBL masks for pre-shuffling
 *
 * State layout: 256-bit = L (columns 0-3, v0) + R (columns 4-7, v1)
 * Each 128-bit register: [c0r0,c0r1,c0r2,c0r3, c1r0,c1r1,c1r2,c1r3, c2r0,c2r1,c2r2,c2r3, c3r0,c3r1,c3r2,c3r3]
 *
 * With TBL using {v0, v1} as 32-byte table:
 *   - Indices 0-15 select from v0 (L)
 *   - Indices 16-31 select from v1 (R)
 *
 * Converted from x86 masks:
 *   x86: mask_L_for_L + mask_R_for_L (with POR)
 *   ARM: Single mask where R's bytes use index+16
 */

/* Mask for L_output (bytes that form the new L half after ShiftRows) */
_mask_for_L:
    .byte 0, 17, 22, 23, 4, 5, 26, 27, 8, 9, 14, 31, 12, 13, 18, 19

/* Mask for R_output (bytes that form the new R half after ShiftRows) */
_mask_for_R:
    .byte 16, 1, 6, 7, 20, 21, 10, 11, 24, 25, 30, 15, 28, 29, 2, 3

/* Inverse masks for decryption */
/* InvShiftRows: row shifts right by (0, 1, 3, 4) = shift left by (0, 7, 5, 4) mod 8 */
_inv_mask_for_L:
    .byte 0, 1, 30, 31, 4, 5, 2, 19, 8, 9, 22, 23, 12, 29, 26, 27

_inv_mask_for_R:
    .byte 16, 17, 14, 15, 20, 21, 18, 3, 24, 25, 6, 7, 28, 13, 10, 11

.align 4

.global _rijndael256_encrypt_arm
.global _rijndael256_decrypt_arm
.global _rijndael256_has_arm_crypto

/*
 * int rijndael256_has_arm_crypto(void)
 *
 * Returns 1 if ARM Crypto Extension is available, 0 otherwise.
 * On Apple Silicon, this always returns 1.
 */
_rijndael256_has_arm_crypto:
    mov w0, #1
    ret

/*
 * void rijndael256_encrypt_arm(const Rijndael256Key *ctx,
 *                               const uint8_t *pt,
 *                               uint8_t *ct)
 *
 * Arguments (AAPCS64):
 *   x0 = ctx (pointer to Rijndael256Key)
 *   x1 = pt  (pointer to 32-byte plaintext)
 *   x2 = ct  (pointer to 32-byte ciphertext output)
 *
 * Rijndael256Key structure:
 *   offset 0: roundKeys[480] (15 rounds * 32 bytes)
 *   offset 480: rounds (int)
 *
 * Register allocation:
 *   v0, v1   = state_L, state_R
 *   v2, v3   = shuffled_L, shuffled_R (temporaries)
 *   v16      = mask_for_L
 *   v17      = mask_for_R
 *   v20, v21 = round keys (L, R)
 *   v31      = zero (for AESE without key XOR)
 *   x3       = round key pointer
 *   w4       = round counter
 */
_rijndael256_encrypt_arm:
    /* Preserve frame pointer */
    stp x29, x30, [sp, #-16]!
    mov x29, sp

    /* Load round count */
    ldr w4, [x0, #480]          // w4 = ctx->rounds (should be 14)

    /* Load plaintext into v0 (L) and v1 (R) */
    ld1 {v0.16b, v1.16b}, [x1]

    /* Load shuffle masks */
    adrp x9, _mask_for_L@PAGE
    add x9, x9, _mask_for_L@PAGEOFF
    ld1 {v16.16b}, [x9]
    adrp x9, _mask_for_R@PAGE
    add x9, x9, _mask_for_R@PAGEOFF
    ld1 {v17.16b}, [x9]

    /* Initialize zero register for AESE */
    movi v31.16b, #0

    /* Setup round key pointer */
    mov x3, x0                  // x3 = &ctx->roundKeys[0]

    /* Initial AddRoundKey (round 0) */
    ld1 {v20.16b, v21.16b}, [x3], #32
    eor v0.16b, v0.16b, v20.16b
    eor v1.16b, v1.16b, v21.16b

    /* Setup loop counter for main rounds (rounds - 1) */
    sub w4, w4, #1              // 13 iterations for 14 rounds

Lenc_round_loop:
    /* Pre-shuffle for Rijndael-256 ShiftRows (0,1,3,4) */
    /* TBL uses {v0, v1} as 32-byte table */
    tbl v2.16b, {v0.16b, v1.16b}, v16.16b   // L_shuffled
    tbl v3.16b, {v0.16b, v1.16b}, v17.16b   // R_shuffled

    /* Load round keys for this round */
    ld1 {v20.16b, v21.16b}, [x3], #32

    /*
     * AESE performs: SubBytes(ShiftRows(state XOR key))
     * With zero key: SubBytes(ShiftRows(state))
     * Then AESMC performs: MixColumns
     * Finally XOR round key (must be AFTER MixColumns!)
     */
    aese v2.16b, v31.16b        // SubBytes(ShiftRows(L_shuffled))
    aese v3.16b, v31.16b        // SubBytes(ShiftRows(R_shuffled))

    /* MixColumns FIRST */
    aesmc v0.16b, v2.16b        // state_L = MixColumns(result_L)
    aesmc v1.16b, v3.16b        // state_R = MixColumns(result_R)

    /* XOR round key AFTER MixColumns (matching x86 aesenc behavior) */
    eor v0.16b, v0.16b, v20.16b
    eor v1.16b, v1.16b, v21.16b

    /* Loop control */
    subs w4, w4, #1
    b.ne Lenc_round_loop

Lenc_final_round:
    /* Final round (no MixColumns) */

    /* Pre-shuffle */
    tbl v2.16b, {v0.16b, v1.16b}, v16.16b
    tbl v3.16b, {v0.16b, v1.16b}, v17.16b

    /* Load final round key */
    ld1 {v20.16b, v21.16b}, [x3]

    /* AESE (SubBytes + ShiftRows) */
    aese v2.16b, v31.16b
    aese v3.16b, v31.16b

    /* XOR final round key */
    eor v0.16b, v2.16b, v20.16b
    eor v1.16b, v3.16b, v21.16b

    /* Store ciphertext */
    st1 {v0.16b, v1.16b}, [x2]

    /* Restore and return */
    ldp x29, x30, [sp], #16
    ret

/*
 * void rijndael256_decrypt_arm(const Rijndael256Key *ctx,
 *                               const uint8_t *ct,
 *                               uint8_t *pt)
 *
 * Decryption using ARM Crypto Extension
 * Uses AESD (inverse SubBytes + inverse ShiftRows) and AESIMC (inverse MixColumns)
 *
 * Note: Decryption requires inverse shuffle masks for inverse ShiftRows
 * Inverse ShiftRows offsets: (0, 7, 5, 4) mod 8
 */
_rijndael256_decrypt_arm:
    /* Preserve frame pointer */
    stp x29, x30, [sp, #-16]!
    mov x29, sp

    /* Load round count */
    ldr w4, [x0, #480]          // w4 = ctx->rounds

    /* Load ciphertext into v0 (L) and v1 (R) */
    ld1 {v0.16b, v1.16b}, [x1]

    /* Load inverse shuffle masks */
    adrp x9, _inv_mask_for_L@PAGE
    add x9, x9, _inv_mask_for_L@PAGEOFF
    ld1 {v16.16b}, [x9]
    adrp x9, _inv_mask_for_R@PAGE
    add x9, x9, _inv_mask_for_R@PAGEOFF
    ld1 {v17.16b}, [x9]

    /* Initialize zero register */
    movi v31.16b, #0

    /* Calculate offset to last round key */
    mov w5, w4
    lsl w5, w5, #5              // w5 = rounds * 32
    add x3, x0, x5              // x3 = &ctx->roundKeys[rounds * 32]

    /* Initial AddRoundKey (with last round key) */
    ld1 {v20.16b, v21.16b}, [x3]
    sub x3, x3, #32             // Move to previous round key
    eor v0.16b, v0.16b, v20.16b
    eor v1.16b, v1.16b, v21.16b

    /* Setup loop counter for main rounds (rounds - 1) */
    sub w4, w4, #1

Ldec_round_loop:
    /* Pre-shuffle for inverse Rijndael-256 ShiftRows */
    tbl v2.16b, {v0.16b, v1.16b}, v16.16b   // L_shuffled
    tbl v3.16b, {v0.16b, v1.16b}, v17.16b   // R_shuffled

    /* Load round key */
    ld1 {v20.16b, v21.16b}, [x3]
    sub x3, x3, #32

    /* AESD: InvSubBytes(InvShiftRows(state XOR key)) */
    /* Use zero key, then XOR after */
    aesd v2.16b, v31.16b
    aesd v3.16b, v31.16b

    /* XOR round key */
    eor v2.16b, v2.16b, v20.16b
    eor v3.16b, v3.16b, v21.16b

    /* InvMixColumns */
    aesimc v0.16b, v2.16b
    aesimc v1.16b, v3.16b

    /* Loop control */
    subs w4, w4, #1
    b.ne Ldec_round_loop

Ldec_final_round:
    /* Final round (no InvMixColumns) */

    /* Pre-shuffle */
    tbl v2.16b, {v0.16b, v1.16b}, v16.16b
    tbl v3.16b, {v0.16b, v1.16b}, v17.16b

    /* Load first round key (round 0) */
    ld1 {v20.16b, v21.16b}, [x3]

    /* AESD (InvSubBytes + InvShiftRows) */
    aesd v2.16b, v31.16b
    aesd v3.16b, v31.16b

    /* XOR final round key */
    eor v0.16b, v2.16b, v20.16b
    eor v1.16b, v3.16b, v21.16b

    /* Store plaintext */
    st1 {v0.16b, v1.16b}, [x2]

    /* Restore and return */
    ldp x29, x30, [sp], #16
    ret
