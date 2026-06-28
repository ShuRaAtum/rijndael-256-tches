/*
 * Rijndael-256 Encryption using ARM Cryptographic Extension (Linux/ELF).
 *
 * ELF port of platform/apple/rijndael256_arm.S for ARMv8-A cores that DO
 * provide the Crypto Extension (e.g. Raspberry Pi 5 / Cortex-A76, A55, A78...).
 * Differences from the Apple/Mach-O source are syntactic only:
 *   - symbols carry no leading underscore
 *   - adrp/add use ':lo12:' instead of @PAGE/@PAGEOFF
 * The instruction sequence (pre-shuffle TBL + AESE + AESMC + EOR) is identical.
 *
 * Build with -march=armv8-a+crypto (or armv8.2-a+crypto on A76).
 */

.text
.align 4

mask_for_L:
    .byte 0, 17, 22, 23, 4, 5, 26, 27, 8, 9, 14, 31, 12, 13, 18, 19
mask_for_R:
    .byte 16, 1, 6, 7, 20, 21, 10, 11, 24, 25, 30, 15, 28, 29, 2, 3
inv_mask_for_L:
    .byte 0, 1, 30, 31, 4, 5, 2, 19, 8, 9, 22, 23, 12, 29, 26, 27
inv_mask_for_R:
    .byte 16, 17, 14, 15, 20, 21, 18, 3, 24, 25, 6, 7, 28, 13, 10, 11

.align 4

.global rijndael256_encrypt_arm
.global rijndael256_decrypt_arm
.global rijndael256_has_arm_crypto

rijndael256_has_arm_crypto:
    mov w0, #1
    ret

/*
 * void rijndael256_encrypt_arm(const Rijndael256Key *ctx (x0),
 *                              const uint8_t *pt (x1),
 *                              uint8_t *ct (x2))
 */
rijndael256_encrypt_arm:
    stp x29, x30, [sp, #-16]!
    mov x29, sp

    ldr w4, [x0, #480]              // ctx->rounds (14)
    ld1 {v0.16b, v1.16b}, [x1]      // L, R

    adrp x9, mask_for_L
    add  x9, x9, :lo12:mask_for_L
    ld1 {v16.16b}, [x9]
    adrp x9, mask_for_R
    add  x9, x9, :lo12:mask_for_R
    ld1 {v17.16b}, [x9]

    movi v31.16b, #0
    mov x3, x0

    ld1 {v20.16b, v21.16b}, [x3], #32
    eor v0.16b, v0.16b, v20.16b
    eor v1.16b, v1.16b, v21.16b

    sub w4, w4, #1

Lenc_round_loop:
    tbl v2.16b, {v0.16b, v1.16b}, v16.16b
    tbl v3.16b, {v0.16b, v1.16b}, v17.16b

    ld1 {v20.16b, v21.16b}, [x3], #32

    aese v2.16b, v31.16b
    aese v3.16b, v31.16b

    aesmc v0.16b, v2.16b
    aesmc v1.16b, v3.16b

    eor v0.16b, v0.16b, v20.16b
    eor v1.16b, v1.16b, v21.16b

    subs w4, w4, #1
    b.ne Lenc_round_loop

Lenc_final_round:
    tbl v2.16b, {v0.16b, v1.16b}, v16.16b
    tbl v3.16b, {v0.16b, v1.16b}, v17.16b

    ld1 {v20.16b, v21.16b}, [x3]

    aese v2.16b, v31.16b
    aese v3.16b, v31.16b

    eor v0.16b, v2.16b, v20.16b
    eor v1.16b, v3.16b, v21.16b

    st1 {v0.16b, v1.16b}, [x2]

    ldp x29, x30, [sp], #16
    ret

/*
 * void rijndael256_decrypt_arm(const Rijndael256Key *ctx (x0),
 *                              const uint8_t *ct (x1),
 *                              uint8_t *pt (x2))
 */
rijndael256_decrypt_arm:
    stp x29, x30, [sp, #-16]!
    mov x29, sp

    ldr w4, [x0, #480]
    ld1 {v0.16b, v1.16b}, [x1]

    adrp x9, inv_mask_for_L
    add  x9, x9, :lo12:inv_mask_for_L
    ld1 {v16.16b}, [x9]
    adrp x9, inv_mask_for_R
    add  x9, x9, :lo12:inv_mask_for_R
    ld1 {v17.16b}, [x9]

    movi v31.16b, #0

    mov w5, w4
    lsl w5, w5, #5
    add x3, x0, x5

    ld1 {v20.16b, v21.16b}, [x3]
    sub x3, x3, #32
    eor v0.16b, v0.16b, v20.16b
    eor v1.16b, v1.16b, v21.16b

    sub w4, w4, #1

Ldec_round_loop:
    tbl v2.16b, {v0.16b, v1.16b}, v16.16b
    tbl v3.16b, {v0.16b, v1.16b}, v17.16b

    ld1 {v20.16b, v21.16b}, [x3]
    sub x3, x3, #32

    aesd v2.16b, v31.16b
    aesd v3.16b, v31.16b

    eor v2.16b, v2.16b, v20.16b
    eor v3.16b, v3.16b, v21.16b

    aesimc v0.16b, v2.16b
    aesimc v1.16b, v3.16b

    subs w4, w4, #1
    b.ne Ldec_round_loop

Ldec_final_round:
    tbl v2.16b, {v0.16b, v1.16b}, v16.16b
    tbl v3.16b, {v0.16b, v1.16b}, v17.16b

    ld1 {v20.16b, v21.16b}, [x3]

    aesd v2.16b, v31.16b
    aesd v3.16b, v31.16b

    eor v0.16b, v2.16b, v20.16b
    eor v1.16b, v3.16b, v21.16b

    st1 {v0.16b, v1.16b}, [x2]

    ldp x29, x30, [sp], #16
    ret
