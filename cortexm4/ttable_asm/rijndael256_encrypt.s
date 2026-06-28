/*
 * Rijndael-256 T-table ASM Encrypt for Cortex-M4
 *
 * Single Te0 table with ROR trick: Te1[x]=ROR(Te0[x],8), etc.
 * NOT constant-time — for performance comparison only.
 *
 * void rijndael256_encrypt(const uint32_t *roundKey, const uint8_t *pt, uint8_t *ct)
 *
 * Register allocation (main rounds):
 *   r0-r7:   state s[0..7] (big-endian words)
 *   r8:      Te0 table base
 *   r9:      round key pointer (advances by 32 each round)
 *   r10-r12: temporaries
 *   r14:     temporary (LR saved on stack)
 *
 * Stack layout (40 bytes):
 *   sp+0  .. sp+31:  temp buffer for round output (8 words)
 *   sp+32:           saved ct pointer
 *   sp+36:           round end pointer
 *
 * ShiftRows pattern for 256-bit block: (0, 1, 3, 4)
 *   t[c] = Te0[s[c]>>24] ^ ROR(Te0[(s[(c+1)%8]>>16)&FF], 8)
 *        ^ ROR(Te0[(s[(c+3)%8]>>8)&FF], 16) ^ ROR(Te0[s[(c+4)%8]&FF], 24)
 *        ^ rk[c]
 */

    .syntax unified
    .thumb
    .text

/* ============================================================
 * Macro: tt_col — compute one T-table column output
 *   \sp_off: stack offset to store result (0,4,8,...,28)
 *   \rc:     register for s[c]      (row 0, no shift)
 *   \rc1:    register for s[(c+1)%8] (row 1, shift 1)
 *   \rc3:    register for s[(c+3)%8] (row 2, shift 3)
 *   \rc4:    register for s[(c+4)%8] (row 3, shift 4)
 *   \rk_off: round key offset (0,4,8,...,28)
 * Uses: r10 (accumulator), r11 (temp)
 * ============================================================ */
.macro tt_col sp_off, rc, rc1, rc3, rc4, rk_off
    lsr     r10, \rc, #24               /* row 0 byte */
    ldr     r10, [r8, r10, lsl #2]      /* Te0[byte] */
    ubfx    r11, \rc1, #16, #8          /* row 1 byte */
    ldr     r11, [r8, r11, lsl #2]
    eor     r10, r10, r11, ror #8       /* ^ Te1[byte] */
    ubfx    r11, \rc3, #8, #8           /* row 2 byte */
    ldr     r11, [r8, r11, lsl #2]
    eor     r10, r10, r11, ror #16      /* ^ Te2[byte] */
    uxtb    r11, \rc4                   /* row 3 byte */
    ldr     r11, [r8, r11, lsl #2]
    eor     r10, r10, r11, ror #24      /* ^ Te3[byte] */
    ldr     r11, [r9, #\rk_off]        /* round key */
    eor     r10, r10, r11
    str     r10, [sp, #\sp_off]         /* store output */
.endm

/* ============================================================
 * Macro: last_col — final round column (SubBytes+ShiftRows+ARK, no MC)
 *   \ct_off: offset into ct output buffer
 *   \rc, \rc1, \rc3, \rc4: source state registers
 *   \rk_off: round key offset
 * Uses: r10, r11, r12;  r8 = SBox base, lr = ct pointer
 * ============================================================ */
.macro last_col ct_off, rc, rc1, rc3, rc4, rk_off
    lsr     r10, \rc, #24               /* row 0 byte */
    ldrb    r10, [r8, r10]              /* SBox[byte] */
    ubfx    r11, \rc1, #16, #8          /* row 1 byte */
    ldrb    r11, [r8, r11]
    orr     r10, r11, r10, lsl #8       /* [row0, row1] */
    ubfx    r11, \rc3, #8, #8           /* row 2 byte */
    ldrb    r11, [r8, r11]
    uxtb    r12, \rc4                   /* row 3 byte */
    ldrb    r12, [r8, r12]
    orr     r11, r12, r11, lsl #8       /* [row2, row3] */
    orr     r10, r11, r10, lsl #16      /* [row0,row1,row2,row3] BE */
    ldr     r11, [r9, #\rk_off]        /* round key (BE) */
    eor     r10, r10, r11
    rev     r10, r10                    /* to little-endian */
    str     r10, [lr, #\ct_off]         /* store to ct */
.endm

/* ============================================================
 * rijndael256_encrypt
 * ============================================================ */
    .global rijndael256_encrypt
    .type   rijndael256_encrypt, %function
    .align  2

rijndael256_encrypt:
    push    {r4-r11, lr}                /* save 36 bytes */
    sub     sp, sp, #40                 /* temp(32) + ct(4) + end(4) */

    /* Save ct pointer and round key base */
    str     r2, [sp, #32]              /* save ct */
    mov     r9, r0                      /* r9 = round key pointer */

    /* Load Te0 base */
    ldr     r8, =r256_Te0

    /* ---- Load plaintext as big-endian words ---- */
    ldr     r0, [r1, #0]
    ldr     r2, [r1, #8]
    ldr     r3, [r1, #12]
    ldr     r4, [r1, #16]
    ldr     r5, [r1, #20]
    ldr     r6, [r1, #24]
    ldr     r7, [r1, #28]
    ldr     r1, [r1, #4]               /* load last (overwrites pt ptr) */

    rev     r0, r0
    rev     r1, r1
    rev     r2, r2
    rev     r3, r3
    rev     r4, r4
    rev     r5, r5
    rev     r6, r6
    rev     r7, r7

    /* ---- Initial AddRoundKey (K0) ---- */
    ldr     r10, [r9, #0]
    eor     r0, r0, r10
    ldr     r10, [r9, #4]
    eor     r1, r1, r10
    ldr     r10, [r9, #8]
    eor     r2, r2, r10
    ldr     r10, [r9, #12]
    eor     r3, r3, r10
    ldr     r10, [r9, #16]
    eor     r4, r4, r10
    ldr     r10, [r9, #20]
    eor     r5, r5, r10
    ldr     r10, [r9, #24]
    eor     r6, r6, r10
    ldr     r10, [r9, #28]
    eor     r7, r7, r10

    /* Advance to K1 */
    add     r9, r9, #32

    /* Compute round end pointer: K1 + 13*32 = K14 */
    add     r10, r9, #416              /* 13 * 32 = 416 */
    str     r10, [sp, #36]

    /* ============================================================
     * Main loop: 13 T-table rounds (K1 .. K13)
     * ============================================================ */
.Lround_loop:
    /*
     * ShiftRows (0,1,3,4):
     *   t[0] uses s[0], s[1], s[3], s[4]
     *   t[1] uses s[1], s[2], s[4], s[5]
     *   t[2] uses s[2], s[3], s[5], s[6]
     *   t[3] uses s[3], s[4], s[6], s[7]
     *   t[4] uses s[4], s[5], s[7], s[0]
     *   t[5] uses s[5], s[6], s[0], s[1]
     *   t[6] uses s[6], s[7], s[1], s[2]
     *   t[7] uses s[7], s[0], s[2], s[3]
     */
    tt_col  0,  r0, r1, r3, r4,  0
    tt_col  4,  r1, r2, r4, r5,  4
    tt_col  8,  r2, r3, r5, r6,  8
    tt_col  12, r3, r4, r6, r7, 12
    tt_col  16, r4, r5, r7, r0, 16
    tt_col  20, r5, r6, r0, r1, 20
    tt_col  24, r6, r7, r1, r2, 24
    tt_col  28, r7, r0, r2, r3, 28

    /* Reload state from temp buffer */
    ldm     sp, {r0-r7}

    /* Advance round key */
    add     r9, r9, #32

    /* Loop check */
    ldr     r10, [sp, #36]
    cmp     r9, r10
    bne     .Lround_loop

    /* ============================================================
     * Final round (K14): SubBytes + ShiftRows + ARK, no MixColumns
     * ============================================================ */

    /* Switch r8 from Te0 to SBox */
    ldr     r8, =r256_sbox

    /* Load ct pointer into lr */
    ldr     lr, [sp, #32]

    last_col  0, r0, r1, r3, r4,  0
    last_col  4, r1, r2, r4, r5,  4
    last_col  8, r2, r3, r5, r6,  8
    last_col 12, r3, r4, r6, r7, 12
    last_col 16, r4, r5, r7, r0, 16
    last_col 20, r5, r6, r0, r1, 20
    last_col 24, r6, r7, r1, r2, 24
    last_col 28, r7, r0, r2, r3, 28

    /* ---- Epilogue ---- */
    add     sp, sp, #40
    pop     {r4-r11, pc}

    .size   rijndael256_encrypt, . - rijndael256_encrypt
