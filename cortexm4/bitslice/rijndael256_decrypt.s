/******************************************************************************
* Rijndael-256 Bitsliced Decrypt — ARM Cortex-M4 (Equivalent Inverse Cipher)
*
* Single 256-bit block, Nr=14 for all key sizes.
* AES-order SWAPMOVE: state[0]=MSB (bit 7).
*
* Structure:
*   [ARK + InvSBox] → InvSR + InvMC  (×13 rounds)
*   [ARK + InvSBox] → InvSR          (×1 round)
*   ARK                               (final)
*
* Inverse S-box: InvAffine ∘ ForwardSBox ∘ InvAffine (all constant-free).
*   Mathematical proof: A*d = c (0x63), so all constants cancel when
*   key schedule absorbs by flipping planes 1,2,6,7 of keys 0..Nr-1.
*   Gate count: 20 + 109 + 20 = 149 (0 NOTs).
*
* InvMixColumns: M-transform ({04}x²+{05}) then forward Käsper-Schwabe MC.
* InvShiftRows: (0, 7, 5, 4) = byte_ror(1, 3) + byte_rol(4).
*
* Requires decrypt key schedule:
*   - Key order reversed (dk[r] = ek[Nr-r])
*   - Middle keys transformed with InvMixColumns (byte domain)
*   - Planes 1,2,6,7 flipped for keys 0..Nr-1
*
* Stack layout (56 bytes local):
*   sp+0..43:  S-box intermediate values (12 slots)
*   sp+44:     S-box scratch
*   sp+48:     round key pointer (auto-advanced)
*   sp+52:     LR save slot
*   sp+56..108: saved r0-r12, r14 from push
*     sp+56 = r0 (ks pointer)
*     sp+60 = r1 (ct pointer)
*     sp+64 = r2 (pt pointer)
*
* void rijndael256_decrypt(const R256Key *ks,
*                          const uint8_t ct[32],
*                          uint8_t pt[32]);
******************************************************************************/

.syntax unified
.thumb

/******************************************************************************
* Macros
******************************************************************************/
.macro swpmv out0, out1, in0, in1, m, n, tmp
    eor     \tmp, \in1, \in0, lsr \n
    and     \tmp, \m
    eor     \out1, \in1, \tmp
    eor     \out0, \in0, \tmp, lsl \n
.endm

.macro byte_rol reg, pos, rot, tmp
    ubfx    \tmp, \reg, #(\pos * 8), #8
    orr     \tmp, \tmp, \tmp, lsl #8
    ubfx    \tmp, \tmp, #(8 - \rot), #8
    bfi     \reg, \tmp, #(\pos * 8), #8
.endm

.macro byte_ror reg, pos, rot, tmp
    ubfx    \tmp, \reg, #(\pos * 8), #8
    orr     \tmp, \tmp, \tmp, lsl #8
    ubfx    \tmp, \tmp, #\rot, #8
    bfi     \reg, \tmp, #(\pos * 8), #8
.endm

// InvShiftRows for one register: ROR(1), ROR(3), ROL(4)
.macro inv_sr_754 reg, tmp
    byte_ror \reg, 2, 1, \tmp
    byte_ror \reg, 1, 3, \tmp
    byte_rol \reg, 0, 4, \tmp
.endm

// InvAffine (A^{-1} matrix, NO constant — absorbed into key schedule)
// Input/Output: r4-r11, Clobbers: r0-r3, r12
.macro inv_affine_noconst
    mov     r0, r4
    mov     r1, r5
    mov     r2, r6
    mov     r3, r7
    // r4 = s6^s3^s1
    eor     r4, r10, r3
    eor     r4, r4, r1
    // r5 = s7^s4^s2
    eor     r5, r11, r8
    eor     r5, r5, r2
    // r7 = s1^s6^s4
    eor     r7, r1, r10
    eor     r7, r7, r8
    // save old s6 before overwriting r10
    mov     r12, r10
    // r10 = s4^s1^s7
    eor     r10, r8, r1
    eor     r10, r10, r11
    // r6 = s0^s5^s3
    eor     r6, r0, r9
    eor     r6, r6, r3
    // r8 = s2^s7^s5
    eor     r8, r2, r11
    eor     r8, r8, r9
    // r11 = s5^s2^s0
    eor     r11, r9, r2
    eor     r11, r11, r0
    // r9 = s3^s0^s6 (r12 = old s6)
    eor     r9, r3, r0
    eor     r9, r9, r12
.endm

// Remap S-box shuffled output to canonical r4-r11
.macro sbox_to_canonical
    mov     r4, r1
    mov     r5, r3
    mov     r9, r0
    mov     r10, r2
.endm

/******************************************************************************
* Packing: Bitplane transpose of r4-r11 in-place
******************************************************************************/
.align 2
dec_packing_256:
    movw    r3, #0x0f0f
    movt    r3, #0x0f0f
    eor     r2, r3, r3, lsl #2
    eor     r1, r2, r2, lsl #1

    swpmv   r5, r4, r5, r4, r1, #1, r12
    swpmv   r7, r6, r7, r6, r1, #1, r12
    swpmv   r9, r8, r9, r8, r1, #1, r12
    swpmv   r11, r10, r11, r10, r1, #1, r12

    swpmv   r6, r4, r6, r4, r2, #2, r12
    swpmv   r7, r5, r7, r5, r2, #2, r12
    swpmv   r10, r8, r10, r8, r2, #2, r12
    swpmv   r11, r9, r11, r9, r2, #2, r12

    swpmv   r8, r4, r8, r4, r3, #4, r12
    swpmv   r9, r5, r9, r5, r3, #4, r12
    swpmv   r10, r6, r10, r6, r3, #4, r12
    swpmv   r11, r7, r11, r7, r3, #4, r12

    bx      lr

/******************************************************************************
* Unpacking: Inverse bitplane transpose of r4-r11
******************************************************************************/
.align 2
dec_unpacking_256:
    movw    r3, #0x0f0f
    movt    r3, #0x0f0f
    eor     r2, r3, r3, lsl #2
    eor     r1, r2, r2, lsl #1

    swpmv   r8, r4, r8, r4, r3, #4, r12
    swpmv   r9, r5, r9, r5, r3, #4, r12
    swpmv   r10, r6, r10, r6, r3, #4, r12
    swpmv   r11, r7, r11, r7, r3, #4, r12

    swpmv   r6, r4, r6, r4, r2, #2, r12
    swpmv   r7, r5, r7, r5, r2, #2, r12
    swpmv   r10, r8, r10, r8, r2, #2, r12
    swpmv   r11, r9, r11, r9, r2, #2, r12

    swpmv   r5, r4, r5, r4, r1, #1, r12
    swpmv   r7, r6, r7, r6, r1, #1, r12
    swpmv   r9, r8, r9, r8, r1, #1, r12
    swpmv   r11, r10, r11, r10, r1, #1, r12

    bx      lr

/******************************************************************************
* ARK + InvAffine + Forward S-box core (Boyar-Peralta, NO NOTs)
*
* Input:  r4-r11 = state[0..7] (canonical order)
*         sp+48  = round key pointer (advanced by 32 bytes after)
*
* Output: SHUFFLED register assignment:
*   r1=S0, r3=S1, r6=S2, r7=S3, r8=S4, r0=S5, r2=S6, r11=S7
******************************************************************************/
.align 2
ark_inv_sbox_256:
    // --- AddRoundKey ---
    ldr.w   r1, [sp, #48]
    ldmia   r1!, {r0,r2,r3,r12}
    eor     r4, r0
    eor     r5, r2
    eor     r6, r3
    eor     r7, r12
    ldmia   r1!, {r0,r2,r3,r12}
    eor     r8, r0
    eor     r9, r2
    eor     r10, r3
    eor     r11, r12
    str.w   r1, [sp, #48]
    str     r14, [sp, #52]

    // --- InvAffine (first, constant-free) ---
    inv_affine_noconst

    // --- Forward S-box core (identical to encrypt, NO XNORs) ---
    // Input: r4=U0..r11=U7, Output: shuffled
    eor     r1, r7, r9
    eor     r3, r4, r10
    eor     r2, r3, r1
    eor     r0, r8, r2
    eor     r14, r0, r9
    and     r12, r2, r14
    eor     r8, r14, r11
    eor     r0, r0, r5
    str.w   r2, [sp, #44]
    eor     r2, r4, r7
    str     r0, [sp, #40]
    eor     r0, r0, r2
    str     r2, [sp, #36]
    and     r2, r2, r0
    str     r8, [sp, #32]
    eor     r8, r11, r0
    eor     r9, r4, r9
    eor     r6, r5, r6
    eor     r5, r14, r6
    str     r14, [sp, #28]
    eor     r14, r5, r0
    str.w   r1, [sp, #24]
    and     r1, r1, r14
    eor     r1, r1, r2
    str     r14, [sp, #20]
    eor     r14, r5, r9
    str.w   r5, [sp, #16]
    and     r5, r9, r5
    eor     r2, r5, r2
    eor     r5, r6, r0
    str.w   r0, [sp, #12]
    eor     r0, r3, r5
    str     r3, [sp, #8]
    and     r3, r3, r5
    str     r5, [sp, #4]
    str     r11, [sp, #0]
    eor     r5, r4, r5
    eor     r6, r6, r11
    eor     r7, r6, r7
    and     r11, r7, r11
    eor     r11, r11, r12
    eor     r11, r11, r2
    eor     r14, r11, r14
    eor     r4, r6, r4
    and     r11, r4, r8
    eor     r11, r11, r3
    eor     r2, r11, r2
    eor     r2, r2, r5
    eor     r10, r6, r10
    and     r11, r10, r6
    eor     r3, r11, r3
    eor     r3, r3, r1
    eor     r3, r3, r0
    eor     r0, r10, r9
    ldr     r11, [sp, #32]
    and     r5, r0, r11
    eor     r12, r5, r12
    ldr     r5, [sp, #40]
    str     r7, [sp, #32]
    eor     r12, r12, r5
    eor     r1, r12, r1
    and     r12, r1, r3
    eor     r5, r2, r12
    eor     r12, r14, r12
    eor     r1, r1, r14
    and     r7, r1, r5
    eor     r14, r7, r14
    and     r4, r14, r4
    and     r8, r14, r8
    eor     r7, r3, r2
    and     r12, r12, r7
    eor     r12, r12, r2
    eor     r7, r5, r12
    and     r2, r2, r7
    eor     r5, r5, r2
    and     r5, r14, r5
    eor     r1, r1, r5
    eor     r5, r14, r1
    ldr.w   r7, [sp, #4]
    and     r7, r5, r7
    eor     r8, r7, r8
    str     r8, [sp, #40]
    ldr     r8, [sp, #8]
    and     r8, r5, r8
    and     r10, r1, r10
    and     r6, r1, r6
    eor     r6, r7, r6
    eor     r3, r3, r12
    eor     r3, r2, r3
    eor     r1, r1, r3
    ldr.w   r5, [sp, #16]
    and     r2, r1, r5
    and     r9, r1, r9
    str     r9, [sp, #16]
    eor     r5, r12, r3
    ldr     r9, [sp, #28]
    ldr.w   r7, [sp, #44]
    and     r9, r5, r9
    and     r7, r5, r7
    and     r0, r3, r0
    and     r3, r3, r11
    eor     r3, r3, r9
    eor     r3, r6, r3
    ldr     r11, [sp, #32]
    ldr.w   r5, [sp, #20]
    and     r11, r12, r11
    eor     r14, r14, r12
    eor     r1, r14, r1
    and     r5, r1, r5
    eor     r6, r5, r6
    ldr     r5, [sp, #24]
    str     r4, [sp, #32]
    and     r1, r1, r5
    ldr     r5, [sp, #12]
    ldr     r4, [sp, #36]
    and     r5, r14, r5
    eor     r5, r5, r6
    and     r4, r14, r4
    eor     r14, r4, r5
    eor     r4, r4, r1
    eor     r1, r0, r4
    eor     r0, r1, r11
    eor     r7, r7, r1
    eor     r1, r7, r5
    eor     r7, r7, r3
    eor     r3, r7, r5
    eor     r11, r10, r4
    ldr.w   r4, [sp, #0]
    and     r12, r12, r4
    eor     r9, r9, r12
    eor     r12, r8, r9
    eor     r2, r2, r12
    eor     r2, r6, r2
    ldr.w   r4, [sp, #32]
    eor     r12, r4, r2
    eor     r0, r0, r12
    eor     r6, r12, r14
    ldr.w   r4, [sp, #16]
    ldr     r12, [sp, #40]
    eor     r6, r6, r4
    eor     r12, r9, r12
    eor     r14, r11, r12
    eor     r2, r2, r14
    eor     r11, r8, r14
    ldr     r14, [sp, #52]
    eor     r8, r12, r7
    bx      lr

/******************************************************************************
* inv_sr_imc: sbox_to_canonical + InvAffine2 + InvSR + InvMC
*
* Input:  Shuffled S-box output (r0-r3,r6-r8,r11)
* Output: r4-r11 = state[0..7], canonical
******************************************************************************/
.align 2
inv_sr_imc:
    // Phase 0: Remap to canonical order
    sbox_to_canonical

    // Phase 1: InvAffine (second, constant-free)
    inv_affine_noconst

    // Phase 2: InvShiftRows — byte_ror(1), byte_ror(3), byte_rol(4)
    inv_sr_754  r4, r0
    inv_sr_754  r5, r0
    inv_sr_754  r6, r0
    inv_sr_754  r7, r0
    inv_sr_754  r8, r0
    inv_sr_754  r9, r0
    inv_sr_754  r10, r0
    inv_sr_754  r11, r0

    // Phase 3: InvMixColumns = M-transform + Forward MC

    // M-transform: M(s) = {04}*(s ^ ror16(s)) ^ s
    // v[0] and v[1] kept for multiple uses
    eor     r0, r4, r4, ror #16        // r0 = v[0]
    eor     r1, r5, r5, ror #16        // r1 = v[1]

    // s'[0] = v[2] ^ s[0]
    eor     r2, r6, r6, ror #16
    eor     r4, r4, r2

    // s'[1] = v[3] ^ s[1]
    eor     r2, r7, r7, ror #16
    eor     r5, r5, r2

    // s'[2] = v[4] ^ v[0] ^ s[2]
    eor     r2, r8, r8, ror #16
    eor     r6, r6, r2
    eor     r6, r6, r0

    // s'[3] = v[5] ^ v[0] ^ v[1] ^ s[3]
    eor     r2, r9, r9, ror #16
    eor     r7, r7, r2
    eor     r7, r7, r0
    eor     r7, r7, r1

    // s'[4] = v[6] ^ v[1] ^ s[4]
    eor     r2, r10, r10, ror #16
    eor     r8, r8, r2
    eor     r8, r8, r1

    // s'[5] = v[7] ^ v[0] ^ s[5]
    eor     r2, r11, r11, ror #16
    eor     r9, r9, r2
    eor     r9, r9, r0

    // s'[6] = v[0] ^ v[1] ^ s[6]
    eor     r10, r10, r0
    eor     r10, r10, r1

    // s'[7] = v[1] ^ s[7]
    eor     r11, r11, r1

    // Forward Käsper-Schwabe MixColumns (35 instructions)
    eor     r0, r4, r4, ror #24        // d_0 (kept for feedback)

    eor     r3, r5, r5, ror #24        // d_1
    eor     r4, r4, r0                 // s_0 ror 24
    eor     r4, r4, r0, ror #16        // ^ d_0 ror 16
    eor     r4, r4, r3                 // ^ d_1

    eor     r2, r6, r6, ror #24        // d_2
    eor     r5, r5, r3
    eor     r5, r5, r3, ror #16
    eor     r5, r5, r2

    eor     r3, r7, r7, ror #24        // d_3
    eor     r6, r6, r2
    eor     r6, r6, r2, ror #16
    eor     r6, r6, r3

    eor     r2, r8, r8, ror #24        // d_4
    eor     r7, r7, r3
    eor     r7, r7, r3, ror #16
    eor     r7, r7, r2
    eor     r7, r7, r0                 // feedback

    eor     r3, r9, r9, ror #24        // d_5
    eor     r8, r8, r2
    eor     r8, r8, r2, ror #16
    eor     r8, r8, r3
    eor     r8, r8, r0                 // feedback

    eor     r2, r10, r10, ror #24      // d_6
    eor     r9, r9, r3
    eor     r9, r9, r3, ror #16
    eor     r9, r9, r2

    eor     r3, r11, r11, ror #24      // d_7
    eor     r10, r10, r2
    eor     r10, r10, r2, ror #16
    eor     r10, r10, r3
    eor     r10, r10, r0               // feedback

    eor     r11, r11, r3
    eor     r11, r11, r3, ror #16
    eor     r11, r11, r0

    bx      lr

/******************************************************************************
* inv_sr_only: sbox_to_canonical + InvAffine2 + InvSR (final round, no MC)
*
* Input:  Shuffled S-box output (r0-r3,r6-r8,r11)
* Output: r4-r11 = state[0..7], canonical with InvSR applied
******************************************************************************/
.align 2
inv_sr_only:
    sbox_to_canonical
    inv_affine_noconst

    inv_sr_754  r4, r0
    inv_sr_754  r5, r0
    inv_sr_754  r6, r0
    inv_sr_754  r7, r0
    inv_sr_754  r8, r0
    inv_sr_754  r9, r0
    inv_sr_754  r10, r0
    inv_sr_754  r11, r0

    bx      lr

/******************************************************************************
* Main decrypt entry point
******************************************************************************/
.global rijndael256_decrypt
.type   rijndael256_decrypt,%function
.align 2
rijndael256_decrypt:
    push    {r0-r12, r14}
    sub.w   sp, #56

    str.w   r0, [sp, #48]

    // Load ciphertext (big-endian)
    ldm     r1, {r4-r11}
    rev     r4, r4
    rev     r5, r5
    rev     r6, r6
    rev     r7, r7
    rev     r8, r8
    rev     r9, r9
    rev     r10, r10
    rev     r11, r11

    bl      dec_packing_256

    // Rounds 1-13: ARK + InvSBox → InvSR + InvMC
    bl      ark_inv_sbox_256
    bl      inv_sr_imc

    bl      ark_inv_sbox_256
    bl      inv_sr_imc

    bl      ark_inv_sbox_256
    bl      inv_sr_imc

    bl      ark_inv_sbox_256
    bl      inv_sr_imc

    bl      ark_inv_sbox_256
    bl      inv_sr_imc

    bl      ark_inv_sbox_256
    bl      inv_sr_imc

    bl      ark_inv_sbox_256
    bl      inv_sr_imc

    bl      ark_inv_sbox_256
    bl      inv_sr_imc

    bl      ark_inv_sbox_256
    bl      inv_sr_imc

    bl      ark_inv_sbox_256
    bl      inv_sr_imc

    bl      ark_inv_sbox_256
    bl      inv_sr_imc

    bl      ark_inv_sbox_256
    bl      inv_sr_imc

    bl      ark_inv_sbox_256
    bl      inv_sr_imc

    // Round 14: ARK + InvSBox → InvSR only
    bl      ark_inv_sbox_256
    bl      inv_sr_only

    // Final ARK (dk[Nr], no NOT absorption)
    ldr     r0, [sp, #48]
    ldmia   r0!, {r1, r2, r3, r12}
    eor     r4, r1
    eor     r5, r2
    eor     r6, r3
    eor     r7, r12
    ldmia   r0!, {r1, r2, r3, r12}
    eor     r8, r1
    eor     r9, r2
    eor     r10, r3
    eor     r11, r12

    bl      dec_unpacking_256

    // Store plaintext (big-endian)
    ldr     r0, [sp, #64]
    rev     r4, r4
    rev     r5, r5
    rev     r6, r6
    rev     r7, r7
    rev     r8, r8
    rev     r9, r9
    rev     r10, r10
    rev     r11, r11
    stm     r0, {r4-r11}

    add.w   sp, #56
    pop     {r0-r12, r14}
    bx      lr
