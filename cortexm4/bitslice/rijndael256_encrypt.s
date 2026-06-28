/******************************************************************************
* Rijndael-256 Bitsliced Encrypt — ARM Cortex-M4 (Explicit ShiftRows v2)
*
* Single 256-bit block, Nr=14 for all key sizes.
* AES-order SWAPMOVE: state[0]=MSB (bit 7), compatible with Boyar-Peralta.
* Big-endian byte ordering (matching C reference trace 1:1).
*
* EXPLICIT ShiftRows approach:
*   - State is ALWAYS in canonical position (position 0)
*   - Each round: ARK+SBox → SR → MC (rounds 1-13), ARK+SBox → SR (round 14)
*   - Single sr_mc function replaces 8 MC variants + resync
*   - All round keys stored in canonical form (no position rotation)
*
* Key difference from fixslicing (v1/v3):
*   - Fixslicing: pre_rot(96) + MC(35) + post_rot(96) = 227 per round (worst)
*   - Explicit SR: SR(96) + MC(35) = 131 per round (constant)
*   - Savings: ~670 instructions over 14 rounds
*
* NOTE: Requires key schedule with NOT-absorbed keys (K1..K14 planes
*       1,2,6,7 XORed with 0xFFFFFFFF). All keys in canonical form.
*
* Based on the AES fixslicing by Alexandre Adomnicai (eprint 2020/1123).
* Adapted for 256-bit block with ShiftRows = (0, 1, 3, 4).
*
* Register allocation:
*   r4-r11: 8-word bitsliced state (state[0]..state[7])
*   r0-r3, r12, r14: temporaries
*
* Stack layout (56 bytes local):
*   sp+0..43:  S-box intermediate values (12 slots)
*   sp+44:     S-box scratch
*   sp+48:     round key pointer (auto-advanced by ark_sbox_256)
*   sp+52:     LR save slot (shared by subroutines)
*   sp+56..108: saved r0-r12, r14 from push
*     sp+56 = r0 (ks pointer)
*     sp+60 = r1 (pt pointer)
*     sp+64 = r2 (ct pointer)
*
* Calling convention:
*   void rijndael256_encrypt(const R256Key *ks,
*                                const uint8_t pt[32],
*                                uint8_t ct[32]);
*   r0 = ks (= &roundKey[0]), r1 = pt, r2 = ct
******************************************************************************/

.syntax unified
.thumb

/******************************************************************************
* SWAPMOVE macro
******************************************************************************/
.macro swpmv out0, out1, in0, in1, m, n, tmp
    eor     \tmp, \in1, \in0, lsr \n
    and     \tmp, \m
    eor     \out1, \in1, \tmp
    eor     \out0, \in0, \tmp, lsl \n
.endm

/******************************************************************************
* BYTE_ROL macro: rotate one byte within a word by rot bits LEFT
*
* pos: byte position (0=bits 0-7, 1=bits 8-15, 2=bits 16-23)
* rot: rotation amount (1-7)
* Uses 1 temporary register. 4 instructions.
******************************************************************************/
.macro byte_rol reg, pos, rot, tmp
    ubfx    \tmp, \reg, #(\pos * 8), #8
    orr     \tmp, \tmp, \tmp, lsl #8
    ubfx    \tmp, \tmp, #(8 - \rot), #8
    bfi     \reg, \tmp, #(\pos * 8), #8
.endm

/******************************************************************************
* SR_134 macro: Apply Rijndael-256 ShiftRows to one register
*
* SR = (0, 1, 3, 4):
*   byte 3 (row 0): unchanged
*   byte 2 (row 1): ROL 1
*   byte 1 (row 2): ROL 3
*   byte 0 (row 3): ROL 4 (= nibble swap)
*
* 12 instructions per register, uses 1 temp.
******************************************************************************/
.macro sr_134 reg, tmp
    byte_rol \reg, 2, 1, \tmp
    byte_rol \reg, 1, 3, \tmp
    byte_rol \reg, 0, 4, \tmp
.endm

/******************************************************************************
* SBOX_TO_CANONICAL: Move S-box shuffled output to canonical r4-r11 order
*
* Input (shuffled from ark_sbox_256):
*   r1=S0, r3=S1, r6=S2, r7=S3, r8=S4, r0=S5, r2=S6, r11=S7
*
* Output (canonical):
*   r4=state[0], r5=state[1], r6=state[2], r7=state[3],
*   r8=state[4], r9=state[5], r10=state[6], r11=state[7]
*
* NOTs are NOT applied — absorbed into key schedule.
* 4 instructions. After this, r0-r3 are free.
******************************************************************************/
.macro sbox_to_canonical
    mov     r4, r1              // state[0] = S0
    mov     r5, r3              // state[1] = S1
    mov     r9, r0              // state[5] = S5
    mov     r10, r2             // state[6] = S6
    // r6 = S2 = state[2]       (already in place)
    // r7 = S3 = state[3]       (already in place)
    // r8 = S4 = state[4]       (already in place)
    // r11 = S7 = state[7]      (already in place)
.endm

/******************************************************************************
* Packing: Bitplane transpose of r4-r11 in-place
******************************************************************************/
.align 2
packing_256:
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
unpacking_256:
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
* ARK + S-box (Boyar-Peralta, 113 gates, NO NOTs)
*
* Input:  r4-r11 = state[0..7] (canonical order)
*         sp+48  = round key pointer (advanced by 32 bytes after)
*
* Output: SHUFFLED register assignment:
*   r1  = S0 (state[0])     r3  = S1 (state[1])
*   r6  = S2 (state[2])     r7  = S3 (state[3])
*   r8  = S4 (state[4])     r0  = S5 (state[5])
*   r2  = S6 (state[6])     r11 = S7 (state[7])
******************************************************************************/
.align 2
ark_sbox_256:
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

    // --- S-box (Boyar-Peralta, gate-for-gate identical to AES) ---
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
* sr_mc: ShiftRows + MixColumns (for rounds 1-13)
*
* Input:  Shuffled S-box output (r0-r3,r6-r8,r11)
* Output: r4-r11 = state[0..7], canonical
*
* sbox_to_canonical (4) + SR (96) + MC_KS (35) = 135 instructions + bx lr
******************************************************************************/
.align 2
sr_mc:
    // ======== Phase 0: Remap S-box output to canonical order ========
    sbox_to_canonical

    // ======== Phase 1: ShiftRows (byte_ROL 1,3,4 for rows 1,2,3) ========
    sr_134  r4, r0
    sr_134  r5, r0
    sr_134  r6, r0
    sr_134  r7, r0
    sr_134  r8, r0
    sr_134  r9, r0
    sr_134  r10, r0
    sr_134  r11, r0

    // ======== Phase 2: Käsper-Schwabe MixColumns (35 instructions) ========
    // d_i = s_i ^ (s_i ror 24), σ_i = d_i ^ (d_i ror 16)
    // OUT_i = (s_i ror 24) ^ (d_i ror 16) ^ xd_i
    // r0 = d_0 kept for GF(2^8) reduction feedback

    eor     r0, r4, r4, ror #24        // d_0 (permanent for feedback)

    // i=0: xd_0 = d_1
    eor     r3, r5, r5, ror #24        // d_1
    eor     r4, r4, r0                 // s_0 ^ d_0 = s_0 ror 24
    eor     r4, r4, r0, ror #16        // ^ (d_0 ror 16)
    eor     r4, r4, r3                 // ^ d_1

    // i=1: xd_1 = d_2
    eor     r2, r6, r6, ror #24        // d_2
    eor     r5, r5, r3                 // s_1 ror 24
    eor     r5, r5, r3, ror #16        // ^ (d_1 ror 16)
    eor     r5, r5, r2                 // ^ d_2

    // i=2: xd_2 = d_3
    eor     r3, r7, r7, ror #24        // d_3
    eor     r6, r6, r2                 // s_2 ror 24
    eor     r6, r6, r2, ror #16        // ^ (d_2 ror 16)
    eor     r6, r6, r3                 // ^ d_3

    // i=3: xd_3 = d_4 ^ d_0 (reduction)
    eor     r2, r8, r8, ror #24        // d_4
    eor     r7, r7, r3                 // s_3 ror 24
    eor     r7, r7, r3, ror #16        // ^ (d_3 ror 16)
    eor     r7, r7, r2                 // ^ d_4
    eor     r7, r7, r0                 // ^ d_0 (feedback)

    // i=4: xd_4 = d_5 ^ d_0 (reduction)
    eor     r3, r9, r9, ror #24        // d_5
    eor     r8, r8, r2                 // s_4 ror 24
    eor     r8, r8, r2, ror #16        // ^ (d_4 ror 16)
    eor     r8, r8, r3                 // ^ d_5
    eor     r8, r8, r0                 // ^ d_0 (feedback)

    // i=5: xd_5 = d_6
    eor     r2, r10, r10, ror #24      // d_6
    eor     r9, r9, r3                 // s_5 ror 24
    eor     r9, r9, r3, ror #16        // ^ (d_5 ror 16)
    eor     r9, r9, r2                 // ^ d_6

    // i=6: xd_6 = d_7 ^ d_0 (reduction)
    eor     r3, r11, r11, ror #24      // d_7
    eor     r10, r10, r2               // s_6 ror 24
    eor     r10, r10, r2, ror #16      // ^ (d_6 ror 16)
    eor     r10, r10, r3               // ^ d_7
    eor     r10, r10, r0               // ^ d_0 (feedback)

    // i=7: xd_7 = d_0
    eor     r11, r11, r3               // s_7 ror 24
    eor     r11, r11, r3, ror #16      // ^ (d_7 ror 16)
    eor     r11, r11, r0               // ^ d_0

    bx      lr

/******************************************************************************
* sr_only: ShiftRows without MixColumns (for final round 14)
*
* Input:  Shuffled S-box output (r0-r3,r6-r8,r11)
* Output: r4-r11 = state[0..7], canonical with SR applied
*
* sbox_to_canonical (4) + SR (96) = 100 instructions + bx lr
******************************************************************************/
.align 2
sr_only:
    sbox_to_canonical

    sr_134  r4, r0
    sr_134  r5, r0
    sr_134  r6, r0
    sr_134  r7, r0
    sr_134  r8, r0
    sr_134  r9, r0
    sr_134  r10, r0
    sr_134  r11, r0

    bx      lr

/******************************************************************************
* Main encrypt entry point
*
* void rijndael256_encrypt(const R256Key *ks,
*                              const uint8_t pt[32],
*                              uint8_t ct[32]);
*
* Round structure (Nr=14, explicit SR, NOTs in keys):
*   pack(pt)
*   Round  1: ARK(K0)+SBox → SR+MC
*   Round  2: ARK(K1)+SBox → SR+MC
*   ...
*   Round 13: ARK(K12)+SBox → SR+MC
*   Round 14: ARK(K13)+SBox → SR (no MC)
*   ARK(K14)
*   unpack(ct)
*
* All round keys are in canonical form (no position rotation).
******************************************************************************/
.global rijndael256_encrypt
.type   rijndael256_encrypt,%function
.align 2
rijndael256_encrypt:
    push    {r0-r12, r14}
    sub.w   sp, #56

    // Save round key pointer
    str.w   r0, [sp, #48]

    // Load 32 bytes of plaintext (big-endian)
    ldm     r1, {r4-r11}
    rev     r4, r4
    rev     r5, r5
    rev     r6, r6
    rev     r7, r7
    rev     r8, r8
    rev     r9, r9
    rev     r10, r10
    rev     r11, r11

    // Bitplane transpose
    bl      packing_256

    // ---- 14 rounds (explicit ShiftRows) ----

    // Rounds 1-13: ARK + SBox → SR + MC
    bl      ark_sbox_256
    bl      sr_mc

    bl      ark_sbox_256
    bl      sr_mc

    bl      ark_sbox_256
    bl      sr_mc

    bl      ark_sbox_256
    bl      sr_mc

    bl      ark_sbox_256
    bl      sr_mc

    bl      ark_sbox_256
    bl      sr_mc

    bl      ark_sbox_256
    bl      sr_mc

    bl      ark_sbox_256
    bl      sr_mc

    bl      ark_sbox_256
    bl      sr_mc

    bl      ark_sbox_256
    bl      sr_mc

    bl      ark_sbox_256
    bl      sr_mc

    bl      ark_sbox_256
    bl      sr_mc

    bl      ark_sbox_256
    bl      sr_mc

    // Round 14 (final): ARK + SBox → SR only (no MC)
    bl      ark_sbox_256
    bl      sr_only

    // ---- Final ARK (K14, NOT-absorbed) ----
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

    // Inverse bitplane transpose
    bl      unpacking_256

    // Store ciphertext (big-endian)
    ldr     r0, [sp, #64]          // load ct pointer (saved r2)
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
