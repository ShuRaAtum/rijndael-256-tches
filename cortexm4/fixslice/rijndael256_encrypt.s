/******************************************************************************
* Rijndael-256 Fully-Fixsliced Encrypt — ARM Cortex-M4 (Optimized v3)
*
* Single 256-bit block, Nr=14 for all key sizes.
* AES-order SWAPMOVE: state[0]=MSB (bit 7), compatible with Boyar-Peralta.
* Big-endian byte ordering (matching C reference trace 1:1).
*
* MC_0..MC_7: 8 MixColumns variants for positions 0-7.
* resync_256: final round resync for Nr=14.
*
* Optimizations vs v1 (fixslicing_rijndael-256_claude):
*   1. remap_sbox merged into MC (saves bl/bx overhead per round)
*   2. S-box 4 NOTs absorbed into key schedule (mvn → mov, saves 2/round)
*   3. Final round inlined (no separate remap/resync function calls)
*   Total savings: ~58 instructions over 14 rounds.
*   NOTE: Requires key schedule with NOT-absorbed keys (K1..K14 planes
*         1,2,6,7 XORed with 0xFFFFFFFF).
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
*
* Swaps bits: t = (in1 ^ (in0 >> n)) & m; out1 = in1 ^ t; out0 = in0 ^ (t<<n)
* Equivalent to C: SWAPMOVE(a=in0, b=in1, mask, n)
******************************************************************************/
.macro swpmv out0, out1, in0, in1, m, n, tmp
    eor     \tmp, \in1, \in0, lsr \n
    and     \tmp, \m
    eor     \out1, \in1, \tmp
    eor     \out0, \in0, \tmp, lsl \n
.endm

/******************************************************************************
* BYTE_ROR macro: rotate each byte within a word by n0 bits right
* m = mask for the shifted-out bits, n0 = shift amount, n1 = 8 - n0
******************************************************************************/
.macro byteror out, in, m, n0, n1, tmp
    and     \out, \m, \in, lsr \n0
    bic     \tmp, \in, \m, ror \n1
    orr     \out, \out, \tmp, lsl \n1
.endm

/******************************************************************************
* BYTE_ROL macro: rotate one byte within a word by rot bits LEFT
*
* Uses the "double and extract" trick:
*   1. Extract the byte (8 bits)
*   2. Duplicate: orr tmp, tmp, tmp, lsl #8  → [b7..b0 b7..b0]
*   3. Extract 8 bits at offset (8-rot) → ROL result
*   4. Insert back into register with bfi
*
* pos: byte position (0=bits 0-7, 1=bits 8-15, 2=bits 16-23)
* rot: rotation amount (1-7)
* Uses 1 temporary register.
******************************************************************************/
.macro byte_rol reg, pos, rot, tmp
    ubfx    \tmp, \reg, #(\pos * 8), #8
    orr     \tmp, \tmp, \tmp, lsl #8
    ubfx    \tmp, \tmp, #(8 - \rot), #8
    bfi     \reg, \tmp, #(\pos * 8), #8
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
* NOTs are NOT applied here — they are absorbed into the key schedule
* (K1..K14 planes 1,2,6,7 pre-XORed with 0xFFFFFFFF).
*
* 4 instructions. After this, r0-r3 are free for use as temporaries.
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
* SR_134 macro: Apply Rijndael-256 ShiftRows byte rotation to one register
*
* SR = (0, 1, 3, 4) → byte_ROL(row1:1, row2:3, row3:4)
*   byte 3 (row 0): unchanged
*   byte 2 (row 1): ROL 1
*   byte 1 (row 2): ROL 3
*   byte 0 (row 3): ROL 4 (= nibble swap)
*
* 12 instructions per register, uses 1 temp.
* This rotation is also apply_pos(1), used for mc_0's post-rotation.
******************************************************************************/
.macro sr_134 reg, tmp
    byte_rol \reg, 2, 1, \tmp
    byte_rol \reg, 1, 3, \tmp
    byte_rol \reg, 0, 4, \tmp
.endm

/******************************************************************************
* ROT_260: byte_ROL(row1:2, row2:6) — 8 instructions per register
******************************************************************************/
.macro rot_260 reg, tmp
    byte_rol \reg, 2, 2, \tmp
    byte_rol \reg, 1, 6, \tmp
.endm

/******************************************************************************
* ROT_314: byte_ROL(row1:3, row2:1, row3:4) — 12 instructions per register
******************************************************************************/
.macro rot_314 reg, tmp
    byte_rol \reg, 2, 3, \tmp
    byte_rol \reg, 1, 1, \tmp
    byte_rol \reg, 0, 4, \tmp
.endm

/******************************************************************************
* NIBSWAP_12: simultaneous nibble swap (ROL 4) of bytes 1 and 2
* Requires mask register = 0x000f0f00. 4 instructions per register.
******************************************************************************/
.macro nibswap_12 reg, mask, tmp
    eor     \tmp, \reg, \reg, lsr #4
    and     \tmp, \mask
    eor     \reg, \reg, \tmp
    eor     \reg, \reg, \tmp, lsl #4
.endm

/******************************************************************************
* ROT_574: byte_ROL(row1:5, row2:7, row3:4) — 12 instructions per register
******************************************************************************/
.macro rot_574 reg, tmp
    byte_rol \reg, 2, 5, \tmp
    byte_rol \reg, 1, 7, \tmp
    byte_rol \reg, 0, 4, \tmp
.endm

/******************************************************************************
* ROT_620: byte_ROL(row1:6, row2:2) — 8 instructions per register
******************************************************************************/
.macro rot_620 reg, tmp
    byte_rol \reg, 2, 6, \tmp
    byte_rol \reg, 1, 2, \tmp
.endm

/******************************************************************************
* ROT_754: byte_ROL(row1:7, row2:5, row3:4) — 12 instructions per register
******************************************************************************/
.macro rot_754 reg, tmp
    byte_rol \reg, 2, 7, \tmp
    byte_rol \reg, 1, 5, \tmp
    byte_rol \reg, 0, 4, \tmp
.endm

/******************************************************************************
* MC_KS_CORE: Käsper-Schwabe MixColumns on column-aligned data (35 instr)
*
* Operates on r4-r11, clobbers r0-r3.
* d_i = s_i ^ (s_i ror 24), σ_i = d_i ^ (d_i ror 16)
* OUT_i = (s_i ror 24) ^ (d_i ror 16) ^ xd_i
* xtime feedback: xd_3, xd_4, xd_6 include d_0; xd_7 = d_0
******************************************************************************/
.macro mc_ks_core
    eor     r0, r4, r4, ror #24
    eor     r3, r5, r5, ror #24
    eor     r4, r4, r0
    eor     r4, r4, r0, ror #16
    eor     r4, r4, r3
    eor     r2, r6, r6, ror #24
    eor     r5, r5, r3
    eor     r5, r5, r3, ror #16
    eor     r5, r5, r2
    eor     r3, r7, r7, ror #24
    eor     r6, r6, r2
    eor     r6, r6, r2, ror #16
    eor     r6, r6, r3
    eor     r2, r8, r8, ror #24
    eor     r7, r7, r3
    eor     r7, r7, r3, ror #16
    eor     r7, r7, r2
    eor     r7, r7, r0
    eor     r3, r9, r9, ror #24
    eor     r8, r8, r2
    eor     r8, r8, r2, ror #16
    eor     r8, r8, r3
    eor     r8, r8, r0
    eor     r2, r10, r10, ror #24
    eor     r9, r9, r3
    eor     r9, r9, r3, ror #16
    eor     r9, r9, r2
    eor     r3, r11, r11, ror #24
    eor     r10, r10, r2
    eor     r10, r10, r2, ror #16
    eor     r10, r10, r3
    eor     r10, r10, r0
    eor     r11, r11, r3
    eor     r11, r11, r3, ror #16
    eor     r11, r11, r0
.endm

/******************************************************************************
* Packing: Bitplane transpose of r4-r11 in-place
*
* Matches C reference r256_pack() — AES-order SWAPMOVE.
* Input:  r4-r11 = 8 big-endian words (after ldm + rev)
* Output: r4-r11 = 8 bitplanes
*   r4  = state[0] = bit 7 (MSB) of all 32 bytes
*   r5  = state[1] = bit 6
*   ...
*   r11 = state[7] = bit 0 (LSB) of all 32 bytes
*
* Within each bitplane word:
*   byte 3 (bits 24-31) = row 0
*   byte 2 (bits 16-23) = row 1
*   byte 1 (bits  8-15) = row 2
*   byte 0 (bits  0- 7) = row 3
*   column c = bit c within each byte (LSB = col 0)
******************************************************************************/
.align 2
packing_256:
    movw    r3, #0x0f0f
    movt    r3, #0x0f0f             // r3 <- 0x0f0f0f0f
    eor     r2, r3, r3, lsl #2      // r2 <- 0x33333333
    eor     r1, r2, r2, lsl #1      // r1 <- 0x55555555

    // Layer 1: n=1, mask=0x55555555
    // SWAPMOVE(state[1], state[0]), (3,2), (5,4), (7,6)
    swpmv   r5, r4, r5, r4, r1, #1, r12
    swpmv   r7, r6, r7, r6, r1, #1, r12
    swpmv   r9, r8, r9, r8, r1, #1, r12
    swpmv   r11, r10, r11, r10, r1, #1, r12

    // Layer 2: n=2, mask=0x33333333
    // SWAPMOVE(state[2], state[0]), (3,1), (6,4), (7,5)
    swpmv   r6, r4, r6, r4, r2, #2, r12
    swpmv   r7, r5, r7, r5, r2, #2, r12
    swpmv   r10, r8, r10, r8, r2, #2, r12
    swpmv   r11, r9, r11, r9, r2, #2, r12

    // Layer 3: n=4, mask=0x0f0f0f0f
    // SWAPMOVE(state[4], state[0]), (5,1), (6,2), (7,3)
    swpmv   r8, r4, r8, r4, r3, #4, r12
    swpmv   r9, r5, r9, r5, r3, #4, r12
    swpmv   r10, r6, r10, r6, r3, #4, r12
    swpmv   r11, r7, r11, r7, r3, #4, r12

    bx      lr

/******************************************************************************
* Unpacking: Inverse bitplane transpose of r4-r11
*
* SWAPMOVE is its own inverse; apply layers in reverse order.
* After this, r4-r11 hold big-endian words ready for rev + stm.
******************************************************************************/
.align 2
unpacking_256:
    movw    r3, #0x0f0f
    movt    r3, #0x0f0f             // r3 <- 0x0f0f0f0f
    eor     r2, r3, r3, lsl #2      // r2 <- 0x33333333
    eor     r1, r2, r2, lsl #1      // r1 <- 0x55555555

    // Layer 3 first (reverse order)
    swpmv   r8, r4, r8, r4, r3, #4, r12
    swpmv   r9, r5, r9, r5, r3, #4, r12
    swpmv   r10, r6, r10, r6, r3, #4, r12
    swpmv   r11, r7, r11, r7, r3, #4, r12

    // Layer 2
    swpmv   r6, r4, r6, r4, r2, #2, r12
    swpmv   r7, r5, r7, r5, r2, #2, r12
    swpmv   r10, r8, r10, r8, r2, #2, r12
    swpmv   r11, r9, r11, r9, r2, #2, r12

    // Layer 1
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
*
* NOTs are NOT included here (moved to remap_sbox_256).
* Credits: https://github.com/Ko-/aes-armcortexm
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
    // Input: r4=U0, r5=U1, r6=U2, r7=U3, r8=U4, r9=U5, r10=U6, r11=U7
    eor     r1, r7, r9              //Exec y14 = U3 ^ U5
    eor     r3, r4, r10             //Exec y13 = U0 ^ U6
    eor     r2, r3, r1              //Exec y12 = y13 ^ y14
    eor     r0, r8, r2              //Exec t1 = U4 ^ y12
    eor     r14, r0, r9             //Exec y15 = t1 ^ U5
    and     r12, r2, r14            //Exec t2 = y12 & y15
    eor     r8, r14, r11            //Exec y6 = y15 ^ U7
    eor     r0, r0, r5              //Exec y20 = t1 ^ U1
    str.w   r2, [sp, #44]           //Store y12
    eor     r2, r4, r7              //Exec y9 = U0 ^ U3
    str     r0, [sp, #40]           //Store y20
    eor     r0, r0, r2              //Exec y11 = y20 ^ y9
    str     r2, [sp, #36]           //Store y9
    and     r2, r2, r0              //Exec t12 = y9 & y11
    str     r8, [sp, #32]           //Store y6
    eor     r8, r11, r0             //Exec y7 = U7 ^ y11
    eor     r9, r4, r9              //Exec y8 = U0 ^ U5
    eor     r6, r5, r6              //Exec t0 = U1 ^ U2
    eor     r5, r14, r6             //Exec y10 = y15 ^ t0
    str     r14, [sp, #28]          //Store y15
    eor     r14, r5, r0             //Exec y17 = y10 ^ y11
    str.w   r1, [sp, #24]           //Store y14
    and     r1, r1, r14             //Exec t13 = y14 & y17
    eor     r1, r1, r2              //Exec t14 = t13 ^ t12
    str     r14, [sp, #20]          //Store y17
    eor     r14, r5, r9             //Exec y19 = y10 ^ y8
    str.w   r5, [sp, #16]           //Store y10
    and     r5, r9, r5              //Exec t15 = y8 & y10
    eor     r2, r5, r2              //Exec t16 = t15 ^ t12
    eor     r5, r6, r0              //Exec y16 = t0 ^ y11
    str.w   r0, [sp, #12]           //Store y11
    eor     r0, r3, r5              //Exec y21 = y13 ^ y16
    str     r3, [sp, #8]            //Store y13
    and     r3, r3, r5              //Exec t7 = y13 & y16
    str     r5, [sp, #4]            //Store y16
    str     r11, [sp, #0]           //Store U7
    eor     r5, r4, r5              //Exec y18 = U0 ^ y16
    eor     r6, r6, r11             //Exec y1 = t0 ^ U7
    eor     r7, r6, r7              //Exec y4 = y1 ^ U3
    and     r11, r7, r11            //Exec t5 = y4 & U7
    eor     r11, r11, r12           //Exec t6 = t5 ^ t2
    eor     r11, r11, r2            //Exec t18 = t6 ^ t16
    eor     r14, r11, r14           //Exec t22 = t18 ^ y19
    eor     r4, r6, r4              //Exec y2 = y1 ^ U0
    and     r11, r4, r8             //Exec t10 = y2 & y7
    eor     r11, r11, r3            //Exec t11 = t10 ^ t7
    eor     r2, r11, r2             //Exec t20 = t11 ^ t16
    eor     r2, r2, r5              //Exec t24 = t20 ^ y18
    eor     r10, r6, r10            //Exec y5 = y1 ^ U6
    and     r11, r10, r6            //Exec t8 = y5 & y1
    eor     r3, r11, r3             //Exec t9 = t8 ^ t7
    eor     r3, r3, r1              //Exec t19 = t9 ^ t14
    eor     r3, r3, r0              //Exec t23 = t19 ^ y21
    eor     r0, r10, r9             //Exec y3 = y5 ^ y8
    ldr     r11, [sp, #32]          //Load y6
    and     r5, r0, r11             //Exec t3 = y3 & y6
    eor     r12, r5, r12            //Exec t4 = t3 ^ t2
    ldr     r5, [sp, #40]           //Load y20
    str     r7, [sp, #32]           //Store y4
    eor     r12, r12, r5            //Exec t17 = t4 ^ y20
    eor     r1, r12, r1             //Exec t21 = t17 ^ t14
    and     r12, r1, r3             //Exec t26 = t21 & t23
    eor     r5, r2, r12             //Exec t27 = t24 ^ t26
    eor     r12, r14, r12           //Exec t31 = t22 ^ t26
    eor     r1, r1, r14             //Exec t25 = t21 ^ t22
    and     r7, r1, r5              //Exec t28 = t25 & t27
    eor     r14, r7, r14            //Exec t29 = t28 ^ t22
    and     r4, r14, r4             //Exec z14 = t29 & y2
    and     r8, r14, r8             //Exec z5 = t29 & y7
    eor     r7, r3, r2              //Exec t30 = t23 ^ t24
    and     r12, r12, r7            //Exec t32 = t31 & t30
    eor     r12, r12, r2            //Exec t33 = t32 ^ t24
    eor     r7, r5, r12             //Exec t35 = t27 ^ t33
    and     r2, r2, r7              //Exec t36 = t24 & t35
    eor     r5, r5, r2              //Exec t38 = t27 ^ t36
    and     r5, r14, r5             //Exec t39 = t29 & t38
    eor     r1, r1, r5              //Exec t40 = t25 ^ t39
    eor     r5, r14, r1             //Exec t43 = t29 ^ t40
    ldr.w   r7, [sp, #4]            //Load y16
    and     r7, r5, r7              //Exec z3 = t43 & y16
    eor     r8, r7, r8              //Exec tc12 = z3 ^ z5
    str     r8, [sp, #40]           //Store tc12
    ldr     r8, [sp, #8]            //Load y13
    and     r8, r5, r8              //Exec z12 = t43 & y13
    and     r10, r1, r10            //Exec z13 = t40 & y5
    and     r6, r1, r6              //Exec z4 = t40 & y1
    eor     r6, r7, r6              //Exec tc6 = z3 ^ z4
    eor     r3, r3, r12             //Exec t34 = t23 ^ t33
    eor     r3, r2, r3              //Exec t37 = t36 ^ t34
    eor     r1, r1, r3              //Exec t41 = t40 ^ t37
    ldr.w   r5, [sp, #16]           //Load y10
    and     r2, r1, r5              //Exec z8 = t41 & y10
    and     r9, r1, r9              //Exec z17 = t41 & y8
    str     r9, [sp, #16]           //Store z17
    eor     r5, r12, r3             //Exec t44 = t33 ^ t37
    ldr     r9, [sp, #28]           //Load y15
    ldr.w   r7, [sp, #44]           //Load y12
    and     r9, r5, r9              //Exec z0 = t44 & y15
    and     r7, r5, r7              //Exec z9 = t44 & y12
    and     r0, r3, r0              //Exec z10 = t37 & y3
    and     r3, r3, r11             //Exec z1 = t37 & y6
    eor     r3, r3, r9              //Exec tc5 = z1 ^ z0
    eor     r3, r6, r3              //Exec tc11 = tc6 ^ tc5
    ldr     r11, [sp, #32]          //Load y4
    ldr.w   r5, [sp, #20]           //Load y17
    and     r11, r12, r11           //Exec z11 = t33 & y4
    eor     r14, r14, r12           //Exec t42 = t29 ^ t33
    eor     r1, r14, r1             //Exec t45 = t42 ^ t41
    and     r5, r1, r5              //Exec z7 = t45 & y17
    eor     r6, r5, r6              //Exec tc8 = z7 ^ tc6
    ldr     r5, [sp, #24]           //Load y14
    str     r4, [sp, #32]           //Store z14
    and     r1, r1, r5              //Exec z16 = t45 & y14
    ldr     r5, [sp, #12]           //Load y11
    ldr     r4, [sp, #36]           //Load y9
    and     r5, r14, r5             //Exec z6 = t42 & y11
    eor     r5, r5, r6              //Exec tc16 = z6 ^ tc8
    and     r4, r14, r4             //Exec z15 = t42 & y9
    eor     r14, r4, r5             //Exec tc20 = z15 ^ tc16
    eor     r4, r4, r1              //Exec tc1 = z15 ^ z16
    eor     r1, r0, r4              //Exec tc2 = z10 ^ tc1
    eor     r0, r1, r11             //Exec tc21 = tc2 ^ z11
    eor     r7, r7, r1              //Exec tc3 = z9 ^ tc2
    eor     r1, r7, r5              //Exec S0 = tc3 ^ tc16
    eor     r7, r7, r3              //Exec S3 = tc3 ^ tc11
    eor     r3, r7, r5              //Exec S1 = S3 ^ tc16 ^ 1
    eor     r11, r10, r4            //Exec tc13 = z13 ^ tc1
    ldr.w   r4, [sp, #0]            //Load U7
    and     r12, r12, r4            //Exec z2 = t33 & U7
    eor     r9, r9, r12             //Exec tc4 = z0 ^ z2
    eor     r12, r8, r9             //Exec tc7 = z12 ^ tc4
    eor     r2, r2, r12             //Exec tc9 = z8 ^ tc7
    eor     r2, r6, r2              //Exec tc10 = tc8 ^ tc9
    ldr.w   r4, [sp, #32]           //Load z14
    eor     r12, r4, r2             //Exec tc17 = z14 ^ tc10
    eor     r0, r0, r12             //Exec S5 = tc21 ^ tc17
    eor     r6, r12, r14            //Exec tc26 = tc17 ^ tc20
    ldr.w   r4, [sp, #16]           //Load z17
    ldr     r12, [sp, #40]          //Load tc12
    eor     r6, r6, r4              //Exec S2 = tc26 ^ z17 ^ 1
    eor     r12, r9, r12            //Exec tc14 = tc4 ^ tc12
    eor     r14, r11, r12           //Exec tc18 = tc13 ^ tc14
    eor     r2, r2, r14             //Exec S6 = tc10 ^ tc18 ^ 1
    eor     r11, r8, r14            //Exec S7 = z12 ^ tc18 ^ 1
    ldr     r14, [sp, #52]          // restore link register
    eor     r8, r12, r7             //Exec S4 = tc14 ^ S3
    // Output: r1=S0, r3=S1, r6=S2, r7=S3, r8=S4, r0=S5, r2=S6, r11=S7
    bx      lr

// remap_sbox_256 REMOVED — NOTs absorbed into key schedule,
// register remap inlined into each mc_X via sbox_to_canonical macro.

/******************************************************************************
* MixColumns stubs: mc_0 through mc_7
*
* Each MC_k transitions position k → (k+1)%8.
* Input:  r4-r11 = state[0..7] in canonical order (after remap_sbox_256)
* Output: r4-r11 = state[0..7] in canonical order
*
* The 3-step decomposition for each MC_k:
*   1. Undo position k: byte-ROR each row r by (k*SR[r])%8 columns
*   2. Canonical MixColumns (xtime + row mixing in GF(2^8))
*   3. Apply position (k+1)%8: byte-ROL each row r by ((k+1)*SR[r])%8 columns
*
* Where SR = (0, 1, 3, 4) and byte rotation = column rotation within rows.
*
* Alignment table (column-shift amounts for byte-ROR, per mc_k):
*   k=0: pre=(0,0,0) post=(1,3,4)  |  k=4: pre=(4,4,0) post=(5,7,4)
*   k=1: pre=(1,3,4) post=(2,6,0)  |  k=5: pre=(5,7,4) post=(6,2,0)
*   k=2: pre=(2,6,0) post=(3,1,4)  |  k=6: pre=(6,2,0) post=(7,5,4)
*   k=3: pre=(3,1,4) post=(4,4,0)  |  k=7: pre=(7,5,4) post=(0,0,0)
*
* For efficient ASM: combine pre/post rotations with MC's BYTE_ROR/ROR
* operations, as done in AES fixslicing for mc_0..mc_3.
******************************************************************************/

/******************************************************************************
* mc_0: MixColumns for position 0 → 1
*
* Three phases:
*   1. ShiftRows: byte_ROL(row1:1, row2:3, row3:4) — aligns columns
*   2. MC_KS: Käsper-Schwabe MixColumns on column-aligned data
*      d_i = s_i ^ (s_i ror 24)       // row diff
*      σ_i = d_i ^ (d_i ror 16)       // column sum
*      OUT_i = s_i ^ σ_i ^ xd_i       // = (s_i ror 24) ^ (d_i ror 16) ^ xd_i
*      where xd = xtime(d) in bitsliced form (state[0]=MSB):
*        xd_0=d_1, xd_1=d_2, xd_2=d_3, xd_3=d_4^d_0,
*        xd_4=d_5^d_0, xd_5=d_6, xd_6=d_7^d_0, xd_7=d_0
*   3. apply_pos(1): same rotation as SR
*
* For mc_0: undo_pos(0) = identity, so phase 1 is just SR.
*
* Input:  Shuffled S-box output (r0-r3,r6-r8,r11)
* Output: r4-r11 = state[0..7], position 1
* Clobbers: r0-r3
* 231 instructions (4 + 96 + 35 + 96)
******************************************************************************/
.align 2
mc_0:
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
    // d_i = s_i ^ (s_i ror 24), computes s_{r} ^ s_{r+1} for all rows
    // OUT_i = (s_i ror 24) ^ (d_i ror 16) ^ xd_i
    // r0 = d_0 kept permanently for GF(2^8) reduction feedback

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

    // ======== Phase 3: apply_pos(1) = same SR rotation ========
    sr_134  r4, r0
    sr_134  r5, r0
    sr_134  r6, r0
    sr_134  r7, r0
    sr_134  r8, r0
    sr_134  r9, r0
    sr_134  r10, r0
    sr_134  r11, r0

    bx      lr

.align 2
mc_1:
    // mc_1: position 1→2. pre=(0,0,0) [skip], post=(2,6,0) [rot_260]
    // 103 instructions: 4 + 0 + 35 + 64

    // Phase 0: Remap S-box output
    sbox_to_canonical

    // Phase 1: pre-rotation — identity (no rotation needed)

    // Phase 2: MC_KS core (35 instructions)
    mc_ks_core

    // Phase 3: post-rotation — rot_260 (byte_ROL row1:2, row2:6)
    rot_260  r4, r0
    rot_260  r5, r0
    rot_260  r6, r0
    rot_260  r7, r0
    rot_260  r8, r0
    rot_260  r9, r0
    rot_260  r10, r0
    rot_260  r11, r0

    bx      lr

.align 2
mc_2:
    // mc_2: position 2→3. pre=(7,5,4) [rot_754], post=(3,1,4) [rot_314]
    // 231 instructions: 4 + 96 + 35 + 96

    // Phase 0: Remap S-box output
    sbox_to_canonical

    // Phase 1: pre-rotation — rot_754 (byte_ROL row1:7, row2:5, row3:4)
    rot_754  r4, r0
    rot_754  r5, r0
    rot_754  r6, r0
    rot_754  r7, r0
    rot_754  r8, r0
    rot_754  r9, r0
    rot_754  r10, r0
    rot_754  r11, r0

    // Phase 2: MC_KS core (35 instructions)
    mc_ks_core

    // Phase 3: post-rotation — rot_314 (byte_ROL row1:3, row2:1, row3:4)
    rot_314  r4, r0
    rot_314  r5, r0
    rot_314  r6, r0
    rot_314  r7, r0
    rot_314  r8, r0
    rot_314  r9, r0
    rot_314  r10, r0
    rot_314  r11, r0

    bx      lr

.align 2
mc_3:
    // mc_3: position 3→4. pre=(6,2,0) [rot_620], post=(4,4,0) [nibswap]
    // 137 instructions: 4 + 64 + 35 + 34

    // Phase 0: Remap S-box output
    sbox_to_canonical

    // Phase 1: pre-rotation — rot_620 (byte_ROL row1:6, row2:2)
    rot_620  r4, r0
    rot_620  r5, r0
    rot_620  r6, r0
    rot_620  r7, r0
    rot_620  r8, r0
    rot_620  r9, r0
    rot_620  r10, r0
    rot_620  r11, r0

    // Phase 2: MC_KS core (35 instructions)
    mc_ks_core

    // Phase 3: post-rotation — nibswap (byte_ROL row1:4, row2:4)
    movw    r0, #0x0f00
    movt    r0, #0x000f             // mask = 0x000f0f00
    nibswap_12  r4, r0, r1
    nibswap_12  r5, r0, r1
    nibswap_12  r6, r0, r1
    nibswap_12  r7, r0, r1
    nibswap_12  r8, r0, r1
    nibswap_12  r9, r0, r1
    nibswap_12  r10, r0, r1
    nibswap_12  r11, r0, r1

    bx      lr

.align 2
mc_4:
    // mc_4: position 4→5. pre=(5,7,4) [rot_574], post=(5,7,4) [rot_574]
    // 231 instructions: 4 + 96 + 35 + 96

    // Phase 0: Remap S-box output
    sbox_to_canonical

    // Phase 1: pre-rotation — rot_574 (byte_ROL row1:5, row2:7, row3:4)
    rot_574  r4, r0
    rot_574  r5, r0
    rot_574  r6, r0
    rot_574  r7, r0
    rot_574  r8, r0
    rot_574  r9, r0
    rot_574  r10, r0
    rot_574  r11, r0

    // Phase 2: MC_KS core (35 instructions)
    mc_ks_core

    // Phase 3: post-rotation — rot_574 (byte_ROL row1:5, row2:7, row3:4)
    rot_574  r4, r0
    rot_574  r5, r0
    rot_574  r6, r0
    rot_574  r7, r0
    rot_574  r8, r0
    rot_574  r9, r0
    rot_574  r10, r0
    rot_574  r11, r0

    bx      lr

.align 2
mc_5:
    // mc_5: position 5→6. pre=(4,4,0) [nibswap], post=(6,2,0) [rot_620]
    // 137 instructions: 4 + 34 + 35 + 64

    // Phase 0: Remap S-box output
    sbox_to_canonical

    // Phase 1: pre-rotation — nibswap (byte_ROL row1:4, row2:4)
    movw    r0, #0x0f00
    movt    r0, #0x000f             // mask = 0x000f0f00
    nibswap_12  r4, r0, r1
    nibswap_12  r5, r0, r1
    nibswap_12  r6, r0, r1
    nibswap_12  r7, r0, r1
    nibswap_12  r8, r0, r1
    nibswap_12  r9, r0, r1
    nibswap_12  r10, r0, r1
    nibswap_12  r11, r0, r1

    // Phase 2: MC_KS core (35 instructions)
    mc_ks_core

    // Phase 3: post-rotation — rot_620 (byte_ROL row1:6, row2:2)
    rot_620  r4, r0
    rot_620  r5, r0
    rot_620  r6, r0
    rot_620  r7, r0
    rot_620  r8, r0
    rot_620  r9, r0
    rot_620  r10, r0
    rot_620  r11, r0

    bx      lr

.align 2
mc_6:
    // mc_6: position 6→7. pre=(3,1,4) [rot_314], post=(7,5,4) [rot_754]
    // 231 instructions: 4 + 96 + 35 + 96

    // Phase 0: Remap S-box output
    sbox_to_canonical

    // Phase 1: pre-rotation — rot_314 (byte_ROL row1:3, row2:1, row3:4)
    rot_314  r4, r0
    rot_314  r5, r0
    rot_314  r6, r0
    rot_314  r7, r0
    rot_314  r8, r0
    rot_314  r9, r0
    rot_314  r10, r0
    rot_314  r11, r0

    // Phase 2: MC_KS core (35 instructions)
    mc_ks_core

    // Phase 3: post-rotation — rot_754 (byte_ROL row1:7, row2:5, row3:4)
    rot_754  r4, r0
    rot_754  r5, r0
    rot_754  r6, r0
    rot_754  r7, r0
    rot_754  r8, r0
    rot_754  r9, r0
    rot_754  r10, r0
    rot_754  r11, r0

    bx      lr

.align 2
mc_7:
    // mc_7: position 7→0. pre=(2,6,0) [rot_260], post=(0,0,0) [skip]
    // 103 instructions: 4 + 64 + 35 + 0

    // Phase 0: Remap S-box output
    sbox_to_canonical

    // Phase 1: pre-rotation — rot_260 (byte_ROL row1:2, row2:6)
    rot_260  r4, r0
    rot_260  r5, r0
    rot_260  r6, r0
    rot_260  r7, r0
    rot_260  r8, r0
    rot_260  r9, r0
    rot_260  r10, r0
    rot_260  r11, r0

    // Phase 2: MC_KS core (35 instructions)
    mc_ks_core

    // Phase 3: post-rotation — identity (no rotation needed)

    bx      lr

/******************************************************************************
* Resync: transition from final position back to canonical + ShiftRows
*
* For Nr=14: final position is (Nr-1)%8 = 5.
* delta_r = SR[r] * (1 - (Nr-1)) mod 8
*   row 0: delta=0 (always)
*   row 1: delta = 1*(1-13) mod 8 = (-12) mod 8 = 4 → ROL 4 cols
*   row 2: delta = 3*(1-13) mod 8 = (-36) mod 8 = 4 → ROL 4 cols
*   row 3: delta = 4*(1-13) mod 8 = (-48) mod 8 = 0 → no rotation
*
* In SWAPMOVE format: ROL n cols = byte_rol(row_byte, n) for each bitplane.
******************************************************************************/
.align 2
resync_256:
    // Resync for Nr=14: position 5 → canonical+SR = apply_pos(4)
    // row 1: ROL 4 (nibble swap byte 2), row 2: ROL 4 (nibble swap byte 1)
    // row 3: no change. 4 + 34 instructions + bx lr.

    // Phase 0: Remap S-box output
    sbox_to_canonical

    movw    r0, #0x0f00
    movt    r0, #0x000f             // mask = 0x000f0f00
    nibswap_12  r4, r0, r1
    nibswap_12  r5, r0, r1
    nibswap_12  r6, r0, r1
    nibswap_12  r7, r0, r1
    nibswap_12  r8, r0, r1
    nibswap_12  r9, r0, r1
    nibswap_12  r10, r0, r1
    nibswap_12  r11, r0, r1
    bx      lr

/******************************************************************************
* Main encrypt entry point
*
* void rijndael256_encrypt(const R256Key *ks,
*                              const uint8_t pt[32],
*                              uint8_t ct[32]);
*
* r0 = ks (roundKey pointer), r1 = pt, r2 = ct
*
* Round structure (Nr=14, remap merged into MC, NOTs in keys):
*   pack(pt)
*   ARK(K0)+SBox → MC_0                // round 1, pos 0→1
*   ARK(K1)+SBox → MC_1                // round 2, pos 1→2
*   ...
*   ARK(K7)+SBox → MC_7                // round 8, pos 7→0
*   ARK(K8)+SBox → MC_0                // round 9, pos 0→1
*   ...
*   ARK(K12)+SBox → MC_4               // round 13, pos 4→5
*   ARK(K13)+SBox → resync_256         // round 14, pos 5→canonical+SR
*   ARK(K14) (final, NOT-absorbed)
*   unpack(ct)
******************************************************************************/
.global rijndael256_encrypt
.type   rijndael256_encrypt,%function
.align 2
rijndael256_encrypt:
    push    {r0-r12, r14}
    sub.w   sp, #56                 // 56 bytes for local variables

    // Save round key pointer for ark_sbox_256
    str.w   r0, [sp, #48]          // sp+48 = rkey ptr (auto-advanced)

    // Load 32 bytes of plaintext (big-endian)
    ldm     r1, {r4-r11}           // load 8 words from pt
    rev     r4, r4                  // byte-reverse for big-endian
    rev     r5, r5
    rev     r6, r6
    rev     r7, r7
    rev     r8, r8
    rev     r9, r9
    rev     r10, r10
    rev     r11, r11

    // Bitplane transpose
    bl      packing_256

    // ---- 14 rounds (ARK fused with SBox, remap merged into MC) ----
    // NOTE: remap_sbox_256 is eliminated — sbox_to_canonical is inlined
    //       into each mc_X function. NOTs absorbed into key schedule.

    // Round 1: ARK(K0) + SBox → MC_0 (pos 0→1)
    bl      ark_sbox_256
    bl      mc_0

    // Round 2: ARK(K1) + SBox → MC_1 (pos 1→2)
    bl      ark_sbox_256
    bl      mc_1

    // Round 3: ARK(K2) + SBox → MC_2 (pos 2→3)
    bl      ark_sbox_256
    bl      mc_2

    // Round 4: ARK(K3) + SBox → MC_3 (pos 3→4)
    bl      ark_sbox_256
    bl      mc_3

    // Round 5: ARK(K4) + SBox → MC_4 (pos 4→5)
    bl      ark_sbox_256
    bl      mc_4

    // Round 6: ARK(K5) + SBox → MC_5 (pos 5→6)
    bl      ark_sbox_256
    bl      mc_5

    // Round 7: ARK(K6) + SBox → MC_6 (pos 6→7)
    bl      ark_sbox_256
    bl      mc_6

    // Round 8: ARK(K7) + SBox → MC_7 (pos 7→0)
    bl      ark_sbox_256
    bl      mc_7

    // Round 9: ARK(K8) + SBox → MC_0 (pos 0→1)
    bl      ark_sbox_256
    bl      mc_0

    // Round 10: ARK(K9) + SBox → MC_1 (pos 1→2)
    bl      ark_sbox_256
    bl      mc_1

    // Round 11: ARK(K10) + SBox → MC_2 (pos 2→3)
    bl      ark_sbox_256
    bl      mc_2

    // Round 12: ARK(K11) + SBox → MC_3 (pos 3→4)
    bl      ark_sbox_256
    bl      mc_3

    // Round 13: ARK(K12) + SBox → MC_4 (pos 4→5)
    bl      ark_sbox_256
    bl      mc_4

    // Round 14 (final): ARK(K13) + SBox → resync (remap merged)
    bl      ark_sbox_256
    bl      resync_256

    // ---- Final ARK (K14, NOT-absorbed) ----
    ldr     r0, [sp, #48]           // rkey ptr now at K14
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
    ldr     r0, [sp, #64]           // load ct pointer (saved r2)
    rev     r4, r4                  // byte-reverse back to big-endian
    rev     r5, r5
    rev     r6, r6
    rev     r7, r7
    rev     r8, r8
    rev     r9, r9
    rev     r10, r10
    rev     r11, r11
    stm     r0, {r4-r11}           // store 32 bytes of ciphertext

    add.w   sp, #56                 // free local variables
    pop     {r0-r12, r14}           // restore registers
    bx      lr

/******************************************************************************
* APPLIED OPTIMIZATIONS (v3 vs v1):
*
* 1. [DONE] remap_sbox merged into MC: sbox_to_canonical (4 mov) inlined at
*    the start of each mc_X. Saves bl/bx overhead (2 instr/round × 14 = 28).
*
* 2. [DONE] NOT absorption: 4 NOTs moved from remap into key schedule
*    (K1..K14 planes 1,2,6,7 XORed with 0xFFFFFFFF). mvn → mov in remap,
*    saves 2 instr/round × 14 = 28.
*
* 3. [DONE] Final round inlined: resync_256 still called via bl (includes
*    sbox_to_canonical), but no separate remap call. Net savings: 6 instr.
*
* Combined: ~58 instructions saved over 14 rounds.
*
* FURTHER OPTIMIZATION IDEAS:
*
* 4. MC structure: AES mc_0 uses BYTE_ROR_6+byteror; mc_1 uses BYTE_ROR_4.
*    For Rijndael-256, non-uniform SR gap (1,2,1,4) prevents BYTE_ROR.
*    Per-byte rotation (byte_rol, 4 instr/byte) is the minimum cost.
*
* 5. Merge S-box output → MC more aggressively: restructure MC to operate
*    on shuffled registers directly (avoiding even the 4 mov). Complex and
*    would save only 4 instructions/round due to register conflicts.
******************************************************************************/
