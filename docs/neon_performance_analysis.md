# NEON 4PT vs IL 4PT Performance Analysis

## Overview

Benchmarks show that **NEON 4PT is about 11% faster than NEON IL 4PT**:

| Implementation | Time (ms) | Throughput (MB/s) | Relative |
|-----|-----------|---------------|-----------|
| NEON 4PT | 70.68 | 452.77 | 1.00x |
| NEON IL 4PT | 79.20 | 404.06 | 0.89x |

This document analyzes the cause of this difference using per-instruction cycle
information for the Apple Silicon Firestorm core.

---

## 1. Apple Firestorm SIMD Instruction Timing

Instruction timings compiled from [Dougall Johnson's Apple CPU analysis](https://dougallj.github.io/applecpu/firestorm-simd.html) and [insn_bench_aarch64](https://github.com/ocxtal/insn_bench_aarch64/blob/master/results/apple_m1_firestorm.md).

### 1.1 Firestorm SIMD Execution Units

```
┌──────────────────────────────────────────────────────┐
│              Firestorm SIMD/FP Pipeline              │
├──────────────────────────────────────────────────────┤
│  4 SIMD units: V0, V1, V2, V3 (= u11, u12, u13, u14) │
│  - Most SIMD ops: 4/cycle throughput                 │
│  - Latency: 2 cycles typical, 3+ for complex ops     │
└──────────────────────────────────────────────────────┘
```

### 1.2 Per-Instruction Timing Table

| Instruction | Latency | Throughput | Uops | Unit | Notes |
|--------|---------|------------|------|------|------|
| **EOR.16b** | 2 | 0.25 (4/cyc) | 1 | V0-V3 | XOR |
| **AND.16b** | 2 | 0.25 (4/cyc) | 1 | V0-V3 | AND |
| **ORR.16b** | 2 | 0.25 (4/cyc) | 1 | V0-V3 | OR (MOV alias) |
| **BIT.16b** | 2 | 0.25 (4/cyc) | 1 | V0-V3 | Bitwise Insert |
| **BIF.16b** | 2 | 0.25 (4/cyc) | 1 | V0-V3 | Bitwise Insert False |
| **MOV.16b** | 2 | 0.25 (4/cyc) | 1 | V0-V3 | ORR alias |
| **DUP.4s** | 2 | 0.25 (4/cyc) | 1 | V0-V3 | Broadcast |
| **SUB.16b** | 2 | 0.25 (4/cyc) | 1 | V0-V3 | Subtract |
| **SHL.16b** | 2 | 0.25 (4/cyc) | 1 | V0-V3 | Shift |
| **SSHR.16b** | 2 | 0.25 (4/cyc) | 1 | V0-V3 | Arithmetic shift |
| **TBL.16b** | 2-3 | 0.25 (4/cyc) | 1 | V0-V3 | Table lookup |
| **TBX.16b** | 2-3 | 0.25 (4/cyc) | 1 | V0-V3 | Table lookup (extend) |
| **TRN1/TRN2** | 2 | 0.25 (4/cyc) | 1 | V0-V3 | Transpose |
| **LD1.16b** | 5 | 0.33 (3/cyc) | 1 | Load | Vector load |
| **ST1.16b** | 5 | 0.50 (2/cyc) | 1 | Store | Vector store |

> **Note:** Throughput 0.25 means 0.25 cycles per instruction, i.e. 4 instructions can be issued per cycle.

---

## 2. Data Layout Comparison

### 2.1 NEON 4PT (Row-major Block Layout)

```
Register allocation:
┌────────┬─────────────────────────────────────┐
│ v0, v1 │ Block 0: [L: cols 0-3] [R: cols 4-7] │
│ v2, v3 │ Block 1: [L: cols 0-3] [R: cols 4-7] │
│ v4, v5 │ Block 2: [L: cols 0-3] [R: cols 4-7] │
│ v6, v7 │ Block 3: [L: cols 0-3] [R: cols 4-7] │
└────────┴─────────────────────────────────────┘

Inside each 128-bit register:
[col0: r0,r1,r2,r3 | col1: r0,r1,r2,r3 | col2: r0,r1,r2,r3 | col3: r0,r1,r2,r3]
```

### 2.2 NEON IL 4PT (Column-interleaved Layout)

```
Register allocation:
┌────┬──────────────────────────────────────────────────┐
│ v0 │ [A_col0 | B_col0 | C_col0 | D_col0]  col0 of 4 blks │
│ v1 │ [A_col1 | B_col1 | C_col1 | D_col1]  col1 of 4 blks │
│ v2 │ [A_col2 | B_col2 | C_col2 | D_col2]  col2 of 4 blks │
│ v3 │ [A_col3 | B_col3 | C_col3 | D_col3]  col3 of 4 blks │
│ v4 │ [A_col4 | B_col4 | C_col4 | D_col4]  col4 of 4 blks │
│ v5 │ [A_col5 | B_col5 | C_col5 | D_col5]  col5 of 4 blks │
│ v6 │ [A_col6 | B_col6 | C_col6 | D_col6]  col6 of 4 blks │
│ v7 │ [A_col7 | B_col7 | C_col7 | D_col7]  col7 of 4 blks │
└────┴──────────────────────────────────────────────────┘
```

---

## 3. Per-Operation Instruction Count

### 3.1 SubBytes (identical)

Both implementations use TBL/TBX for the S-box lookup, with identical instruction counts.

```assembly
// sbox_lookup macro (applied to 8 registers)
sub.16b  v28, reg, v12      // 1 SUB
tbl.16b  reg, {v8-v11}, reg // 1 TBL
sub.16b  v29, v28, v12      // 1 SUB
tbx.16b  reg, {v16-v19}, v28 // 1 TBX
sub.16b  v28, v29, v12      // 1 SUB
tbx.16b  reg, {v20-v23}, v29 // 1 TBX
tbx.16b  reg, {v24-v27}, v28 // 1 TBX
// total: 7 instructions/register
```

**SubBytes total instructions:**
- S-box load: 3 × LD1.16b = 3
- 8 registers: 8 × 7 = 56
- **total: 59 instructions** (identical)

### 3.2 ShiftRows (key difference)

#### NEON 4PT: TBL-based (16 instructions)

```assembly
// shiftrows_block macro (4 blocks × 4 instructions = 16)
mov.16b v30, regL           // 1 MOV
mov.16b v31, regR           // 1 MOV
tbl.16b regL, {v30,v31}, v13 // 1 TBL (2-reg source)
tbl.16b regR, {v30,v31}, v14 // 1 TBL (2-reg source)
```

**Analysis:**
- 4 blocks × 4 instructions = **16 instructions**
- TBL selects arbitrary bytes from 2 source registers
- Dependency: MOV → TBL (serial)

#### NEON IL 4PT: BIT-based (41 instructions)

```assembly
// shiftrows_il macro
ld1.16b {v24,v25,v26}, [x7]  // 1 LD1 (row masks)

// Phase 1: copy row0 (8 MOV)
mov.16b v16, v0              // out0 = v0
mov.16b v17, v1              // out1 = v1
...                          // 8 total

// Phase 2: insert row1 (8 BIT)
bit.16b v16, v1, v24         // out0.row1 = v1.row1
bit.16b v17, v2, v24         // out1.row1 = v2.row1
...                          // 8 total

// Phase 3: insert row2 (8 BIT)
bit.16b v16, v3, v25         // out0.row2 = v3.row2
...                          // 8 total

// Phase 4: insert row3 (8 BIT)
bit.16b v16, v4, v26         // out0.row3 = v4.row3
...                          // 8 total

// Phase 5: copy result (8 MOV)
mov.16b v0, v16
...                          // 8 total
```

**Analysis:**
- 1 LD1 + 8 MOV + 24 BIT + 8 MOV = **41 instructions**
- Dependency chain: Phase 1 → Phase 2 → Phase 3 → Phase 4 → Phase 5 (serial)

#### ShiftRows difference summary

| Metric | NEON 4PT | NEON IL 4PT | Diff |
|------|----------|-------------|------|
| Instruction count | 16 | 41 | **+25 (+156%)** |
| Core op | TBL | BIT | - |
| Dependency depth | 2 stages | 5 stages | +3 stages |

### 3.3 MixColumns (identical)

```assembly
// mixcolumn macro (applied to 8 registers)
tbl.16b v28, {reg}, v13     // 1 TBL (rot1)
eor.16b v29, reg, v28       // 1 EOR
tbl.16b v30, {v29}, v14     // 1 TBL (rot2)
eor.16b v31, v29, v30       // 1 EOR
sshr.16b v30, v29, #7       // 1 SSHR
shl.16b v29, v29, #1        // 1 SHL
and.16b v30, v30, v15       // 1 AND
eor.16b v29, v29, v30       // 1 EOR (xtime)
eor.16b reg, reg, v31       // 1 EOR
eor.16b reg, reg, v29       // 1 EOR
// total: 10 instructions/register (11 incl. v15 load)
```

**MixColumns total instructions:**
- 8 registers × 10 = **80 instructions** (identical)

### 3.4 AddRoundKey (differs)

#### NEON 4PT: direct XOR (9 instructions)

```assembly
ld1.16b {v28, v29}, [rk_ptr], #32  // 1 LD1

eor.16b v0, v0, v28          // 8 EOR
eor.16b v1, v1, v29
eor.16b v2, v2, v28
...
```

#### NEON IL 4PT: broadcast then XOR (17 instructions)

```assembly
ld1.16b {v28, v29}, [rk_ptr], #32  // 1 LD1

dup v30.4s, v28.s[0]         // 8 DUP (broadcast)
eor.16b v0, v0, v30          // 8 EOR
dup v30.4s, v28.s[1]
eor.16b v1, v1, v30
...
```

#### AddRoundKey difference summary

| Metric | NEON 4PT | NEON IL 4PT | Diff |
|------|----------|-------------|------|
| Instruction count | 9 | 17 | **+8 (+89%)** |
| DUP needed | No | Yes | - |

### 3.5 Layout-conversion overhead (IL 4PT only)

IL 4PT must convert the input to the interleaved layout and restore the output to the original layout.

#### convert_to_interleaved (~26 instructions)

```assembly
// transpose L halves
trn1.4s v0, v16, v18         // 4 TRN1
trn2.4s v2, v16, v18         // 4 TRN2
...
trn1.2d v16, v0, v28         // 4 TRN1
trn2.2d v18, v0, v28         // 4 TRN2
...
mov.16b v0, v16              // 8 MOV
...
```

#### convert_from_interleaved (~24 instructions)

Inverse transform of the same structure.

**Layout conversion total: ~50 instructions**

---

## 4. Total Instruction Count

### 4.1 Instructions per round

| Operation | NEON 4PT | NEON IL 4PT | Diff |
|------|----------|-------------|------|
| SubBytes | 59 | 59 | 0 |
| ShiftRows | 16 | 41 | +25 |
| MixColumns | 80 | 80 | 0 |
| AddRoundKey | 9 | 17 | +8 |
| **Round total** | **164** | **197** | **+33 (+20%)** |

### 4.2 Full encryption (14 rounds)

| Item | NEON 4PT | NEON IL 4PT | Diff |
|------|----------|-------------|------|
| Layout conversion | 0 | 50 | +50 |
| Initial AddRoundKey | 9 | 17 | +8 |
| Rounds 1-13 | 164 × 13 = 2,132 | 197 × 13 = 2,561 | +429 |
| Last round | 84 | 117 | +33 |
| I/O (load/store) | 12 | 12 | 0 |
| **Total instructions** | **~2,237** | **~2,757** | **+520 (+23%)** |

---

## 5. Cycle Analysis

### 5.1 Theoretical throughput

Firestorm executes most SIMD instructions at **4/cycle** throughput.

```
NEON 4PT:  2,237 instructions ÷ 4 = ~559 cycles/4 blocks
NEON IL:   2,757 instructions ÷ 4 = ~689 cycles/4 blocks

Theoretical difference: 689 / 559 = 1.23x (IL is 23% slower)
```

### 5.2 Actual benchmark results

```
NEON 4PT:  70.68 ms / (1,048,576/4) = 270 ns / 4 blocks
NEON IL:   79.20 ms / (1,048,576/4) = 302 ns / 4 blocks

Actual difference: 302 / 270 = 1.12x (IL is 12% slower)
```

### 5.3 Theory vs. actual

The gap between the theoretical prediction (23%) and the actual result (12%) comes from:

1. **Instruction-level parallelism (ILP):** Firestorm's deep pipeline and large reorder buffer (~600 entries) hide some dependencies.
2. **Memory latency:** cache misses and memory accesses relatively shrink the compute difference.
3. **Branch prediction:** loop prediction works well, so both implementations stay efficient.

---

## 6. Key Performance Bottlenecks

### 6.1 ShiftRows dependency chain

#### NEON 4PT ShiftRows

```
Cycle 0: MOV v30, v0  |  MOV v31, v1
         ↓ (2 cycles latency)
Cycle 2: TBL v0, {v30,v31}, mask  |  TBL v1, {v30,v31}, mask

Total latency: 4 cycles (2 + 2)
```

#### NEON IL 4PT ShiftRows

```
Cycle 0:  LD1 {v24,v25,v26}  (row masks)
          ↓ (5 cycles latency)
Cycle 5:  MOV v16, v0 (8×)
          ↓ (2 cycles latency)
Cycle 7:  BIT v16, v1, v24 (Phase 2, 8×)
          ↓ (2 cycles latency)
Cycle 9:  BIT v16, v3, v25 (Phase 3, 8×)
          ↓ (2 cycles latency)
Cycle 11: BIT v16, v4, v26 (Phase 4, 8×)
          ↓ (2 cycles latency)
Cycle 13: MOV v0, v16 (8×)

Total latency: ~15 cycles
```

**ShiftRows latency difference: ~11 cycles/round**

### 6.2 AddRoundKey DUP overhead

IL 4PT must broadcast the round key to each column:

```assembly
dup v30.4s, v28.s[0]   // 2 cycles latency
eor.16b v0, v0, v30    // 2 cycles, but depends on DUP
```

4PT simply does:
```assembly
eor.16b v0, v0, v28    // 2 cycles, no dependency
```

**AddRoundKey extra latency: ~8 cycles/round** (dependency of 8 DUPs)

---

## 7. Conclusions

### 7.1 Why is NEON 4PT faster?

| Factor | NEON 4PT advantage |
|------|---------------|
| **ShiftRows** | TBL shuffles directly from a 2-reg source (minimal dependencies) |
| **AddRoundKey** | No broadcast needed (same key XORed directly into 4 blocks) |
| **Layout** | No input/output conversion overhead |
| **Dependency chain** | Shorter critical path |

### 7.2 IL 4PT's theoretical advantage (unrealized)

Original intent of the IL 4PT design:
- **True SIMD parallelism:** process the same position of 4 blocks simultaneously
- **Better vectorization:** operating per column increases SIMD efficiency

**Why it was not realized:**
1. SubBytes and MixColumns already have the same parallelism in both implementations.
2. The BIT instruction chain in ShiftRows is less efficient than TBL.
3. Layout-conversion overhead cancels the benefit.

### 7.3 Recommendations

| Use case | Recommended |
|----------|----------|
| Maximum performance | ARM Crypto Extension |
| No Crypto Extension | NEON 4PT |
| Research/teaching | NEON IL 4PT (data-layout study) |

---

## 8. References

- [Dougall Johnson - Firestorm SIMD Instructions](https://dougallj.github.io/applecpu/firestorm-simd.html)
- [insn_bench_aarch64 - Apple M1 Firestorm Results](https://github.com/ocxtal/insn_bench_aarch64/blob/master/results/apple_m1_firestorm.md)
- [Apple M1 Optimization Notes](https://github.com/ocxtal/insn_bench_aarch64/blob/master/optimization_notes_apple_m1.md)
- [Daniel Lemire - ARM NEON TBL Performance](https://lemire.me/blog/2019/07/23/arbitrary-byte-to-byte-maps-using-arm-neon/)
