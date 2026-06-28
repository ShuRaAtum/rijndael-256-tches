# Rijndael-256 Benchmark Results

Measured performance data for paper tables. All results are reproducible via `make run` in each board_test directory.

Raw benchmark data: `docs/results/` (CSV files + environment info, committed for reproducibility).

---

## Cortex-M4 (STM32F407, 168 MHz)

Measured: 2026-03-17
Toolchain: arm-none-eabi-gcc 13.2.1, -O3
Method: DWT cycle counter, average of 16 runs per measurement

### Encrypt Cycles

| Implementation | 128-bit | 192-bit | 256-bit | c/B | Constant-time |
|----------------|--------:|--------:|--------:|----:|:-------------:|
| T-table ASM    |   3,175 |   3,172 |   3,174 |  99 | No            |
| T-table C      |   3,785 |   3,785 |   3,785 | 118 | No            |
| Bitslice ASM   |   4,962 |   4,962 |   4,962 | 155 | Yes           |
| Fixslice ASM   |   5,481 |   5,481 |   5,481 | 171 | Yes           |
| Native C       |  12,373 |  12,374 |  12,374 | 387 | No            |

> Nr = 14 for all key sizes (Nr = max(Nk, Nb) + 6, Nb = 8), so encrypt cycles are identical across key sizes. Only key schedule cost varies.

### Decrypt Cycles (Bitslice only)

| Key size | Decrypt cycles | c/B | KS (decrypt) |
|----------|---------------:|----:|-------------:|
| 128-bit  |          6,060 | 189 |       20,877 |
| 192-bit  |          6,060 | 189 |       20,721 |
| 256-bit  |          6,060 | 189 |       20,915 |

> Other implementations: fixslice has no decrypt (intentional — negative result). T-table ASM has no decrypt. Native C and T-table C have decrypt implementations but are not benchmarked on-board (host-verified only).

### Key Schedule Cycles

| Implementation | 128-bit | 192-bit | 256-bit |
|----------------|--------:|--------:|--------:|
| T-table ASM    |   3,101 |   2,962 |   3,525 |
| T-table C      |   3,102 |   2,967 |   3,525 |
| Native C       |   3,102 |   2,967 |   3,525 |
| Bitslice (enc) |   5,726 |   5,590 |   5,931 |
| Bitslice (dec) |  20,877 |  20,721 |  20,915 |
| Fixslice       |  10,229 |  10,089 |  10,299 |

> Bitslice/fixslice key schedules are more expensive due to bitplane packing (SWAPMOVE) and, for decrypt, InvMixColumns transformation.

### ROM / Stack (paper convention)

The paper reports the encryption path only: encryption routine, encryption key
schedule, and lookup tables needed for encryption. Decryption routines, inverse
tables, and decrypt-key-schedule helpers are excluded from the ROM column. Stack
is the call-chain peak across encryption and the encryption key schedule.

| Implementation | ROM (B) | Stack (B) |
|----------------|--------:|----------:|
| Native C       |   3,216 |       240 |
| T-table C      |   5,972 |       136 |
| T-table ASM    |   2,880 |        76 |
| Bitslice ASM   |   3,352 |       576 |
| Fixslice ASM   |   8,924 |       696 |

The full-object legacy breakdown, including decrypt code and inverse tables, is
kept in `docs/results/cortexm4_rom_stack_2026-04-14.txt` for audit purposes only;
it is not the convention used in the paper table.

### Correctness

All implementations: **ALL PASS** for 128/192/256-bit keys.

```
Bitslice:   encrypt 3/3 PASS, decrypt 3/3 PASS
Fixslice:   encrypt 3/3 PASS
Native C:   encrypt 3/3 PASS
T-table C:  encrypt 3/3 PASS
T-table ASM: encrypt 3/3 PASS
```

### Bitslice Host Verification (x86)

Decrypt-only verification (encrypt is ARM ASM, not runnable on x86):

```
tv1 (128-bit, all-zeros):    PASS
tv2 (192-bit, all-zeros):    PASS
tv3 (256-bit, all-zeros):    PASS
tv4 (128-bit, incrementing): PASS
4/4 PASS
```

---

## AArch64

### Apple M2

Measured: 2026-03-18
Device: Apple M2 (Firestorm P-core, 3.49 GHz, ARMv8-A)
Toolchain: Apple clang 17.0.0, -O3 -march=armv8-a+crypto
Method: clock_gettime CLOCK_MONOTONIC, 32 MB (1M blocks), 10 iterations avg
ARM Crypto Extension: **Available**
Raw data: `docs/results/apple_m2_2026-03-18.csv`

This subsection is the historical EOR/NEON baseline from the original
measurement campaign. The folded ARM-Crypto path promoted in the revised paper
is reported in the 2026-06-18 subsection below.

#### Encrypt Throughput (all key sizes identical — Nr=14)

| Implementation          | 128-bit      | 192-bit      | 256-bit      | Speedup vs Ref |
|-------------------------|-------------:|-------------:|-------------:|---------------:|
| ARM Crypto (AESE/AESD)  | 2,055 MB/s   | 2,069 MB/s   | 2,145 MB/s   |        16.1x   |
| NEON 4PT                |   461 MB/s   |   424 MB/s   |   480 MB/s   |         3.6x   |
| T-table C               |   432 MB/s   |   428 MB/s   |   437 MB/s   |         3.3x   |
| NEON IL 4PT             |   412 MB/s   |   399 MB/s   |   429 MB/s   |         3.2x   |
| Reference C             |   131 MB/s   |   129 MB/s   |   133 MB/s   |         1.0x   |
| NEON Single             |   115 MB/s   |   114 MB/s   |   120 MB/s   |         0.9x   |

#### Decrypt Throughput (all key sizes identical — Nr=14)

| Implementation          | 128-bit      | 192-bit      | 256-bit      | Speedup vs Ref |
|-------------------------|-------------:|-------------:|-------------:|---------------:|
| ARM Crypto (AESD)       | 1,958 MB/s   | 1,906 MB/s   | 1,988 MB/s   |        18.2x   |
| T-table C               |   218 MB/s   |   154 MB/s*  |   222 MB/s   |         2.0x   |
| Reference C             |   105 MB/s   |    91 MB/s*  |   109 MB/s   |         1.0x   |
| NEON Single/4PT/IL      |     N/A      |     N/A      |     N/A      |          N/A   |

> \*192-bit decrypt showed variance due to system interference during measurement. Since Nr=14 for all key sizes, 256-bit results are representative. ARM Crypto achieves ~2 GB/s encrypt throughput via AESE/AESD with TBL pre-shuffle to emulate Rijndael-256 ShiftRows. NEON 4PT outperforms T-table by 1.10x on M2 (contrast with RPi4 where T-table wins by 2.07x), because Firestorm's wide SIMD pipeline (4 units, 4 ops/cycle) amortizes the TBL-based S-box cost. NEON IL 4PT is 12% slower than NEON 4PT due to ShiftRows BIT-chain overhead (+25 instructions/round) and AddRoundKey DUP broadcast cost.

#### Correctness

```
Reference:   encrypt 3/3 PASS
T-table:     encrypt 3/3 PASS
ARM Crypto:  encrypt 3/3 PASS
NEON Single: encrypt 3/3 PASS
NEON 4PT:    encrypt 3/3 PASS
NEON IL 4PT: encrypt 3/3 PASS
Cross-impl consistency: ALL MATCH
```

#### Folded path + ARM AES-128/256 HW baselines + EOR (same-run, 2026-06-18)

Measured: 2026-06-18 (same M2; Apple clang 17.0.0, -O3 -march=armv8-a+crypto; best-of-10)
Raw data: `docs/results/apple_m2_2026-06-18.csv` (+ `_run.txt`, `_env.txt`, `apple_m2_throughput_2026-06-18.csv`)

The AddRoundKey-**folded** ARM-Crypto R256 (pre-shuffled round keys; AddRoundKey folded into
AESE) is measured in the **same binary** as round-matched **AES-256 (14R)** and **AES-128 (10R)**
hardware baselines, so the AES→R256 per-byte slowdown is internally consistent (same method, same
silicon). The shipped **EOR** path is the reference point that folded replaces.

| Path (best-of-10) | single | x2 | x4 | x8 |
|-------------------|-------:|-------:|-------:|-------:|
| AES-128 (10R)     | 10,335.9 | 12,945.0 | 15,252.6 | 17,057.6 |
| AES-256 (14R)     |  7,710.8 |  9,439.5 | 11,721.6 | 12,820.5 |
| **R256 folded**   |  4,196.7 |  5,708.2 | **6,520.0** |  2,516.7 |
| R256 EOR          |  2,193.9 |   —    |   —    |   —    |

MB/s. Best interleave **N=4**; x8 folded collapses (8×2 = 16 live NEON state regs + round keys
spill). Folded is **~1.9× faster than EOR**, so folded is the promoted path.

**AES → R256 per-byte slowdown (folded):**

| Regime | vs AES-256 | vs AES-128 |
|--------|-----------:|-----------:|
| single-block | 1.84x | 2.46x |
| interleaved **N=4** (regime-matched to x86 VAES) | **1.80x** | 2.34x |

> Resolves the §B "1.9×/2.5× vs 1.7×/2.2×" gap: the final same-run best-of-10
> single-block values are **1.84×/2.46×**; **regime-matched interleaved N=4 =
> 1.80×/2.34×** — the cross-platform value, giving the
> monotone story **x86 1.09× < M2 1.80× < A76 2.4×**. KAT: NIST R256 (`make test`), AES FIPS-197,
> and folded (single + 1000-block sweep + x2/x4/x8) all **PASS**.

#### FEAT_DIT (Data-Independent Timing) overhead (2026-06-18)

`hw.optional.arm.FEAT_DIT = 1` on this M2. A/B of the folded encrypt loop with `PSTATE.DIT`
toggled at EL0 (`msr DIT, #0/#1`, read-back confirmed), best-of-50, single + x4:

| Regime | DIT-off | DIT-on | Overhead |
|--------|--------:|-------:|---------:|
| single | 4,179 MB/s | 4,180 MB/s | −0.04% |
| x4     | 6,532 MB/s | 6,536 MB/s | −0.06% |

> **No measurable overhead** (|Δ| ≤ 0.1%, within noise — DIT-on was marginally faster). Expected:
> AESE/AESMC are already data-independent on Apple Silicon, so enabling DIT adds no cost to the AES
> path. This measured result supports/tightens the paper's "≤0.3%" claim. Harness
> `aarch64/bench_dit.c` (`make bench_dit`); raw data `docs/results/apple_m2_dit_2026-06-18.{csv,_env.txt}`.

### Raspberry Pi 5 / Cortex-A76

Measured: 2026-06-19 (Cortex-A76, ARMv8.2-A; gcc 13.3.0, -O3 -march=armv8.2-a+crypto; best-of-10; **active fan**)
Raw data: `docs/results/rpi5_a76_2026-06-19.csv` (+ `_run.txt`, `_env.txt`, `rpi5_a76_throughput_2026-06-19.csv`)

First **non-Apple** Crypto-Extension core for the folded path — confirms the AArch64 findings
generalise off Apple Silicon. Same binary/config as the M2 run (round-matched AES-256 (14R) / AES-128
(10R) HW baselines + folded R256 + EOR), so the AES→R256 per-byte slowdown is internally consistent.

| Path (best-of-10) | single | x2 | x4 | x8 |
|-------------------|-------:|-------:|-------:|-------:|
| AES-128 (10R)     | 2,591 | 3,441 | 2,537 | 2,714 |
| AES-256 (14R)     | 1,937 | 2,436 | 1,932 | 2,097 |
| **R256 folded**   |   608 | **1,014** |   989 |   990 |
| R256 EOR          |   509 |   —    |   —    |   —    |

MB/s. Best interleave **N=2** (x4/x8 do not beat x2 — a shallower sweet-spot than M2's N=4,
consistent with the narrower A76 NEON issue width). Folded x2 ≈ **1.99× the EOR single**.

**AES → R256 per-byte slowdown (folded):**

| Regime | vs AES-256 | vs AES-128 |
|--------|-----------:|-----------:|
| single-block | 3.18x | 4.26x |
| interleaved **N=2** (regime-matched to x86 VAES) | **2.40x** | 3.39x |

> Completes the monotone cross-platform story **x86 1.09× < M2 1.80× < A76 2.40×** (NEON width:
> A76 = 2 `TBL` on shared NEON pipes; x86 = 1 `VPERMB` on a separate port overlapping AES). KAT: NIST
> R256 (`make -f Makefile.rpi5 test`), AES FIPS-197, and folded (single + 1000-block sweep + x2/x4/x8)
> all **PASS**. Needs **active cooling**: a fanless A76 throttles above 85 °C (firmware-level, invisible
> to Linux `scaling_cur_freq`) and corrupts the comparison — see `_env.txt`.

#### FEAT_DIT — N/A on Cortex-A76

Cortex-A76 is **ARMv8.2-A** and does **not implement FEAT_DIT** (no `dit` HWCAP; FEAT_DIT is an
ARMv8.4 feature). DIT overhead is therefore **not applicable** on the A76 (nor the A72); the M2
measurement (FEAT_DIT=1, ~0% overhead) stands as the datapoint for DIT-capable cores.

### Raspberry Pi 4 / Cortex-A72

Measured: 2026-03-18
Device: Raspberry Pi 4 Model B (Cortex-A72, ARMv8-A, 1.8 GHz)
Toolchain: gcc (Debian 14.2.0), -O3 -march=armv8-a
Method: clock_gettime CLOCK_MONOTONIC, 32 MB (1M blocks), 10 iterations avg
ARM Crypto Extension: **Not available** (no AES/SHA in CPU features)

#### Encrypt Throughput (all key sizes identical — Nr=14)

| Implementation          | 128-bit     | 192-bit     | 256-bit     | Speedup |
|-------------------------|------------:|------------:|------------:|--------:|
| T-table C               | 53.33 MB/s  | 53.80 MB/s  | 53.83 MB/s  |  2.52x  |
| NEON 4PT                | 25.79 MB/s  | 26.03 MB/s  | 26.05 MB/s  |  1.22x  |
| NEON IL 4PT             | 25.04 MB/s  | 25.14 MB/s  | 25.24 MB/s  |  1.18x  |
| Reference C             | 21.15 MB/s  | 21.27 MB/s  | 21.35 MB/s  |  1.00x  |
| NEON Single             |  6.43 MB/s  |  6.48 MB/s  |  6.49 MB/s  |  0.30x  |
| ARM Crypto              |     N/A     |     N/A     |     N/A     |   N/A   |

#### Decrypt Throughput (all key sizes identical — Nr=14)

| Implementation          | 128-bit     | 192-bit     | 256-bit     | Speedup vs Ref |
|-------------------------|------------:|------------:|------------:|---------------:|
| T-table C               | 30.08 MB/s  | 30.38 MB/s  | 30.40 MB/s  |         1.65x  |
| Reference C             | 18.27 MB/s  | 18.41 MB/s  | 18.41 MB/s  |         1.00x  |
| NEON Single/4PT/IL      |     N/A     |     N/A     |     N/A     |          N/A   |

> T-table is the clear winner on RPi4 (2.52x encrypt, 1.65x decrypt vs reference). NEON 4PT underperforms T-table (0.48x) due to software S-box via TBL/TBX being memory-bound on Cortex-A72's smaller caches. NEON IL 4PT is 3% slower than NEON 4PT — the transpose overhead outweighs any SIMD benefit. NEON Single is slower than Reference because it duplicates 1 block to 4 blocks and calls 4PT.

#### Correctness

```
Reference:   encrypt 3/3 PASS
T-table:     encrypt 3/3 PASS
NEON Single: encrypt 3/3 PASS
NEON 4PT:    encrypt 3/3 PASS
NEON IL 4PT: encrypt 3/3 PASS
ARM Crypto:  SKIPPED (not available)
Cross-impl consistency: ALL MATCH
```

## x86-64 (AES-NI / VAES-512)

### Intel Core i7-1165G7 (Tiger Lake)

Measured: 2026-06-18
Device: 11th Gen Intel Core i7-1165G7 @ 2.80 GHz (Tiger Lake, 4C/8T, turbo 4.70 GHz)
Toolchain: gcc 13.3.0, `-O3 -march=native -mavx512f -mavx512bw -mavx512vbmi -mvaes -mvpclmulqdq`
ISA: avx512f, avx512bw, avx512vbmi, avx512vl, avx512dq, **vaes**, **vpclmulqdq**
Method: L1-resident (32 KiB) peak interleaved throughput, best-of-30, 3 trials; GB/s via CLOCK_MONOTONIC, cyc/byte via RDTSC (nominal 2.80 GHz)
Raw data: `docs/results/x86_i7-1165g7_2026-06-18.csv`

#### Encrypt Throughput / cycles-per-byte (best of 3 trials, Nr=14 for R256)

| Implementation             | GB/s   | cyc/byte | Notes                                  |
|----------------------------|-------:|---------:|----------------------------------------|
| AES-128 VAES512 (10R)      | 14.91  |   0.188  | vector AES-NI baseline                 |
| AES-256 VAES512 (14R)      | 11.98  |   0.234  | round-matched baseline                 |
| **R256 VAES512 (14R)**     | **10.98** | **0.255** | **this work** (512-bit VAES)        |
| R256 AES-NI scalar x4 (14R)|  3.60  |   0.778  | prior scalar 128-bit path, same CPU    |

#### Key comparisons

| Comparison                              | Result        |
|-----------------------------------------|---------------|
| R256 VAES512 vs AES-256 (round-matched) | **1.09x** slowdown/byte |
| R256 VAES512 vs scalar AES-NI 4-way     | **~3.0x** faster (0.255 vs 0.778 cyc/byte, same silicon) |
| R256 VAES512 vs [DG22] report (~0.27 cpb)| comparable on different silicon |

> One ZMM packs two 256-bit blocks `{L0,R0,L1,R1}`, so a round is a single
> 64-byte AVX-512 VBMI `VPERMB` pre-shuffle (R256 ShiftRows correction, derived
> from the verified `SRC_L`/`SRC_R` = AArch64 TBL maps) plus one `VAESENC`; an
> 8-ZMM (16-block) interleave hides VAESENC latency. The per-byte VAESENC count
> is identical to round-matched AES-256 — the only extra work is one port-5
> VPERMB per round, which overlaps the port-0 VAESENC, so the ~9% gap is
> essentially this chip's hardware ceiling. cyc/byte is on a nominal-TSC basis
> (same as the repo's other x86 figures); GB/s and the ratios are
> frequency-independent. This is a 15-28 W mobile part (AVX-512 license
> downclock applies); a server part with higher sustained AVX-512 clock or dual
> VAES units would lower the absolute cyc/byte further.

#### Correctness

```
KAT (x86/test/test_kat_vaes.c) vs portable reference:
  key 128 / 192 / 256:        PASS
  1000-block sweep:           PASS
  16-way interleaved path:    PASS  (all blocks bit-identical)
```

---

## CUDA (NVIDIA GeForce RTX 4080)

Measured: 2026-04-09
GPU: NVIDIA GeForce RTX 4080 (76 SMs, Compute Capability 8.9, 16 GiB, 100 KiB shared/SM)
CUDA: nvcc 12.x, `-O3 -arch=sm_89`
Key size: 256-bit representative (Nr = 14 for all key sizes with Nb = 8; the round
function and kernel throughput are identical across 128/192/256-bit keys, only the
key schedule differs and is not included in kernel timing).

Raw per-configuration data (all thread counts, Compact / CF-naive / CF-staggered,
ECB/CTR/ES, encrypt + decrypt) is committed under `results/cuda_rtx4080/`; NCU
profiling is under `../paper/data/ncu/`. These are the numbers used in the paper (§5).

### Kernel-only throughput (256-bit, 128 threads/block, 100 MiB)

| Layout              | ECB (GiB/s) | CTR (GiB/s) |
|---------------------|------------:|------------:|
| Compact (8 KiB)     |       79.93 |      100.57 |
| CF naive (36 KiB)   |       52.84 |       56.10 |
| CF staggered        |   **81.16** |  **103.74** |

End-to-end (incl. malloc + H2D/D2H copies): ~5.1–5.5 GiB/s (PCIe-transfer-bound).

### Why CF staggered wins on the RTX 4080

Naive conflict-free (CF) replication into 36 KiB shared memory incurs 65.5M
store-side bank conflicts, driving SM cycles to 1.59× the Compact layout.
Staggering the replicated-table stores cuts bank conflicts by 99.4% (65.5M →
389k), so despite much lower occupancy (15.6% vs Compact's 86.9%) the
conflict-free main-round lookups make CF staggered the fastest kernel
(81.16 vs 79.93 GiB/s ECB; 103.74 vs 100.57 CTR).

> Supersedes an earlier RTX 3060 Laptop measurement (where the Compact layout
> won because the narrower SM made occupancy the dominant factor). The paper uses
> the RTX 4080 results above.

### Correctness

```
ECB: 66/66 tests PASS (KAT enc/dec 128/192/256, roundtrip, multi-block, V2/V3 consistency)
CTR: 29/29 tests PASS (roundtrip, CPU vs GPU, keystream-only, nonce carry, all key sizes)
ES:  34/34 tests PASS (find known key, not-found, all key sizes, boundary cases)
```

---

## Measurement Status

| Platform | Encrypt | Decrypt | Multi-key | Code size | Status |
|----------|:-------:|:-------:|:---------:|:---------:|--------|
| Cortex-M4 (STM32F407) | 5/5 | 1/5 (bitslice) | 128/192/256 | measured | **Complete** |
| AArch64 Apple M2 | 6/6 | 3/3 (Ref, T-table, ARM Crypto) | 128/192/256 | — | **Complete** |
| AArch64 RPi4 | 4/4 (no ARM Crypto) | 2/2 (Ref, T-table) | 128/192/256 | — | **Complete** |
| x86-64 i7-1165G7 (VAES-512) | R256 + AES-128/256 baselines | — | 128/192/256 KAT (Nr=14 identical) | — | **Complete** |
| CUDA RTX 4080 | ECB/CTR/ES | ECB | 256-bit representative (Nr=14 identical) | — | **Complete** |

---

## Test Environment Summary

| Platform | Device | Clock | Memory | Toolchain |
|----------|--------|------:|-------:|-----------|
| Cortex-M4 | STM32F407VG | 168 MHz | 192 KiB SRAM (chip total; linker maps the 128 KiB main SRAM, 64 KiB CCM excluded), 1 MiB Flash | arm-none-eabi-gcc 13.2.1, -O3 |
| AArch64 | Apple M2 (Firestorm) | 3.49 GHz | 8 GB unified LPDDR5 | Apple clang 17.0.0, -O3 -march=armv8-a+crypto |
| AArch64 | RPi4 (Cortex-A72) | 1.8 GHz | 4 GB LPDDR4 | gcc, -O3 -march=armv8-a |
| x86-64 | Intel i7-1165G7 (Tiger Lake) | 2.80 GHz (turbo 4.70) | 32 GB DDR4 | gcc 13.3.0, -O3 -march=native (AVX-512 + VAES) |
| CUDA | RTX 4080 (AD103) | 2.505 GHz | 16 GiB GDDR6X, 76 SMs | nvcc 12.x, -O3 -arch=sm_89 |

---

## Reproduction

### Cortex-M4

```bash
# Requires: arm-none-eabi-gcc, st-flash, STM32F407 board
cd cortexm4/{bitslice,fixslice,native,ttable,ttable_asm}/board_test
make run        # Flash + read results
make code_size  # Measure implementation code size
make size       # Measure ELF section sizes
```

### AArch64

```bash
# Apple Silicon
cd aarch64 && make benchmark
./rijndael256_benchmark          # Human-readable
./rijndael256_benchmark --csv    # CSV for paper tables

# Raspberry Pi 4
cd aarch64 && make -f Makefile.rpi4 benchmark
```

### x86-64 (AES-NI / VAES-512)

```bash
# Requires AVX-512 + VAES (+ AVX-512 VBMI for the single-op pre-shuffle)
cd x86
make vaes_test        # KAT vs portable reference (key 128/192/256 + sweep + x16)
make vaes_benchmark   # GB/s + cyc/byte: R256 VAES512 vs AES-128/256 baselines
```

### CUDA

```bash
cd cuda && mkdir -p build && cd build && cmake .. && make
./benchmark_ecb
./benchmark_ctr
./benchmark_es
```

---

## Reproducibility notes

Latency per block for the single-block ARM Crypto EOR path can be derived from
throughput: at 2,193.9 MB/s, `32 / 2193.9 × 1e6 ≈ 14.6 ns/block ≈ 51 cycles` at
3.49 GHz. Direct per-block cycle measurement on macOS is restricted (user-space
ARM PMU access is unavailable); a Linux AArch64 host with `perf_event_open`
exposes the counters directly.
