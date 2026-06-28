# Rijndael-256 PQC Signature Algorithm Benchmark Results

**Platform**: Apple M2 (arm64), macOS, clang -O2/-O3
**Timer**: CNTVCT_EL0 (CPU cycle counter) or wall-clock as noted

---

## 1. SDitH (wall-clock seconds, median of 201 iterations)

### cat3_fast (Level 3, 192-bit security)

| Impl | Sign (s) | Verify (s) | Sign Speedup | Verify Speedup |
|------|----------|------------|-------------|---------------|
| **Reference** | 0.2636 | 0.2476 | 1.00x | 1.00x |
| **NEON** | 0.2359 | 0.2205 | 1.12x | 1.12x |
| **ARM Crypto** | 0.2236 | 0.2069 | **1.18x** | **1.20x** |

### cat5_fast (Level 5, 256-bit security)

| Impl | Sign (s) | Verify (s) | Sign Speedup | Verify Speedup |
|------|----------|------------|-------------|---------------|
| **Reference** | 0.4028 | 0.3727 | 1.00x | 1.00x |
| **NEON** | 0.3733 | 0.3474 | 1.08x | 1.07x |
| **ARM Crypto** | 0.3426 | 0.3142 | **1.18x** | **1.19x** |

> In SDitH, Rijndael-256 is only a fraction of the total work, so the overall speedup is ~18%.

---

## 2. Mirath (CPU cycles, CNTVCT_EL0)

### tcith_3a_fast (Level 3, 192-bit security)

| Impl | Keygen | Sign | Verify | Sign Speedup | Verify Speedup |
|------|--------|------|--------|-------------|---------------|
| **Reference** | 2,021 | 46,582,032 | 76,162,784 | 1.00x | 1.00x |
| **NEON** | 1,988 | 1,182,940 | 1,062,624 | 39.4x | 71.7x |
| **ARM Crypto** | 1,985 | 906,790 | 571,653 | **51.4x** | **133.2x** |

### tcith_5a_fast (Level 5, 256-bit security)

| Impl | Keygen | Sign | Verify | Sign Speedup | Verify Speedup |
|------|--------|------|--------|-------------|---------------|
| **Reference** | 3,243 | 65,481,183 | 105,752,534 | 1.00x | 1.00x |
| **NEON** | 3,233 | 2,557,389 | 1,912,192 | 25.6x | 55.3x |
| **ARM Crypto** | 3,234 | 2,148,705 | 1,237,505 | **30.5x** | **85.5x** |

> Mirath relies heavily on Rijndael-256, giving dramatic speedups (sign 30-51x, verify 72-133x).

---

## 3. RYDE (CPU cycles, CNTVCT_EL0)

### ryde3f (Level 3, 192-bit security)

| Impl | Keygen | Sign | Verify | Sign Speedup | Verify Speedup |
|------|--------|------|--------|-------------|---------------|
| **Reference** | 4,435 | 57,459,608 | 56,999,935 | 1.00x | 1.00x |
| **NEON** | 3,624 | 883,760 | 812,983 | 65.0x | 70.1x |
| **ARM Crypto** | 2,594 | 541,176 | 467,798 | **106.2x** | **121.9x** |

### ryde5f (Level 5, 256-bit security)

| Impl | Keygen | Sign | Verify | Sign Speedup | Verify Speedup |
|------|--------|------|--------|-------------|---------------|
| **Reference** | *(est.)* | 72,010,636 | 70,098,943 | 1.00x | 1.00x |
| **NEON** | 4,915 | 1,692,412 | 1,472,767 | 42.5x | 47.6x |
| **ARM Crypto** | 4,984 | 1,272,354 | 1,043,226 | **56.6x** | **67.2x** |

> RYDE relies heavily on Rijndael-256; ARM Crypto gives sign 56-106x, verify 67-122x.
> NEON (measured 2026-06-18, `ryde_neon_2026-06-18.txt`): single-block NEON Rijndael — sign 42-65x, verify 48-70x.
> As with MQOM, the key differs per GGM-tree node, so the 4-block `neon_4pt` path does not apply; single-block NEON is
> ~3.5x slower than ARM Crypto on the Rijndael portion. The NEON column is filled for completeness, but ARM Crypto is the recommended path on Crypto Extension cores.

---

## 4. MQOM (wall-clock ms, 10 iterations)

### cat3_gf256_fast_r3 (Level 3, 192-bit security)

| Impl | Keygen (ms) | Sign (ms) | Verify (ms) | Sign Speedup | Verify Speedup |
|------|------------|-----------|-------------|-------------|---------------|
| **Reference (CT)** | 391.44 | 2,861.00 | 2,823.33 | 1.00x | 1.00x |
| **Table (ref-opt)** | 1.90 | 24.05 | 17.86 | 118.9x | 158.1x |
| **ARM Crypto** | 2.15 | 25.02 | 18.14 | **114.3x** | **155.6x** |

### cat5_gf256_fast_r3 (Level 5, 256-bit security)

| Impl | Keygen (ms) | Sign (ms) | Verify (ms) | Sign Speedup | Verify Speedup |
|------|------------|-----------|-------------|-------------|---------------|
| **Reference (CT)** | 686.84 | 3,990.40 | 3,953.49 | 1.00x | 1.00x |
| **Table (ref-opt)** | 3.32 | 46.69 | 31.19 | 85.4x | 126.8x |
| **ARM Crypto** | 3.75 | 46.92 | 31.49 | **85.0x** | **125.5x** |

> MQOM: Table ≈ ARM Crypto (the x4 multi-key use rules out the shared-key `neon_4pt`; per-call overhead).
> Speedup of 85-158x over the Reference (constant-time).
>
> The MQOM NEON column (multi-key variant) is from `final_benchmark_20260321_150352.txt`:
> Sign **26.94 / 49.52** ms, Verify **21.01 / 35.21** ms (L3 / L5 respectively).
> (The Reference/Table/ARM Crypto rows above are from a separate measurement run.)

---

## 5. FAEST

### faest_256f (Level 5)

| Impl | Time (s) | Speedup |
|------|----------|---------|
| **Reference** | 0.29 | 1.00x |
| **NEON** | 0.29 | 1.00x |
| **ARM Crypto** | 0.29 | 1.00x |

> faest_256f uses AES-256 (16-byte block) as its OWF; Rijndael-256 (32-byte block) is used only in the EM variant
> → no optimization effect. faest_em_256f is the correct benchmark target.

---

## Summary: ARM Crypto Extension speedup over Reference

| Algorithm | Level | Sign Speedup | Verify Speedup | Notes |
|---------|-------|-------------|---------------|------|
| **SDitH** | 3 | 1.18x | 1.20x | low Rijndael-256 share |
| **SDitH** | 5 | 1.18x | 1.19x | |
| **Mirath** | 3 | **51.4x** | **133.2x** | high Rijndael-256 share |
| **Mirath** | 5 | **30.5x** | **85.5x** | |
| **RYDE** | 3 | **106.2x** | **121.9x** | high Rijndael-256 share |
| **RYDE** | 5 | **56.6x** | **67.2x** | |
| **MQOM** | 3 | 114.3x | 155.6x | vs CT ref; similar to Table |
| **MQOM** | 5 | 85.0x | 125.5x | vs CT ref |
| **FAEST** | 5 | 1.00x | 1.00x | not a target (needs EM variant) |

### Key Insights

1. **Algorithms with a high Rijndael-256 share** (Mirath, RYDE, MQOM) see dramatic speedups (30-155x).
2. **SDitH** is dominated by non-Rijndael-256 work, so the speedup is limited to ~18%.
3. **MQOM** ARM Crypto ≈ Table — the x4 multi-key use prevents exploiting hardware-AES parallelism.
4. **FAEST faest_256f** does not use Rijndael-256, so there is no effect.
5. The **constant-time Reference** implementation is extremely slow on Apple Silicon (bitsliced).
