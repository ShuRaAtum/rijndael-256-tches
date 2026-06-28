# Rijndael-256 Optimized Implementations — Artifact

This artifact accompanies the paper *"Adapting AES-Oriented Optimizations to Rijndael-256: Cortex-M4, ARMv8-A, and CUDA"* submitted to TCHES.

It contains optimized constant-time and high-throughput implementations of Rijndael-256 (the 256-bit block variant of the Rijndael cipher family) targeting three platforms:

- **ARM Cortex-M4** (STM32F407) — bitsliced and T-table implementations
- **ARMv8-A / AArch64** (Apple M2, Raspberry Pi 5/A76, Raspberry Pi 4/A72) — ARM Crypto Extension and NEON implementations
- **x86-64** (Intel i7-1165G7) — VAES-512 reproduction for AES-to-R256 slowdown comparison
- **NVIDIA CUDA GPU** (RTX 4080) — shared-memory T-table with bank-conflict optimization

Additionally, end-to-end PQC signature benchmarks (SDitH, Mirath, RYDE, MQOM) are included.

---

## Directory Structure

```
artifact/
├── README.md               # This file
├── common/                  # Shared headers (S-box, T-tables, test vectors)
│   ├── rijndael256.h
│   ├── rijndael256_tables.h
│   └── test_vectors.h
│
├── cortexm4/                # ARM Cortex-M4 implementations (Section 3)
│   ├── bitslice/            # Constant-time bitsliced ASM
│   ├── fixslice/            # Fixsliced ASM (negative result)
│   ├── ttable_asm/          # T-table hand-optimized ASM
│   ├── ttable/              # T-table C
│   ├── native/              # Reference C
│   └── board_setup/         # STM32F407 startup code and linker script
│
├── aarch64/                 # AArch64 implementations (Section 4)
│   ├── platform/apple/      # Apple Silicon: ARM Crypto + NEON ASM
│   ├── platform/linux_aarch64/  # Linux AArch64: ARM Crypto + NEON ASM
│   ├── test/                # Test harness
│   ├── benchmark/           # Throughput benchmark
│   ├── Makefile             # Apple Silicon build
│   ├── Makefile.rpi4        # Raspberry Pi 4 build
│   └── Makefile.rpi5        # Raspberry Pi 5 / Cortex-A76 build
│
├── x86/                     # x86-64 AES-NI / VAES reproduction
│   ├── test/                # Test harness
│   ├── benchmark/           # Throughput benchmark
│   └── results/             # Native x86 measurements
│
├── cuda/                    # CUDA GPU implementations (Section 5)
│   ├── cuda/                # GPU kernel sources (ECB, CTR, ES modes)
│   ├── cpu/                 # CPU-side reference
│   ├── include/             # Headers
│   ├── test/                # Correctness tests
│   ├── benchmark/           # Throughput benchmarks
│   ├── profile/             # Nsight Compute profiling
│   ├── scripts/             # Utility scripts
│   └── CMakeLists.txt       # CMake build (3.18+)
│
├── benchmark_pqc/           # PQC signature integration benchmarks (Section 6)
│   ├── bench_pqc_sign.c     # Benchmark driver
│   ├── INTEGRATION_STATUS.md
│   └── results/             # Raw benchmark logs
│
└── results/                 # Pre-collected benchmark results
    ├── cortexm4_stm32f407/  # Cortex-M4 data
    ├── aarch64_apple_m2/    # AArch64 data
    ├── aarch64_rpi5_a76/    # Cortex-A76 data
    ├── aarch64_rpi4/        # Cortex-A72 data
    ├── x86_i7_1165g7/       # x86 VAES-512 data
    ├── cuda_rtx4080/        # CUDA data + NCU profiling
    └── pqc_apple_m2/        # PQC integration data
```

---

## Prerequisites

### Cortex-M4

| Item | Details |
|------|---------|
| Board | STM32F407VG Discovery (or compatible) |
| Toolchain | `arm-none-eabi-gcc` 13.x+ |
| Flasher | `st-flash` (stlink) |
| Python 3 | For `parse_result.py` (result parsing) |

### AArch64

| Item | Apple Silicon | Raspberry Pi 4 |
|------|-------------|-----------------|
| Hardware | Apple M2 or later | RPi4 Model B (Cortex-A72) |
| OS | macOS | Linux (64-bit) |
| Compiler | `clang` (Xcode) | `gcc` |
| Crypto HW | ARM Crypto Extension | Not available |

### CUDA

| Item | Details |
|------|---------|
| GPU | NVIDIA GPU with Compute Capability >= 8.0 (paper uses RTX 4080, CC 8.9) |
| CUDA Toolkit | >= 11.0 (paper uses 12.0) |
| CMake | >= 3.18 |
| Driver | Compatible with CUDA toolkit version |

To target a different GPU architecture, override at configure time:
```bash
cmake -DCMAKE_CUDA_ARCHITECTURES=86 ..   # e.g., RTX 3060 (Ampere)
```

---

## Build and Run

### Cortex-M4

Each implementation has a `board_test/` subdirectory with its own Makefile.

```bash
# Example: bitslice implementation
cd cortexm4/bitslice/board_test
make                  # Build
make flash            # Flash to STM32F407
make read             # Read cycle counts from SRAM
make run              # Flash + read in one step
```

For host-side test vector verification (no board required):

```bash
# Implementations with verify_host.c
cd cortexm4/ttable
make -f Makefile verify    # Builds and runs host verification
```

The board test prints encrypt/decrypt cycle counts via `parse_result.py`, which reads from the device SRAM.

### AArch64 (Apple Silicon)

```bash
cd aarch64
make test              # Build and run test vectors
make benchmark         # Build and run throughput benchmark
```

### AArch64 (Raspberry Pi 4)

```bash
cd aarch64
make -f Makefile.rpi4 test
make -f Makefile.rpi4 benchmark
```

Cross-compilation from x86:
```bash
make -f Makefile.rpi4 CROSS=aarch64-linux-gnu- test
```

### CUDA

```bash
cd cuda
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)

# Run correctness tests
./test_ecb
./test_ctr
./test_es

# Run benchmarks
./benchmark_ecb
./benchmark_ctr
./benchmark_es

# GPU capability check
./check_gpu
```

---

## Test Vectors

All implementations validate against 4 test vectors defined in `common/test_vectors.h`:

| ID | Key Size | Key | Plaintext | Expected Ciphertext (first 8 bytes) |
|----|----------|-----|-----------|--------------------------------------|
| TV1 | 128-bit | all zeros | all zeros | `A693B288 ...` |
| TV2 | 192-bit | all zeros | all zeros | `F927363E ...` |
| TV3 | 256-bit | all zeros | all zeros | `C6227E77 ...` |
| TV4 | 128-bit | `00 01 02 ... 0F` | `00 01 02 ... 1F` | `21C89C4A ...` |

Block size is always 256 bits (32 bytes). Nr = 14 for all key sizes.

---

## Expected Results

### Cortex-M4 (STM32F407, 168 MHz) — corresponds to the paper's Cortex-M4 performance table

| Implementation | Encrypt (cycles/block) | ROM (bytes) | Stack (bytes) | Constant-Time |
|----------------|----------------------:|------------:|--------------:|:-------------:|
| T-table ASM | 3,174 | 2,880 | 76 | No |
| T-table C | 3,785 | 5,972 | 136 | No |
| Bitslice ASM | 4,962 | 3,352 | 576 | Yes |
| Fixslice ASM | 5,481 | 8,924 | 696 | Yes |
| Reference C | 12,374 | 3,216 | 240 | No |

ROM (encrypt path only: encrypt + key schedule + tables) and Stack (call-chain peak across encrypt and key schedule) were measured per the paper's methodology. Raw per-function breakdown is in `results/cortexm4_stm32f407/rom_stack.txt`, measured with `-ffunction-sections -fdata-sections -fstack-usage` flags (arm-none-eabi-gcc 13.2.1). The `rom_stack.txt` paper-table summary uses the same encrypt-path convention as this table; decrypt-path data is retained there only as a reference breakdown.

### Hardware AES reuse — corresponds to the paper's AArch64/x86 comparison table

| Platform | Method | AES-128 | AES-256 | R256 | Slowdown vs AES-256 |
|----------|--------|--------:|--------:|-----:|--------------------:|
| Apple M2 | ARM Crypto folded, N=4 | 15,252.6 MB/s | 11,721.6 MB/s | **6,520.0 MB/s** | 1.80x |
| Cortex-A76 (RPi5) | ARM Crypto folded, N=2 | 3,441.0 MB/s | 2,435.6 MB/s | **1,014.1 MB/s** | 2.40x |
| Intel i7-1165G7 | VAES-512, 16 blocks | 0.188 cpb | 0.234 cpb | **0.255 cpb** | 1.09x |

AArch64 values are throughput (higher is better); x86 values are cycles/byte
(lower is better). The folded AArch64 path is reported for bulk/key-reuse
throughput. The PQC integrations use the EOR ARM Crypto variant because those
schemes rekey frequently.

### CUDA (RTX 4080, 76 SMs) — corresponds to the paper's CUDA throughput/profiling tables

| Mode | Compact V2 (GiB/s) | CF Staggered V3 (GiB/s) |
|------|--------------------:|------------------------:|
| ECB kernel | 79.93 | 81.16 |
| CTR kernel | 100.57 | 103.74 |
| ECB end-to-end | 5.22 | 5.41 |

Performance on other GPUs will differ proportionally to SM count and memory bandwidth.

### PQC Integration (Apple M2) — corresponds to the paper's PQC integration table

| Algorithm | Level | Sign Speedup | Verify Speedup |
|-----------|-------|------------:|---------------:|
| SDitH | 3 | 1.18x | 1.20x |
| SDitH | 5 | 1.18x | 1.19x |
| Mirath | 3 | 51.4x | 133.2x |
| Mirath | 5 | 30.5x | 85.5x |
| RYDE | 3 | 106.2x | 121.9x |
| RYDE | 5 | 56.6x | 67.2x |
| MQOM | 3 | 114.3x | 155.6x |
| MQOM | 5 | 85.0x | 125.5x |

Speedups are ARM Crypto Extension over constant-time Reference implementation.

---

## Results Directory

Each subdirectory in `results/` contains an `env.txt` file describing the exact hardware, OS, toolchain, and measurement methodology.

| Directory | Platform | Paper section |
|-----------|----------|------------|
| `cortexm4_stm32f407/` | STM32F407VG, Cortex-M4, 168 MHz | Cortex-M4 |
| `aarch64_apple_m2/` | Apple M2, macOS | AArch64 |
| `aarch64_rpi5_a76/` | Raspberry Pi 5, Cortex-A76, Linux | AArch64 |
| `aarch64_rpi4/` | Raspberry Pi 4, Cortex-A72, Linux | AArch64 |
| `x86_i7_1165g7/` | Intel i7-1165G7, VAES-512 | AArch64/x86 comparison |
| `cuda_rtx4080/` | RTX 4080, 76 SMs, CUDA 12.0 | CUDA |
| `pqc_apple_m2/` | Apple M2, PQC signature schemes | Evaluation |

The CUDA results directory also includes:
- Nsight Compute profiling data (`ncu_*.txt`, `ncu_summary.csv`) showing occupancy, IPC, and bank conflict metrics reported in the paper
- `ecb_naive.csv` / `ctr_naive.csv` — CF layout **without** staggered store optimization (pre-optimization baseline)
- `ecb_staggered.csv` / `ctr_staggered.csv` — CF layout **with** staggered store optimization

The naive vs. staggered comparison corresponds to the paper's CUDA tables
(Compact vs. CF naive vs. CF staggered).

**Note on PQC benchmark data:** The raw logs in `pqc_apple_m2/final_benchmark_*.txt` are from a separate measurement run and may show minor variations (within typical run-to-run noise) from the summary values. The canonical results used in the paper are in `pqc_apple_m2/benchmark_summary.md`.

---

## PQC Integration Notes

The PQC benchmarks (`benchmark_pqc/`) require external NIST PQC signature candidate source trees:

- **SDitH**: [NIST PQC Round 1 submission](https://csrc.nist.gov/Projects/pqc-dig-sig)
- **Mirath**: [NIST PQC Round 1 submission](https://csrc.nist.gov/Projects/pqc-dig-sig)
- **RYDE**: [NIST PQC Round 1 submission](https://csrc.nist.gov/Projects/pqc-dig-sig)
- **MQOM**: [NIST PQC Round 1 submission](https://csrc.nist.gov/Projects/pqc-dig-sig)

See `benchmark_pqc/INTEGRATION_STATUS.md` for integration details and patching instructions. The pre-collected results in `results/pqc_apple_m2/` can be used for verification without building the PQC libraries.

---

## Cipher Parameters

| Parameter | AES-128 | Rijndael-256 |
|-----------|---------|-------------|
| Block size (bits) | 128 | 256 |
| State matrix | 4 x 4 | 4 x 8 |
| Nb (32-bit words) | 4 | 8 |
| ShiftRows offsets | (0, 1, 2, 3) | (0, 1, 3, 4) |
| Nr (rounds) | 10 | 14 (all key sizes) |

The non-uniform ShiftRows offset difference (0,1,3,4) vs AES's arithmetic progression (0,1,2,3) is the core obstacle addressed by this work.
