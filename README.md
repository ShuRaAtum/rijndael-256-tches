# Rijndael-256

Optimized implementations of Rijndael-256 (256-bit block) across multiple platforms.

- **Block size**: 256 bits (Nb = 8)
- **ShiftRows**: (0, 1, 3, 4)
- **Rounds**: Nr = 14 for all key sizes (128/192/256-bit)

## Performance Summary

### Cortex-M4 (STM32F407, 168 MHz)

| Directory | Method | Cycles | c/B | Constant-time |
|-----------|--------|-------:|----:|:-------------:|
| `cortexm4/ttable_asm/` | T-table ASM | **3,174** | 99 | No |
| `cortexm4/ttable/` | T-table C | 3,785 | 118 | No |
| `cortexm4/bitslice/` | Bitsliced ASM | **4,962** | 155 | Yes |
| `cortexm4/fixslice/` | Fixsliced ASM | 5,481 | 171 | Yes |
| `cortexm4/native/` | Native C | 12,374 | 387 | No |

> Measured 2026-03-17. Nr = 14 for all key sizes; encrypt cycles identical across 128/192/256-bit.
> Only key schedule cost varies. See `docs/benchmark_results.md` for full tables.

### Hardware AES reuse (AArch64 and x86)

| Platform | Method | AES-128 | AES-256 | R256 | Slowdown vs AES-256 |
|----------|--------|--------:|--------:|-----:|--------------------:|
| Apple M2 | ARM Crypto folded, N=4 | 15,252.6 MB/s | 11,721.6 MB/s | **6,520.0 MB/s** | 1.80x |
| Cortex-A76 (RPi5) | ARM Crypto folded, N=2 | 3,441.0 MB/s | 2,435.6 MB/s | **1,014.1 MB/s** | 2.40x |
| Intel i7-1165G7 | VAES-512, 16 blocks | 0.188 cpb | 0.234 cpb | **0.255 cpb** | 1.09x |

> AArch64 numbers are throughput, so higher is better; x86 numbers are cycles/byte,
> so lower is better. The folded AArch64 path is the bulk/key-reuse throughput
> path. PQC integration uses the EOR ARM Crypto variant because those schemes
> rekey frequently.
> Raw data: `docs/results/apple_m2_2026-06-18_run.txt`,
> `docs/results/rpi5_a76_2026-06-19_run.txt`,
> `docs/results/x86_i7-1165g7_2026-06-18.csv`.

## Project Structure

```
common/             Shared headers (rijndael256.h, test_vectors.h, tables)
cortexm4/           ARM Cortex-M4 (ARMv7E-M) implementations
  bitslice/           Bitsliced with explicit ShiftRows (best constant-time)
  fixslice/           Fixsliced with 8 MC variants (comparison)
  ttable_asm/         T-table hand-optimized ASM (fastest, not constant-time)
  ttable/             T-table C
  native/             Baseline native C
  board_setup/        STM32F407 startup code and linker script
aarch64/            AArch64 (ARMv8-A) implementations
  platform/apple/     ARM Crypto Extension + NEON (Apple Silicon)
  platform/linux_aarch64/  NEON only (Raspberry Pi 4)
  test/               Test suite
  benchmark/          Performance benchmark
x86/                x86-64 AES-NI / VAES reproduction for comparison
cuda/               NVIDIA GPU implementations
  cuda/               CUDA kernels (ECB, CTR, ES)
  cpu/                CPU reference
  test/               Test suite
  benchmark/          Benchmarks
docs/               Performance analysis, artifact guide (ARTIFACT_README.md),
                    and raw measurement data (results/)
```

## Build

```bash
# Cortex-M4 board test (requires arm-none-eabi-gcc + st-flash)
cd cortexm4/bitslice/board_test && make run

# AArch64 Apple Silicon
cd aarch64 && make test

# AArch64 Raspberry Pi 4
cd aarch64 && make -f Makefile.rpi4 test

# CUDA
cd cuda && mkdir build && cd build && cmake .. && make
```

## Paper

This repository accompanies the paper *Adapting AES-Oriented Optimizations to
Rijndael-256: Cortex-M4, ARMv8-A, and CUDA* (IACR TCHES). Citation details will
be added upon publication.

## License

Released under the MIT License (see [LICENSE](LICENSE)). The PQC integration
files under `benchmark_pqc/folded_integration/` are meant to be applied on top of
the respective upstream NIST reference implementations, which carry their own
licenses.

## References

- Alexandre Adomnicai and Thomas Peyrin, "Fixslicing AES-like Ciphers," TCHES 2021/1
- Joan Daemen and Vincent Rijmen, "The Design of Rijndael," Springer, 2002
