# Rijndael-256 ARM Optimization Integration Status

> **Note on third-party code and licensing.** `folded_integration/` contains only
> our own Rijndael-256 integration files (the `rijndael256_*` sources, wrappers,
> and the build-file edits) intended to be dropped on top of each scheme's
> upstream NIST reference implementation. Obtain the upstream SDitH, Mirath, RYDE,
> MQOM, and FAEST reference codebases from their respective sources; those carry
> their own licenses. Our integration files are released under this repository's
> MIT license (see `../LICENSE`).

## All 5 NIST PQC Signature Algorithms Integrated

| # | Algorithm | Variants | Build System | Status | KAT Verified |
|---|-----------|----------|-------------|--------|-------------|
| 1 | **SDitH** | cat3_fast, cat5_fast | CMake | DONE | Runtime OK |
| 2 | **Mirath** | tcith_3a_fast, tcith_5a_fast | Makefile | DONE | Runtime OK |
| 3 | **RYDE** | ryde3f, ryde5f | Makefile | DONE | KAT byte-identical |
| 4 | **MQOM** | cat3_gf256_fast_r3, cat5_gf256_fast_r3 | Makefile | DONE | Test 1/1 pass |
| 5 | **FAEST** | faest_256f | Makefile | DONE | API test + KAT OK |

## Build Commands

### SDitH
```bash
cd SDitH/Reference_Implementation/sdith_cat3_fast
mkdir build_arm && cd build_arm
cmake .. -DUSE_ARM_CRYPTO=ON -DBUILD_KATS=OFF && make -j
# NEON variant:
cmake .. -DUSE_NEON=ON -DBUILD_KATS=OFF && make -j
```

### Mirath
```bash
cd Mirath/Reference_Implementation/mirath_tcith/mirath_tcith_3a_fast
make arm_crypto   # ARM Crypto Extension
make neon         # NEON TBL/TBX
make ref          # Original reference
```

### RYDE
```bash
cd RYDE/Reference_Implementation/ryde3f
make ryde3f-arm-main    # ARM Crypto build
make ryde3f-arm-bench   # ARM benchmark
make ryde3f-arm-kat     # KAT generation
```

### MQOM
```bash
cd MQOM/Reference_Implementation/mqom2_cat3_gf256_fast_r3
make bench RIJNDAEL_ARM_CRYPTO=1   # ARM Crypto
make bench                          # Reference (default)
```

### FAEST
```bash
cd FAEST/Reference_Implementation/faest_256f
make    # Auto-detects ARM, enables ARM Crypto by default
make USE_NEON=1   # NEON variant
```

## Architecture Summary

### Common Pattern
All integrations follow the same pattern:
1. Copy our optimized files (header, tables, keyschedule, ARM/NEON assembly)
2. Create wrapper bridging algorithm's API to our `Rijndael256Key` + `rijndael256_encrypt_arm/neon()`
3. Modify build system with ARM/NEON compile options
4. Guard original reference code with `#if !defined(USE_ARM_CRYPTO) && !defined(USE_NEON)`

### Key Compatibility
All algorithms store Rijndael-256 round keys in a 480-byte layout that is **byte-identical** to our `Rijndael256Key.roundKeys[480]`. No conversion needed -- simple `memcpy`.

### Optimization Highlights

| Algorithm | Special Optimization | Notes |
|-----------|---------------------|-------|
| SDitH | 4-block CTR via `neon_4pt` | CTR mode batches 4 counter values for SIMD parallel encryption |
| Mirath | Single-block ARM Crypto | Seed expansion uses single-block encrypt |
| RYDE | Single-block ARM Crypto | Same pattern as Mirath (same authors) |
| MQOM | Individual `encrypt_arm` x4 | x4 multi-key = 4 different keys, cannot use `neon_4pt` |
| FAEST | Only encrypt function replaced | `aes_extend_witness` untouched (needs intermediate round state) |

### Platform Fixes Applied
- **Mirath, RYDE**: RDTSC cycle counter replaced with ARM `cntvct_el0`
- **RYDE**: `x86intrin.h` guarded with arch check, `bsr` replaced with ARM `clz`
- **All**: x86-specific compiler flags (`-maes`, `-msse`, `-march=native`) removed for ARM builds

## Preliminary Performance (Apple Silicon M-series)

| Algorithm | Metric | Speedup vs Reference |
|-----------|--------|---------------------|
| MQOM | Sign | ~33x |
| MQOM | Verify | ~118x |
| RYDE | Sign | ~47x |
| SDitH | Sign+Verify | ~0.2s total (ARM Crypto) |
