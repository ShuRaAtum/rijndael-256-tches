#!/bin/bash
# =============================================================================
# Full PQC Signature Benchmark Suite
# Rijndael-256 ARM Optimization Impact on NIST PQC 2nd-round Additional Signatures
# Platform: Apple Silicon (M2) / AArch64
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(dirname "$SCRIPT_DIR")"
PQC_DIR="$(dirname "$BASE_DIR")/2nd-additional_signature"
RESULTS_DIR="$SCRIPT_DIR/results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULT_FILE="$RESULTS_DIR/benchmark_${TIMESTAMP}.txt"

OPENSSL_PREFIX=$(brew --prefix openssl 2>/dev/null || echo /opt/homebrew/opt/openssl@3)
OPENSSL_INC="$OPENSSL_PREFIX/include"
OPENSSL_LIB="$OPENSSL_PREFIX/lib"

mkdir -p "$RESULTS_DIR"

echo "=============================================" | tee "$RESULT_FILE"
echo "PQC Signature Benchmark — $(date)" | tee -a "$RESULT_FILE"
echo "Platform: $(uname -m) / $(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo unknown)" | tee -a "$RESULT_FILE"
echo "=============================================" | tee -a "$RESULT_FILE"
echo "" | tee -a "$RESULT_FILE"

# ---- Helper ----
section() { echo -e "\n=== $1 ===" | tee -a "$RESULT_FILE"; }

# =============================================================================
# 1. SDitH (CMake-based, wall-clock seconds)
# =============================================================================
run_sdith() {
    local variant=$1  # cat3_fast or cat5_fast
    local dir="$PQC_DIR/SDitH/Reference_Implementation/sdith_${variant}"
    section "SDitH $variant"

    for build in ref neon arm; do
        local builddir="$dir/build_${build}"
        if [ ! -f "$builddir/bench_sdith" ]; then
            echo "  Building $build..." | tee -a "$RESULT_FILE"
            mkdir -p "$builddir" && cd "$builddir"
            case $build in
                ref)  cmake .. 2>/dev/null && make -j 2>/dev/null ;;
                neon) cmake .. -DUSE_NEON=ON 2>/dev/null && make -j 2>/dev/null ;;
                arm)  cmake .. -DUSE_ARM_CRYPTO=ON 2>/dev/null && make -j 2>/dev/null ;;
            esac
            cd "$SCRIPT_DIR"
        fi
        echo "  [$build]" | tee -a "$RESULT_FILE"
        "$builddir/bench_sdith" 2>&1 | grep -E "^\s+(0|50|100)%" | tee -a "$RESULT_FILE"
    done
}

# =============================================================================
# 2. Mirath (Make-based, CPU cycles)
# =============================================================================
run_mirath() {
    local variant=$1  # 3a_fast or 5a_fast
    local dir="$PQC_DIR/Mirath/Reference_Implementation/mirath_tcith/mirath_tcith_${variant}"
    section "Mirath $variant"

    for build in ref neon arm_crypto; do
        echo "  [$build]" | tee -a "$RESULT_FILE"
        cd "$dir"
        make clean 2>/dev/null
        make $build 2>/dev/null
        local binary=$(ls mirath_*_f 2>/dev/null | head -1)
        if [ -n "$binary" ]; then
            ./$binary 2>&1 | grep -E "crypto_sign" | tee -a "$RESULT_FILE"
        fi
        cd "$SCRIPT_DIR"
    done
}

# =============================================================================
# 3. RYDE (Make-based, CPU cycles)
# =============================================================================
run_ryde() {
    local variant=$1  # 3f or 5f
    local dir="$PQC_DIR/RYDE/Reference_Implementation/ryde${variant}"
    section "RYDE ${variant}"

    cd "$dir"
    make clean 2>/dev/null

    # ref
    echo "  [ref]" | tee -a "$RESULT_FILE"
    make ryde${variant}-rijndael-bench 2>/dev/null
    ./bin/ryde${variant}-rijndael-bench 2>&1 | grep -E "crypto_sign|Failures" | tee -a "$RESULT_FILE"

    # arm_crypto
    echo "  [arm_crypto]" | tee -a "$RESULT_FILE"
    make ryde${variant}-arm-bench 2>/dev/null
    ./bin/ryde${variant}-arm-bench 2>&1 | grep -E "crypto_sign|Failures" | tee -a "$RESULT_FILE"

    # neon
    echo "  [neon]" | tee -a "$RESULT_FILE"
    make ryde${variant}-neon-bench 2>/dev/null
    ./bin/ryde${variant}-neon-bench 2>&1 | grep -E "crypto_sign|Failures" | tee -a "$RESULT_FILE"

    cd "$SCRIPT_DIR"
}

# =============================================================================
# 4. MQOM (Make-based, wall-clock ms)
# =============================================================================
run_mqom() {
    local variant=$1  # cat3 or cat5
    local dir="$PQC_DIR/MQOM/Reference_Implementation/mqom2_${variant}_gf256_fast_r3"
    section "MQOM $variant"

    local extra="-I${OPENSSL_INC} -L${OPENSSL_LIB}"
    cd "$dir"

    for build in "RIJNDAEL_TABLE=1" "RIJNDAEL_NEON=1" "RIJNDAEL_ARM_CRYPTO=1"; do
        local name=$(echo $build | cut -d= -f1 | sed 's/RIJNDAEL_//' | tr '[:upper:]' '[:lower:]')
        echo "  [$name]" | tee -a "$RESULT_FILE"
        make clean 2>/dev/null
        make bench $build EXTRA_CFLAGS="$extra" 2>/dev/null
        ./bench 2>&1 | grep -E "Key Gen|Sign|Verify|Correctness" | tee -a "$RESULT_FILE"
    done

    cd "$SCRIPT_DIR"
}

# =============================================================================
# Run all
# =============================================================================
run_sdith cat3_fast
run_sdith cat5_fast
run_mirath 3a_fast
run_mirath 5a_fast
run_ryde 3f
run_ryde 5f
run_mqom cat3
run_mqom cat5

echo "" | tee -a "$RESULT_FILE"
echo "=============================================" | tee -a "$RESULT_FILE"
echo "Results saved to: $RESULT_FILE" | tee -a "$RESULT_FILE"
echo "=============================================" | tee -a "$RESULT_FILE"
