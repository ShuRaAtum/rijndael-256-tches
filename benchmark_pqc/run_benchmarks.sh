#!/bin/bash
# =============================================================================
# PQC Signature Benchmark Runner
#
# Builds and benchmarks each algorithm with Reference, NEON, and ARM Crypto
# implementations of Rijndael-256.
#
# Usage: ./run_benchmarks.sh [--iterations N] [--algorithm NAME]
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
NIST_DIR="$(cd "$ROOT_DIR/../2nd-additional_signature" && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"
ITERATIONS=100

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --iterations) ITERATIONS="$2"; shift 2;;
        --algorithm) ONLY_ALGO="$2"; shift 2;;
        --help) echo "Usage: $0 [--iterations N] [--algorithm NAME]"; exit 0;;
        *) echo "Unknown option: $1"; exit 1;;
    esac
done

mkdir -p "$RESULTS_DIR"

CSV_FILE="$RESULTS_DIR/benchmark_$(date +%Y%m%d_%H%M%S).csv"
echo "algorithm,level,impl,keygen_ms,sign_ms,verify_ms" > "$CSV_FILE"

echo "=========================================="
echo "  PQC Signature Benchmark Suite"
echo "  Iterations: $ITERATIONS"
echo "  Output: $CSV_FILE"
echo "=========================================="

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; }
info() { echo -e "${YELLOW}[INFO]${NC} $1"; }

# =============================================================================
# SDitH
# =============================================================================
build_sdith() {
    local variant=$1  # cat3_fast or cat5_fast
    local impl=$2     # ref, neon, arm
    local src_dir="$NIST_DIR/SDitH/Reference_Implementation/sdith_${variant}"
    local build_dir="$src_dir/build_${impl}"

    info "Building SDitH ${variant} (${impl})..."

    rm -rf "$build_dir"
    mkdir -p "$build_dir"
    cd "$build_dir"

    local cmake_flags="-DCMAKE_BUILD_TYPE=Release"
    case $impl in
        neon) cmake_flags="$cmake_flags -DUSE_NEON=ON";;
        arm)  cmake_flags="$cmake_flags -DUSE_ARM_CRYPTO=ON";;
        neon_il) cmake_flags="$cmake_flags -DUSE_NEON_IL=ON";;
    esac

    if cmake $cmake_flags .. > build.log 2>&1 && make -j$(sysctl -n hw.ncpu) >> build.log 2>&1; then
        pass "SDitH ${variant} (${impl}) built"
        return 0
    else
        fail "SDitH ${variant} (${impl}) build failed"
        cat build.log
        return 1
    fi
}

bench_sdith() {
    local variant=$1
    local impl=$2
    local level=$(echo $variant | sed 's/cat\([0-9]\).*/\1/')
    local build_dir="$NIST_DIR/SDitH/Reference_Implementation/sdith_${variant}/build_${impl}"

    if [ -f "$build_dir/sdith_bench" ]; then
        info "Benchmarking SDitH ${variant} (${impl})..."
        local result=$("$build_dir/sdith_bench" --csv --iterations $ITERATIONS 2>/dev/null || true)
        if [ -n "$result" ]; then
            echo "$result" >> "$CSV_FILE"
            pass "SDitH ${variant} (${impl}) benchmarked"
        fi
    elif [ -f "$build_dir/bench_sdith" ]; then
        info "Benchmarking SDitH ${variant} (${impl}) with bench_sdith..."
        local result=$("$build_dir/bench_sdith" --csv --iterations $ITERATIONS 2>/dev/null || true)
        if [ -n "$result" ]; then
            echo "$result" >> "$CSV_FILE"
            pass "SDitH ${variant} (${impl}) benchmarked"
        fi
    else
        fail "SDitH ${variant} (${impl}) benchmark binary not found"
    fi
}

# =============================================================================
# Mirath
# =============================================================================
build_mirath() {
    local variant=$1  # mirath_tcith_3a_fast or mirath_tcith_5a_fast
    local impl=$2     # ref, neon, arm
    local src_dir="$NIST_DIR/Mirath/Reference_Implementation/mirath_tcith/${variant}"

    info "Building Mirath ${variant} (${impl})..."
    cd "$src_dir"

    local make_flags=""
    case $impl in
        neon) make_flags="USE_NEON=1";;
        arm)  make_flags="USE_ARM_CRYPTO=1";;
    esac

    if make clean > /dev/null 2>&1 && make $make_flags -j$(sysctl -n hw.ncpu) > build.log 2>&1; then
        pass "Mirath ${variant} (${impl}) built"
        return 0
    else
        fail "Mirath ${variant} (${impl}) build failed"
        return 1
    fi
}

bench_mirath() {
    local variant=$1
    local impl=$2
    local level=$(echo $variant | sed 's/.*_\([0-9]\)a.*/\1/')
    local src_dir="$NIST_DIR/Mirath/Reference_Implementation/mirath_tcith/${variant}"

    local bench_bin=""
    for name in bench bench_mirath mirath_bench; do
        if [ -f "$src_dir/$name" ]; then
            bench_bin="$src_dir/$name"
            break
        fi
    done

    if [ -n "$bench_bin" ]; then
        info "Benchmarking Mirath ${variant} (${impl})..."
        local result=$("$bench_bin" --csv --iterations $ITERATIONS 2>/dev/null || true)
        if [ -n "$result" ]; then
            echo "$result" >> "$CSV_FILE"
            pass "Mirath ${variant} (${impl}) benchmarked"
        fi
    else
        fail "Mirath ${variant} (${impl}) benchmark binary not found"
    fi
}

# =============================================================================
# RYDE
# =============================================================================
build_ryde() {
    local variant=$1  # ryde3f or ryde5f
    local impl=$2
    local src_dir="$NIST_DIR/RYDE/Reference_Implementation/${variant}"

    info "Building RYDE ${variant} (${impl})..."
    cd "$src_dir"

    local make_flags=""
    case $impl in
        neon) make_flags="USE_NEON=1";;
        arm)  make_flags="USE_ARM_CRYPTO=1";;
    esac

    if make clean > /dev/null 2>&1 && make $make_flags -j$(sysctl -n hw.ncpu) > build.log 2>&1; then
        pass "RYDE ${variant} (${impl}) built"
        return 0
    else
        fail "RYDE ${variant} (${impl}) build failed"
        return 1
    fi
}

bench_ryde() {
    local variant=$1
    local impl=$2
    local level=$(echo $variant | sed 's/ryde\([0-9]\).*/\1/')
    local src_dir="$NIST_DIR/RYDE/Reference_Implementation/${variant}"

    local bench_bin=""
    for name in bench bench_ryde ryde_bench; do
        if [ -f "$src_dir/$name" ]; then
            bench_bin="$src_dir/$name"
            break
        fi
    done

    if [ -n "$bench_bin" ]; then
        info "Benchmarking RYDE ${variant} (${impl})..."
        local result=$("$bench_bin" --csv --iterations $ITERATIONS 2>/dev/null || true)
        if [ -n "$result" ]; then
            echo "$result" >> "$CSV_FILE"
            pass "RYDE ${variant} (${impl}) benchmarked"
        fi
    else
        fail "RYDE ${variant} (${impl}) benchmark binary not found"
    fi
}

# =============================================================================
# MQOM
# =============================================================================
build_mqom() {
    local variant=$1  # mqom2_cat3_gf256_fast_r3 or mqom2_cat5_gf256_fast_r3
    local impl=$2
    local src_dir="$NIST_DIR/MQOM/Reference_Implementation/${variant}"

    info "Building MQOM ${variant} (${impl})..."
    cd "$src_dir"

    local make_flags=""
    case $impl in
        neon) make_flags="USE_NEON=1";;
        arm)  make_flags="USE_ARM_CRYPTO=1";;
    esac

    if make clean > /dev/null 2>&1 && make $make_flags -j$(sysctl -n hw.ncpu) > build.log 2>&1; then
        pass "MQOM ${variant} (${impl}) built"
        return 0
    else
        fail "MQOM ${variant} (${impl}) build failed"
        return 1
    fi
}

bench_mqom() {
    local variant=$1
    local impl=$2
    local level=$(echo $variant | sed 's/.*cat\([0-9]\).*/\1/')
    local src_dir="$NIST_DIR/MQOM/Reference_Implementation/${variant}"

    local bench_bin=""
    for name in bench bench_mqom mqom_bench; do
        if [ -f "$src_dir/$name" ]; then
            bench_bin="$src_dir/$name"
            break
        fi
    done

    if [ -n "$bench_bin" ]; then
        info "Benchmarking MQOM ${variant} (${impl})..."
        local result=$("$bench_bin" --csv --iterations $ITERATIONS 2>/dev/null || true)
        if [ -n "$result" ]; then
            echo "$result" >> "$CSV_FILE"
            pass "MQOM ${variant} (${impl}) benchmarked"
        fi
    else
        fail "MQOM ${variant} (${impl}) benchmark binary not found"
    fi
}

# =============================================================================
# FAEST
# =============================================================================
build_faest() {
    local variant=$1  # faest_256f
    local impl=$2
    local src_dir="$NIST_DIR/FAEST/Reference_Implementation/${variant}"

    info "Building FAEST ${variant} (${impl})..."
    cd "$src_dir"

    local make_flags=""
    case $impl in
        neon) make_flags="USE_NEON=1";;
        arm)  make_flags="USE_ARM_CRYPTO=1";;
    esac

    if make clean > /dev/null 2>&1 && make $make_flags -j$(sysctl -n hw.ncpu) > build.log 2>&1; then
        pass "FAEST ${variant} (${impl}) built"
        return 0
    else
        fail "FAEST ${variant} (${impl}) build failed"
        return 1
    fi
}

bench_faest() {
    local variant=$1
    local impl=$2
    local src_dir="$NIST_DIR/FAEST/Reference_Implementation/${variant}"

    local bench_bin=""
    for name in bench bench_faest faest_bench; do
        if [ -f "$src_dir/$name" ]; then
            bench_bin="$src_dir/$name"
            break
        fi
    done

    if [ -n "$bench_bin" ]; then
        info "Benchmarking FAEST ${variant} (${impl})..."
        local result=$("$bench_bin" --csv --iterations $ITERATIONS 2>/dev/null || true)
        if [ -n "$result" ]; then
            echo "$result" >> "$CSV_FILE"
            pass "FAEST ${variant} (${impl}) benchmarked"
        fi
    else
        fail "FAEST ${variant} (${impl}) benchmark binary not found"
    fi
}

# =============================================================================
# KAT Verification
# =============================================================================
verify_kat() {
    local algo=$1
    local variant=$2
    local impl=$3
    local kat_dir=$4
    local build_dir=$5

    info "Verifying KAT: ${algo} ${variant} (${impl})..."

    local gen_bin=""
    for name in PQCgenKAT_sign PQCgenKAT; do
        if [ -f "$build_dir/$name" ]; then
            gen_bin="$build_dir/$name"
            break
        fi
    done

    if [ -z "$gen_bin" ]; then
        fail "KAT generator not found for ${algo} ${variant} (${impl})"
        return 1
    fi

    local kat_output="$RESULTS_DIR/kat_${algo}_${variant}_${impl}"
    mkdir -p "$kat_output"
    cd "$kat_output"
    "$gen_bin" > /dev/null 2>&1

    if [ -f "$kat_dir"/*.rsp ] && [ -f "$kat_output"/*.rsp ]; then
        if diff -q "$kat_dir"/*.rsp "$kat_output"/*.rsp > /dev/null 2>&1; then
            pass "KAT ${algo} ${variant} (${impl}): MATCH"
            return 0
        else
            fail "KAT ${algo} ${variant} (${impl}): MISMATCH"
            return 1
        fi
    else
        info "KAT ${algo} ${variant} (${impl}): .rsp files not found, skipping"
        return 0
    fi
}

# =============================================================================
# Main
# =============================================================================

IMPLS="ref neon arm"

echo ""
echo "=========================================="
echo "  Building and Benchmarking"
echo "=========================================="
echo ""

# SDitH
if [ -z "$ONLY_ALGO" ] || [ "$ONLY_ALGO" = "sdith" ]; then
    for variant in cat3_fast cat5_fast; do
        for impl in $IMPLS; do
            build_sdith $variant $impl && bench_sdith $variant $impl
        done
        # Extra: NEON interleaved for SDitH (4-block CTR)
        build_sdith $variant neon_il && bench_sdith $variant neon_il
    done
fi

# Mirath
if [ -z "$ONLY_ALGO" ] || [ "$ONLY_ALGO" = "mirath" ]; then
    for variant in mirath_tcith_3a_fast mirath_tcith_5a_fast; do
        for impl in $IMPLS; do
            build_mirath $variant $impl && bench_mirath $variant $impl
        done
    done
fi

# RYDE
if [ -z "$ONLY_ALGO" ] || [ "$ONLY_ALGO" = "ryde" ]; then
    for variant in ryde3f ryde5f; do
        for impl in $IMPLS; do
            build_ryde $variant $impl && bench_ryde $variant $impl
        done
    done
fi

# MQOM
if [ -z "$ONLY_ALGO" ] || [ "$ONLY_ALGO" = "mqom" ]; then
    for variant in mqom2_cat3_gf256_fast_r3 mqom2_cat5_gf256_fast_r3; do
        for impl in $IMPLS; do
            build_mqom $variant $impl && bench_mqom $variant $impl
        done
    done
fi

# FAEST (only 256f)
if [ -z "$ONLY_ALGO" ] || [ "$ONLY_ALGO" = "faest" ]; then
    for impl in $IMPLS; do
        build_faest faest_256f $impl && bench_faest faest_256f $impl
    done
fi

echo ""
echo "=========================================="
echo "  Results Summary"
echo "=========================================="
echo ""
echo "CSV output: $CSV_FILE"
echo ""

if [ -f "$CSV_FILE" ]; then
    echo "algorithm,level,impl,keygen_ms,sign_ms,verify_ms"
    tail -n +2 "$CSV_FILE" | sort
fi

echo ""
echo "Done."
