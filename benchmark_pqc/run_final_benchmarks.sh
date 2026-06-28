#!/bin/bash
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUT="$RESULTS_DIR/final_benchmark_${TIMESTAMP}.txt"
PQC_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")/2nd-additional_signature"
OPENSSL_PREFIX=$(brew --prefix openssl 2>/dev/null || echo /opt/homebrew/opt/openssl@3)
EXTRA="-I${OPENSSL_PREFIX}/include -L${OPENSSL_PREFIX}/lib"
mkdir -p "$RESULTS_DIR"

header() { echo -e "\n=== $1 ===" | tee -a "$OUT"; }
logmsg() { echo "  $1" | tee -a "$OUT"; }

echo "Final PQC Benchmark — $(date)" | tee "$OUT"
echo "Platform: $(uname -m)" | tee -a "$OUT"

# --- SDitH (201 iterations built-in) ---
run_sdith() {
    local variant="$1"
    local dir="$PQC_DIR/SDitH/Reference_Implementation/sdith_${variant}"
    header "SDitH $variant"
    for b in ref neon arm; do
        local bd="$dir/build_${b}"
        if [ ! -f "$bd/bench_sdith" ]; then
            mkdir -p "$bd" && cd "$bd"
            case $b in
                ref)  cmake .. > /dev/null 2>&1 ;;
                neon) cmake .. -DUSE_NEON=ON > /dev/null 2>&1 ;;
                arm)  cmake .. -DUSE_ARM_CRYPTO=ON > /dev/null 2>&1 ;;
            esac
            make -j > /dev/null 2>&1
            cd "$SCRIPT_DIR"
        fi
        logmsg "[$b]"
        "$bd/bench_sdith" 2>&1 | grep -E "50%" | tee -a "$OUT"
    done
}

# --- Mirath (shell loop: ref 10×, arm/neon 100×) ---
run_mirath() {
    local variant="$1"
    local dir="$PQC_DIR/Mirath/Reference_Implementation/mirath_tcith/mirath_tcith_${variant}"
    header "Mirath $variant"
    for b in ref neon arm_crypto; do
        cd "$dir" && make clean > /dev/null 2>&1 && make $b > /dev/null 2>&1
        local bin=$(ls mirath_*_f 2>/dev/null | head -1)
        if [ -z "$bin" ]; then logmsg "[$b] FAILED"; continue; fi
        local n=100
        [ "$b" = "ref" ] && n=10
        logmsg "[$b] ($n iterations)"
        local tmp="/tmp/mirath_${variant}_${b}_$$"
        for i in $(seq 1 $n); do ./$bin 2>&1 >> "$tmp"; done
        local half=$((n/2))
        local kg=$(grep "keypair:" "$tmp" | awk '{print $2}' | sort -n | awk "NR==${half}{print}")
        local sg=$(grep "crypto_sign:" "$tmp" | grep -v "open\|keypair" | awk '{print $2}' | sort -n | awk "NR==${half}{print}")
        local vf=$(grep "sign_open:" "$tmp" | awk '{print $2}' | sort -n | awk "NR==${half}{print}")
        logmsg "  keygen=$kg  sign=$sg  verify=$vf"
        rm -f "$tmp"
        cd "$SCRIPT_DIR"
    done
}

# --- RYDE (patch bench.c: ref 10×3, arm/neon 100×10) ---
run_ryde() {
    local variant="$1"
    local dir="$PQC_DIR/RYDE/Reference_Implementation/ryde${variant}"
    header "RYDE $variant"
    local bench="$dir/src/bench.c"
    cp "$bench" "$bench.orig"

    # ref (10 samples × 3 tests)
    sed -i '' 's/#define NB_TEST [0-9]*/#define NB_TEST 3/' "$bench"
    sed -i '' 's/#define NB_SAMPLES [0-9]*/#define NB_SAMPLES 10/' "$bench"
    cd "$dir" && make clean > /dev/null 2>&1
    logmsg "[ref] (10×3)"
    make ryde${variant}-rijndael-bench > /dev/null 2>&1
    ./bin/ryde${variant}-rijndael-bench 2>&1 | grep -E "crypto_sign|Failures" | tee -a "$OUT"

    # arm_crypto (100 samples × 10 tests)
    sed -i '' 's/#define NB_TEST [0-9]*/#define NB_TEST 10/' "$bench"
    sed -i '' 's/#define NB_SAMPLES [0-9]*/#define NB_SAMPLES 100/' "$bench"
    make clean > /dev/null 2>&1
    logmsg "[arm_crypto] (100×10)"
    make ryde${variant}-arm-bench > /dev/null 2>&1
    ./bin/ryde${variant}-arm-bench 2>&1 | grep -E "crypto_sign|Failures" | tee -a "$OUT"

    # neon (100 samples × 10 tests)
    logmsg "[neon] (100×10)"
    make ryde${variant}-neon-bench > /dev/null 2>&1
    ./bin/ryde${variant}-neon-bench 2>&1 | grep -E "crypto_sign|Failures" | tee -a "$OUT"

    mv "$bench.orig" "$bench"
    cd "$SCRIPT_DIR"
}

# --- MQOM (table/neon/arm 100×) ---
run_mqom() {
    local variant="$1"
    local dir="$PQC_DIR/MQOM/Reference_Implementation/mqom2_${variant}_gf256_fast_r3"
    header "MQOM $variant"
    cd "$dir"

    for flag_name in "RIJNDAEL_TABLE=1:table" "RIJNDAEL_NEON=1:neon" "RIJNDAEL_ARM_CRYPTO=1:arm_crypto"; do
        local flag=$(echo "$flag_name" | cut -d: -f1)
        local name=$(echo "$flag_name" | cut -d: -f2)
        make clean > /dev/null 2>&1
        make bench "$flag" EXTRA_CFLAGS="$EXTRA" > /dev/null 2>&1
        logmsg "[$name] (100 iterations)"
        ./bench 100 2>&1 | grep -E "Key Gen|Sign|Verify|Correctness" | tee -a "$OUT"
    done

    cd "$SCRIPT_DIR"
}

run_sdith cat3_fast
run_sdith cat5_fast
run_mqom cat3
run_mqom cat5
run_ryde 3f
run_ryde 5f
run_mirath 3a_fast
run_mirath 5a_fast

echo -e "\n=== DONE ===" | tee -a "$OUT"
echo "Results: $OUT" | tee -a "$OUT"
