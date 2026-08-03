#!/usr/bin/env bash
# bench_android.sh — measure what O-MVLL costs, on a real arm64 Android device.
#
# Builds wb_bench TWICE from identical sources — once with the O-MVLL pass-plugin,
# once without — pushes both to the device along with ONE host-generated blob,
# runs them interleaved, and prints a ratio table.
#
# Usage:
#   ./scripts/bench_android.sh                       # full A/B
#   ./scripts/bench_android.sh --rounds 3 --cpu 7
#   ./scripts/bench_android.sh --blob my.blob --pass secret
#
# Options:
#   --blob FILE     blob to benchmark (default sealed.blob; generated if missing)
#   --pass P        blob passphrase (default "demo", matching gen_blob.sh)
#   --rounds N      interleaved A/B rounds (default 2)
#   --cooldown SEC  pause between runs, to bleed off heat (default 5)
#   --cpu N         pin to this CPU index (default: the highest-max-freq core)
#   --min-time MS   wb_bench batch target (default 300)
#   --reps N        wb_bench timed batches per metric (default 7)
#   --open-reps N   reps for wbc_open / the KDF (default 5); raise to tighten the
#                   `open - kdf` bound
#   --bulk-mb N     ALSO time a full N-MiB CTR encrypt+decrypt on device (the
#                   "how long does my N MB payload take?" number). OFF by default,
#                   and for good reason: the white-box runs well under 1 MB/s, so
#                   N=5 is ~2 min per leg — times 2 legs, times 2 builds, times
#                   --rounds. Start at 1. The per-block ratio the A/B actually
#                   needs is already covered by crypt_ctr_4k.
#   --serial S      adb device serial (for multiple attached devices)
#   --no-build      reuse the existing build-bench-{plain,omvll} trees
#
# ENVIRONMENT: this script deliberately INHERITS your working O-MVLL shell rather
# than reconstructing it. Export the same vars you use for a normal obfuscated
# build before running (NDK, OMVLL_CONFIG, OMVLL_PYTHONPATH, DYLD_LIBRARY_PATH,
# and PYTHONHOME if your CPython is under pyenv — see docs/BUILD.md Option C).
# It warns about anything missing instead of guessing a value for you.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"

BLOB="sealed.blob"
PASS="demo"
ROUNDS=2
COOLDOWN=5
CPU=""
MIN_TIME=300
REPS=7
OPEN_REPS=5
BULK_MB=0
SERIAL=""
DO_BUILD=1

while [ "$#" -gt 0 ]; do
    case "$1" in
        --blob)     BLOB="$2"; shift 2 ;;
        --pass)     PASS="$2"; shift 2 ;;
        --rounds)   ROUNDS="$2"; shift 2 ;;
        --cooldown) COOLDOWN="$2"; shift 2 ;;
        --cpu)      CPU="$2"; shift 2 ;;
        --min-time) MIN_TIME="$2"; shift 2 ;;
        --reps)     REPS="$2"; shift 2 ;;
        --open-reps) OPEN_REPS="$2"; shift 2 ;;
        --bulk-mb)  BULK_MB="$2"; shift 2 ;;
        --serial)   SERIAL="$2"; shift 2 ;;
        --no-build) DO_BUILD=0; shift ;;
        -h|--help)  sed -n '2,30p' "$0"; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

ADB=(adb)
[ -n "$SERIAL" ] && ADB=(adb -s "$SERIAL")

PLUGIN="$ROOT/third_party/omvll/omvll_ndk_r29.dylib"
OUT="$ROOT/build-bench-out"
DEV_DIR="/data/local/tmp/wbbench"
TREE_PLAIN="$ROOT/build-bench-plain"
TREE_OMVLL="$ROOT/build-bench-omvll"

say()  { printf '==> %s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*" >&2; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# ---- 1. preflight -----------------------------------------------------------
say "preflight"

[ -n "${NDK:-}" ] || die "NDK is not set. export NDK=\$ANDROID_HOME/ndk/29.0.14206865 (see docs/BUILD.md)"
[ -d "$NDK" ] || die "NDK=$NDK does not exist"
TOOLCHAIN="$NDK/build/cmake/android.toolchain.cmake"
[ -f "$TOOLCHAIN" ] || die "no toolchain file at $TOOLCHAIN — is NDK=$NDK an NDK root?"

command -v cmake >/dev/null 2>&1 || die "cmake not found"
command -v ninja >/dev/null 2>&1 || die "ninja not found (the O-MVLL path uses -GNinja)"
command -v adb   >/dev/null 2>&1 || die "adb not found (install platform-tools)"

# The plugin is fetched on demand, exactly as -DOMVLL=ON would.
if [ ! -f "$PLUGIN" ]; then
    say "fetching the O-MVLL plugin (not committed)"
    ./third_party/fetch_deps.sh omvll
fi
[ -f "$PLUGIN" ] || die "plugin still missing at $PLUGIN"

# O-MVLL embeds a CPython VM; without a 3.10 stdlib it aborts with "failed to get
# the Python codec of the filesystem encoding". Warn rather than guess a path.
[ -n "${OMVLL_CONFIG:-}" ]     || warn "OMVLL_CONFIG is unset — the plugin will apply NO passes, making the A/B meaningless. export OMVLL_CONFIG=\$PWD/third_party/omvll/omvll_config.py"
[ -n "${OMVLL_PYTHONPATH:-}" ] || warn "OMVLL_PYTHONPATH is unset — the plugin's embedded CPython will likely abort. export OMVLL_PYTHONPATH=\$PWD/third_party/python/Lib"
if [ "$(uname -s)" = "Darwin" ] && [ -z "${DYLD_LIBRARY_PATH:-}" ]; then
    warn "DYLD_LIBRARY_PATH is unset — the plugin may fail to load. See docs/BUILD.md Option C"
fi

# Guard: the timing harness must NOT itself be a target of the obfuscator.
# omvll_config.py matches module names by SUBSTRING, so a harness named e.g.
# bench_wbvm.cpp would match "vm.cpp" and get break_control_flow injected into the
# measurement loop — in the obfuscated build only, silently inflating every ratio.
HARNESS="bench/wb_bench.cpp"
SENS_MODS=$(sed -n '/^_SENSITIVE_MODULES = (/,/^)/p' third_party/omvll/omvll_config.py \
            | grep -o '"[^"]*"' | tr -d '"' || true)
for _m in $SENS_MODS; do
    case "$HARNESS" in
        *"$_m"*) warn "$HARNESS matches _SENSITIVE_MODULES entry \"$_m\" in omvll_config.py — the obfuscator would transform the TIMING HARNESS itself, making every ratio below meaningless. Rename the benchmark source." ;;
    esac
done

DEV_STATE=$("${ADB[@]}" get-state 2>/dev/null || true)
[ "$DEV_STATE" = "device" ] || die "no adb device ready (get-state='$DEV_STATE'). Connect a device, enable USB debugging, accept the RSA prompt; use --serial if several are attached."
DEV_ABI=$("${ADB[@]}" shell getprop ro.product.cpu.abi | tr -d '\r\n')
say "device: $("${ADB[@]}" shell getprop ro.product.model | tr -d '\r\n') (abi=$DEV_ABI)"
case "$DEV_ABI" in
    arm64*) ;;
    *) die "device ABI is '$DEV_ABI'; O-MVLL supports AArch64/AArch32 only and this script builds arm64-v8a" ;;
esac

# ---- 2. one host-generated blob, shared by both builds ----------------------
# Generated on the HOST by the deliberately-unobfuscated gen_blob.sh path. Both
# builds then execute BYTE-IDENTICAL bytecode, which is the precondition for the
# ns/block numbers being comparable at all. Never seal on device: AssembleWhiteBox
# lives in assembler.cpp, which is in _MBA_MODULES (the heaviest pass set), so
# in-process sealing would diverge wildly between the two builds for no benefit.
if [ ! -f "$BLOB" ]; then
    say "blob $BLOB missing — generating on the host via scripts/gen_blob.sh"
    ./scripts/gen_blob.sh --key 000102030405060708090a0b0c0d0e0f --pass "$PASS" \
        --seed 42 --out "$BLOB"
fi
[ -f "$BLOB" ] || die "blob $BLOB still missing"
say "blob: $BLOB ($(wc -c < "$BLOB" | tr -d ' ') bytes)"

# ---- 3. build both trees (identical but for the plugin flag) ----------------
# Separate build dirs so the user's existing ./build is never clobbered.
build_tree() {  # build_tree <dir> <label> [extra cmake args...]
    local dir="$1" label="$2"; shift 2
    say "configuring $label -> $(basename "$dir")"
    cmake -GNinja -B "$dir" -S "$ROOT" \
        -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN" \
        -DANDROID_ABI=arm64-v8a \
        -DANDROID_PLATFORM=android-24 \
        -DCMAKE_BUILD_TYPE=Release \
        "$@" >"$OUT/configure-$label.log" 2>&1 \
        || { tail -30 "$OUT/configure-$label.log" >&2; die "configure failed for $label (full log: $OUT/configure-$label.log)"; }
    say "building $label (target wb_bench)"
    cmake --build "$dir" --target wb_bench -j >"$OUT/build-$label.log" 2>&1 \
        || { tail -40 "$OUT/build-$label.log" >&2; die "build failed for $label (full log: $OUT/build-$label.log)"; }
}

mkdir -p "$OUT"
if [ "$DO_BUILD" -eq 1 ]; then
    # Plain: no plugin flag at all. Everything else identical.
    build_tree "$TREE_PLAIN" plain
    # Obfuscated: -DOMVLL_PLUGIN=<path>, the flag shape from the known-good
    # invocation in docs/BUILD.md. CMakeLists.txt adds -fpass-plugin and
    # -Wl,-z,muldefs from it. Do NOT also pass -fpass-plugin via CMAKE_CXX_FLAGS.
    build_tree "$TREE_OMVLL" omvll -DOMVLL_PLUGIN="$PLUGIN"
else
    say "--no-build: reusing existing trees"
fi

BIN_PLAIN="$TREE_PLAIN/wb_bench"
BIN_OMVLL="$TREE_OMVLL/wb_bench"
for b in "$BIN_PLAIN" "$BIN_OMVLL"; do
    [ -f "$b" ] || die "missing $b (drop --no-build to build it)"
done

# A quick sanity signal that the plugin actually did something. Identical sizes
# usually mean the passes never applied (OMVLL_CONFIG unset / targeting missed).
SZ_PLAIN=$(wc -c < "$BIN_PLAIN" | tr -d ' ')
SZ_OMVLL=$(wc -c < "$BIN_OMVLL" | tr -d ' ')
say "binary size: plain=$SZ_PLAIN  omvll=$SZ_OMVLL"
[ "$SZ_PLAIN" = "$SZ_OMVLL" ] && warn "identical binary sizes — the plugin may not have applied any passes; check OMVLL_CONFIG and the configure log"

# ---- 4. push -----------------------------------------------------------------
say "pushing to $DEV_DIR"
"${ADB[@]}" shell "mkdir -p $DEV_DIR" >/dev/null
"${ADB[@]}" push "$BIN_PLAIN" "$DEV_DIR/wb_bench_plain" >/dev/null
"${ADB[@]}" push "$BIN_OMVLL" "$DEV_DIR/wb_bench_omvll" >/dev/null
"${ADB[@]}" push "$BLOB" "$DEV_DIR/bench.blob" >/dev/null
"${ADB[@]}" shell "chmod 755 $DEV_DIR/wb_bench_plain $DEV_DIR/wb_bench_omvll" >/dev/null

# ---- 5. CPU pinning ----------------------------------------------------------
# Pin to a big core: on big.LITTLE the scheduler can migrate the run mid-measure,
# which shows up as variance far larger than the effect being measured.
if [ -z "$CPU" ]; then
    CPU=$("${ADB[@]}" shell '
        best=-1; bestf=-1
        for d in /sys/devices/system/cpu/cpu[0-9]*; do
            n=${d#/sys/devices/system/cpu/cpu}
            f=$(cat $d/cpufreq/cpuinfo_max_freq 2>/dev/null || echo 0)
            if [ "$f" -gt "$bestf" ]; then bestf=$f; best=$n; fi
        done
        echo $best' 2>/dev/null | tr -d '\r\n' || true)
fi
PIN=""
if [ -n "$CPU" ] && [ "$CPU" != "-1" ]; then
    MASK=$(printf '%x' $(( 1 << CPU )))
    if "${ADB[@]}" shell "cd $DEV_DIR && taskset $MASK true" >/dev/null 2>&1; then
        PIN="taskset $MASK "
        say "pinning to cpu$CPU (mask 0x$MASK)"
    else
        warn "taskset unavailable on this device — running unpinned (expect more variance)"
    fi
else
    warn "could not determine the fastest core — running unpinned"
fi

# ---- 6. interleaved A/B runs -------------------------------------------------
# plain, omvll, plain, omvll — NOT all-plain-then-all-omvll. Thermal drift over a
# session is monotonic, so a sequential ordering systematically biases the ratio
# in favour of whichever build ran first. Take the best per (build, metric).
# The passphrase crosses TWO shells (local, then the device's), so it is wrapped in
# single quotes for the remote shell with any embedded single quote escaped. Without
# this, a passphrase containing a quote breaks the remote command line.
PASS_Q="'${PASS//\'/\'\\\'\'}'"

# Only pass --bulk-mb when asked; 0 means "skip the slow large-payload pass".
BULK_ARG=""
[ "$BULK_MB" -gt 0 ] 2>/dev/null && BULK_ARG="--bulk-mb $BULK_MB"

run_one() {  # run_one <plain|omvll> <round> -> writes $OUT/raw-<label>-<round>.csv
    local label="$1" round="$2"
    local dst="$OUT/raw-$label-$round.csv"
    "${ADB[@]}" shell "cd $DEV_DIR && ${PIN}./wb_bench_$label --blob bench.blob \
        --pass $PASS_Q --csv --label $label --min-time $MIN_TIME --reps $REPS \
        --open-reps $OPEN_REPS $BULK_ARG" \
        | tr -d '\r' > "$dst"
    # wb_bench exits non-zero on a correctness failure; adb shell does not
    # propagate that, so detect it from the absent CSV header instead.
    grep -q '^metric,' "$dst" || { cat "$dst" >&2; die "wb_bench ($label, round $round) produced no results — see above"; }
    echo "$dst"
}

say "running $ROUNDS interleaved round(s), ${COOLDOWN}s cooldown between runs"
for r in $(seq 1 "$ROUNDS"); do
    for label in plain omvll; do
        printf '    round %s/%s: %-5s ... ' "$r" "$ROUNDS" "$label"
        run_one "$label" "$r" >/dev/null
        printf 'ok\n'
        sleep "$COOLDOWN"
    done
done

# ---- 7. reduce across rounds (best per metric) + compare --------------------
reduce() {  # reduce <label> -> $OUT/bench-<label>.csv
    local label="$1" dst="$OUT/bench-$label.csv"
    # Keep, per metric, the WHOLE ROW from the round with the smallest min_ns —
    # the least thermally-degraded observation of that work. Carrying the whole row
    # (rather than a per-column minimum) keeps median/min/max/mb_s mutually
    # consistent, which the noise-floor logic in bench_compare.sh depends on.
    grep '^#' "$OUT/raw-$label-1.csv" > "$dst"
    echo 'metric,iters,median_ns,min_ns,max_ns,mb_s' >> "$dst"
    awk -F, '
        /^#/ || $1 == "metric" { next }
        {
            if (!($1 in best) || $4 + 0 < best[$1]) { best[$1] = $4 + 0; row[$1] = $0 }
            if (!($1 in seen)) { seen[$1] = 1; order[++n] = $1 }
        }
        END { for (i = 1; i <= n; i++) print row[order[i]] }
    ' "$OUT"/raw-"$label"-*.csv >> "$dst"
    echo "$dst"
}

CSV_PLAIN=$(reduce plain)
CSV_OMVLL=$(reduce omvll)
say "results: $CSV_PLAIN  $CSV_OMVLL"

./scripts/bench_compare.sh "$CSV_PLAIN" "$CSV_OMVLL"

cat <<EOF

  Raw per-round CSVs are in $OUT/raw-*.csv — compare rounds to spot thermal
  throttling (a later round much slower than an earlier one means the cooldown
  was too short; raise --cooldown).
EOF
