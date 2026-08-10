#!/usr/bin/env bash
# bench_android.sh — measure what O-MVLL costs, on a real arm64 Android device.
#
# Builds wb_bench TWICE from identical sources — once with the O-MVLL pass-plugin,
# once without — pushes both to the device along with host-generated blobs, runs
# them interleaved, and prints a ratio table.
#
# TWO KDF TIERS ARE MEASURED EVERY RUN. `wbc_open`'s cost is set by the blob's
# seal-KDF tier, not by the obfuscator, and the tiers differ by ~100x (~250 ms at
# heavy vs ~2 ms at light on arm64). Reporting one tier alone invites reading a
# 250 ms `open` as "the loader is slow", so the primary blob gets the full metric
# set and a contrasting-tier blob is re-measured for `open`/`kdf` only — those are
# the sole tier-dependent metrics, so the second pass costs seconds at most.
#
# Usage:
#   ./scripts/bench_android.sh                       # full A/B, heavy + light
#   ./scripts/bench_android.sh --rounds 3 --cpu 7
#   ./scripts/bench_android.sh --blob my.blob --pass secret
#   ./scripts/bench_android.sh --kdf light --no-build   # light primary, heavy contrast
#
# Options:
#   --blob FILE     blob to benchmark (default sealed.blob; regenerated if
#                   missing OR left over from an older blob format version).
#                   The contrasting-tier blob is <name>-<tier>.blob beside it.
#   --pass P        blob passphrase (default "demo", matching gen_blob.sh)
#   --kdf TIER      light|medium|heavy (default heavy) — the PRIMARY tier, i.e.
#                   the one every metric is measured against. The secondary tier
#                   is chosen to contrast with it (light unless primary is light,
#                   in which case heavy). Passing this RE-SEALS the primary blob
#                   if it sits at a different tier, so the reported tier is always
#                   the one actually measured; omitting it reuses whatever tier the
#                   existing blob has. Reported tiers are always read back out of
#                   the blob headers, never echoed from this flag.
#   --rounds N      interleaved A/B rounds (default 2)
#   --cooldown SEC  pause between runs, to bleed off heat (default 5)
#   --cpu N         pin to this CPU index (default: the highest-max-freq core)
#   --min-time MS   wb_bench batch target (default 300)
#   --reps N        wb_bench timed batches per metric (default 7)
#   --open-reps N   reps for wbc_open / the KDF (default 5); raise to tighten the
#                   `open - kdf` bound
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
KDF="heavy"
KDF_EXPLICIT=0   # was --kdf actually passed? decides whether to re-seal an
                 # existing blob that sits at a different tier
ROUNDS=2
COOLDOWN=5
CPU=""
MIN_TIME=300
REPS=7
OPEN_REPS=5
SERIAL=""
DO_BUILD=1

while [ "$#" -gt 0 ]; do
    case "$1" in
        --blob)     BLOB="$2"; shift 2 ;;
        --pass)     PASS="$2"; shift 2 ;;
        --kdf)      KDF="$2"; KDF_EXPLICIT=1; shift 2 ;;
        --rounds)   ROUNDS="$2"; shift 2 ;;
        --cooldown) COOLDOWN="$2"; shift 2 ;;
        --cpu)      CPU="$2"; shift 2 ;;
        --min-time) MIN_TIME="$2"; shift 2 ;;
        --reps)     REPS="$2"; shift 2 ;;
        --open-reps) OPEN_REPS="$2"; shift 2 ;;
        --serial)   SERIAL="$2"; shift 2 ;;
        --no-build) DO_BUILD=0; shift ;;
        # Print the whole comment header rather than a hardcoded line range: the
        # range silently truncated --help mid-options list every time the header
        # grew. Stops at the first non-comment line.
        -h|--help)  sed -n '2,/^[^#]/p' "$0" | sed '$d'; exit 0 ;;
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
#
# Regenerate on a MISSING blob or a STALE one. Checking only for existence was a
# trap: a blob left over from an older format version is present, so it was
# pushed to the device, where wb_bench refused it and the failure surfaced as an
# opaque mid-run error rather than "your blob is old". The format version is the
# u32 at offset 4, little-endian.
blob_version() {  # blob_version <file> -> decimal format version, or empty
    [ -f "$1" ] || return 0
    [ "$(dd if="$1" bs=1 count=4 status=none | tr -d '\0')" = "WBTS" ] || return 0
    od -An -tu4 -j4 -N4 "$1" 2>/dev/null | tr -d ' \n'
}
blob_tier() {  # blob_tier <file> -> light|medium|heavy, or empty
    [ -f "$1" ] || return 0
    case "$(od -An -tu4 -j8 -N4 "$1" 2>/dev/null | tr -d ' \n')" in
        0) echo light ;; 1) echo medium ;; 2) echo heavy ;;
    esac
}
tier_desc() {  # tier_desc <light|medium|heavy> -> what to expect from `open`
    case "$1" in
        light)  echo "HKDF-SHA256, no Argon2id — expect open ~2 ms" ;;
        medium) echo "Argon2id 16 MiB / 2 passes — expect open ~60 ms" ;;
        heavy)  echo "Argon2id 64 MiB / 2 passes — expect open ~250 ms" ;;
        *)      echo "unknown tier" ;;
    esac
}
BLOB_WANT_VERSION=4

# ensure_blob <file> <wanted-tier> <force-tier: 0|1>
# Seals <file> at <wanted-tier> if it is missing, from an older format version,
# or (when force-tier is 1) sealed at some other tier. Echoes the tier read back
# OUT of the finished file — never the one that was asked for, so a mismatch can
# never be reported as a success.
ensure_blob() {
    local f="$1" want="$2" force="$3" reason=""
    if [ ! -f "$f" ]; then
        reason="missing"
    elif [ "$(blob_version "$f")" != "$BLOB_WANT_VERSION" ]; then
        reason="stale (format v$(blob_version "$f") != v$BLOB_WANT_VERSION)"
    elif [ "$force" -eq 1 ] && [ "$(blob_tier "$f")" != "$want" ]; then
        # Reusing the file and merely reporting the requested tier would print
        # e.g. "kdf=light" beside a 254 ms heavy `open` — a wrong number in
        # benchmark output, which is the one thing this harness must never do.
        reason="sealed at kdf=$(blob_tier "$f"), but kdf=$want was requested"
    fi
    if [ -n "$reason" ]; then
        # NOTE: >&2. This function's STDOUT is its return value (the tier), so any
        # progress chatter on stdout would be captured into the caller's variable
        # — which is exactly what happened, and produced a banner reading
        # "KDF TIER: ==> blob ... missing\nlight".
        say "blob $f $reason — sealing at kdf=$want via scripts/gen_blob.sh" >&2
        ./scripts/gen_blob.sh --key 000102030405060708090a0b0c0d0e0f --pass "$PASS" \
            --seed 42 --kdf "$want" --out "$f" >&2
    fi
    [ -f "$f" ] || die "blob $f still missing"
    [ "$(blob_version "$f")" = "$BLOB_WANT_VERSION" ] \
        || die "blob $f is not format v$BLOB_WANT_VERSION — delete it and re-run"
    local got; got=$(blob_tier "$f")
    [ -n "$got" ] || die "blob $f carries an unknown KDF tier — delete it and re-run"
    echo "$got"
}

# PRIMARY blob: the one every metric is measured against. Its tier is $KDF
# (default heavy — the tier docs/BUILD.md's historical numbers were taken at, and
# the safe default for the human-shaped default passphrase).
BLOB_TIER=$(ensure_blob "$BLOB" "$KDF" "$KDF_EXPLICIT")
say "blob: $BLOB ($(wc -c < "$BLOB" | tr -d ' ') bytes, kdf=$BLOB_TIER)"

# SECONDARY blob: the same key and seed at a CONTRASTING tier, so `open` is never
# ambiguous — one run reports both ends of the ~100x spread. Only `open` and `kdf`
# are re-measured against it (--only), because every other metric is
# tier-independent and re-running them would be pure wasted device time.
case "$BLOB_TIER" in
    light) BLOB2_TIER=heavy ;;   # contrast upward
    *)     BLOB2_TIER=light ;;   # heavy/medium -> contrast downward
esac
BLOB2="${BLOB%.blob}-$BLOB2_TIER.blob"
BLOB2_TIER=$(ensure_blob "$BLOB2" "$BLOB2_TIER" 1)
say "blob: $BLOB2 ($(wc -c < "$BLOB2" | tr -d ' ') bytes, kdf=$BLOB2_TIER) — open/kdf only"

# The KDF tier decides the whole scale of the `open` metric — a 100x spread
# between light and heavy — so it gets a banner rather than a line buried in
# preflight. "why is open still 250 ms?" is answered here, before the run.
#
# Note what the tier is a property OF: the blob, not the build. Both binaries
# below are byte-identical in this respect and would open a light blob just as
# happily; there is no such thing as a "heavy build".
printf '\n'
printf '  ============================================================\n'
printf '   KDF TIER (primary, all metrics): %s\n' "$BLOB_TIER"
printf '        %s\n' "$(tier_desc "$BLOB_TIER")"
printf '   KDF TIER (secondary, open+kdf) : %s\n' "$BLOB2_TIER"
printf '        %s\n' "$(tier_desc "$BLOB2_TIER")"
printf '\n'
printf '   The tier is read from each blob header (offset 8). It is a\n'
printf '   property of the BLOB, not of either build — both binaries open\n'
printf '   any tier, so there is no such thing as a "heavy build".\n'
printf '\n'
printf "   Only 'open' and 'kdf' change between tiers; the white-box, the\n"
printf '   VM and the tables are identical, so every other metric is\n'
printf '   measured once, against the primary blob.\n'
printf '  ============================================================\n\n'
# Both benchmark blobs are sealed with $PASS. At kdf=light that is only sound
# because these are throwaway measurement artifacts — say so, so nobody copies
# the pattern into a deployment. See wbc_kdf_tier in include/wbcrypto.h.
if [ "$BLOB_TIER" = "light" ] || [ "$BLOB2_TIER" = "light" ]; then
    warn "the kdf=light blob here is sealed with the benchmark passphrase '$PASS'.
      That is fine for measurement and WRONG for deployment: kdf=light assumes a
      passphrase with >=128 bits of machine-generated entropy."
fi

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
"${ADB[@]}" push "$BLOB2" "$DEV_DIR/bench2.blob" >/dev/null
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

run_one() {  # run_one <plain|omvll> <round> -> writes $OUT/raw-<label>-<round>.csv
    local label="$1" round="$2"
    local dst="$OUT/raw-$label-$round.csv"
    "${ADB[@]}" shell "cd $DEV_DIR && ${PIN}./wb_bench_$label --blob bench.blob \
        --pass $PASS_Q --csv --label $label --min-time $MIN_TIME --reps $REPS \
        --open-reps $OPEN_REPS" \
        | tr -d '\r' > "$dst"
    # wb_bench exits non-zero on a correctness failure; adb shell does not
    # propagate that, so detect it from the absent CSV header instead.
    grep -q '^metric,' "$dst" || { cat "$dst" >&2; die "wb_bench ($label, round $round) produced no results — see above"; }
    echo "$dst"
}

run_one_secondary() {  # -> $OUT/raw2-<label>-<round>.csv, open+kdf only
    local label="$1" round="$2"
    local dst="$OUT/raw2-$label-$round.csv"
    "${ADB[@]}" shell "cd $DEV_DIR && ${PIN}./wb_bench_$label --blob bench2.blob \
        --pass $PASS_Q --csv --label $label --min-time $MIN_TIME --reps $REPS \
        --open-reps $OPEN_REPS --only open,kdf" \
        | tr -d '\r' > "$dst"
    grep -q '^metric,' "$dst" || { cat "$dst" >&2; die "wb_bench (secondary, $label, round $round) produced no results — see above"; }
    echo "$dst"
}

say "running $ROUNDS interleaved round(s) at kdf=$BLOB_TIER, ${COOLDOWN}s cooldown between runs"
# Per-run wall clock, so a slow session is attributable rather than just "slow".
# At kdf=heavy each run spends (open-reps+1)x2 Argon2id evaluations ~ 3 s on
# Argon2id alone; at kdf=light that term all but vanishes.
RUN_T0=$(date +%s)
for r in $(seq 1 "$ROUNDS"); do
    for _label in plain omvll; do
        printf '    round %s/%s: %-5s kdf=%-6s (all metrics) ... ' \
               "$r" "$ROUNDS" "$_label" "$BLOB_TIER"
        _t0=$(date +%s)
        run_one "$_label" "$r" >/dev/null
        printf 'ok (%ss)\n' "$(( $(date +%s) - _t0 ))"
        # Secondary pass: open+kdf only, so this costs seconds at heavy and
        # milliseconds at light. No cooldown after it for the same reason.
        printf '    round %s/%s: %-5s kdf=%-6s (open+kdf)    ... ' \
               "$r" "$ROUNDS" "$_label" "$BLOB2_TIER"
        _t0=$(date +%s)
        run_one_secondary "$_label" "$r" >/dev/null
        printf 'ok (%ss)\n' "$(( $(date +%s) - _t0 ))"
        sleep "$COOLDOWN"
    done
done
say "device runs took $(( $(date +%s) - RUN_T0 ))s total (incl. ${COOLDOWN}s cooldowns)"

# ---- 7. reduce across rounds (best per metric) + compare --------------------
reduce() {  # reduce <label> [raw-prefix] -> $OUT/<prefix:-bench>-<label>.csv
    # NB: two separate `local` statements. Bash expands ALL words of a single
    # `local a=… b=$a` before performing any of the assignments, so a combined
    # form would expand $label to whatever leaked out of the `for label in …`
    # loop above (always "omvll") — silently comparing the omvll CSV to itself.
    local label="$1"
    local raw="${2:-raw}"
    local out_prefix="bench"
    [ "$raw" = "raw" ] || out_prefix="bench2"
    local dst="$OUT/$out_prefix-$label.csv"
    # Keep, per metric, the WHOLE ROW from the round with the smallest min_ns —
    # the least thermally-degraded observation of that work. Carrying the whole row
    # (rather than a per-column minimum) keeps median/min/max/mb_s mutually
    # consistent, which the noise-floor logic in bench_compare.sh depends on.
    grep '^#' "$OUT/$raw-$label-1.csv" > "$dst"
    echo 'metric,iters,median_ns,min_ns,max_ns,mb_s' >> "$dst"
    awk -F, '
        /^#/ || $1 == "metric" { next }
        {
            if (!($1 in best) || $4 + 0 < best[$1]) { best[$1] = $4 + 0; row[$1] = $0 }
            if (!($1 in seen)) { seen[$1] = 1; order[++n] = $1 }
        }
        END { for (i = 1; i <= n; i++) print row[order[i]] }
    ' "$OUT"/"$raw"-"$label"-*.csv >> "$dst"
    echo "$dst"
}

CSV_PLAIN=$(reduce plain)
CSV_OMVLL=$(reduce omvll)
CSV2_PLAIN=$(reduce plain raw2)
CSV2_OMVLL=$(reduce omvll raw2)
say "results: $CSV_PLAIN  $CSV_OMVLL"
say "results: $CSV2_PLAIN  $CSV2_OMVLL  (kdf=$BLOB2_TIER, open+kdf only)"

./scripts/bench_compare.sh "$CSV_PLAIN" "$CSV_OMVLL"

# ---- 8. open across KDF tiers -----------------------------------------------
# The point of the second pass: `open`'s scale is set by the tier, not by the
# obfuscator, and the two differ by ~100x. Printing both side by side is what
# stops a 250 ms `open` from being read as "the loader is slow".
metric_min() {  # metric_min <csv> <metric> -> min_ns, or empty
    awk -F, -v m="$2" '$1 == m { print $4; exit }' "$1"
}
fmt_ms() { awk -v n="$1" 'BEGIN { printf (n >= 1e6) ? "%.2f ms" : "%.0f us", (n >= 1e6) ? n/1e6 : n/1e3 }'; }

P1=$(metric_min "$CSV_PLAIN" open);  O1=$(metric_min "$CSV_OMVLL" open)
P2=$(metric_min "$CSV2_PLAIN" open); O2=$(metric_min "$CSV2_OMVLL" open)
K1=$(metric_min "$CSV_PLAIN" kdf);   K2=$(metric_min "$CSV2_PLAIN" kdf)

if [ -n "$P1" ] && [ -n "$P2" ]; then
    # The KDF column is headed "kdf alone", NOT "of which KDF". It is measured in
    # its own loop, so at the Argon2id tiers it is not a strict subset of `open`
    # and can even exceed it (the two fault in the 16/64 MiB arena differently).
    # Claiming containment here would contradict the UPPER BOUND caveat that
    # wb_bench prints for `open - kdf`. Values that exceed `open` get a marker.
    mark() { awk -v k="$1" -v o="$2" 'BEGIN { print (k + 0 >= o + 0) ? "*" : "" }'; }
    M1=$(mark "$K1" "$P1"); M2=$(mark "$K2" "$P2")
    printf '\n  === wbc_open across KDF tiers (min over %s round(s)) ===\n\n' "$ROUNDS"
    printf '  %-8s %14s %14s %15s\n' "tier" "plain" "omvll" "kdf alone"
    printf '  %-8s %14s %14s %15s\n' "--------" "-------------" "-------------" "--------------"
    printf '  %-8s %14s %14s %15s\n' "$BLOB_TIER"  "$(fmt_ms "$P1")" "$(fmt_ms "$O1")" "$(fmt_ms "$K1")$M1"
    printf '  %-8s %14s %14s %15s\n' "$BLOB2_TIER" "$(fmt_ms "$P2")" "$(fmt_ms "$O2")" "$(fmt_ms "$K2")$M2"
    if [ -n "$M1$M2" ]; then
        printf '\n  * kdf alone came out >= open: it is timed in a separate loop, so at the\n'
        printf '    Argon2id tiers it is NOT a subset of open and the two are not\n'
        printf '    subtractable. See "Reading open - kdf" in docs/BUILD.md.\n'
    fi
    printf '\n'
    awk -v a="$P1" -v b="$P2" -v ta="$BLOB_TIER" -v tb="$BLOB2_TIER" 'BEGIN {
        if (a > 0 && b > 0) {
            if (b < a) printf "  => kdf=%s opens %.0fx faster than kdf=%s (%.1f ms saved per open)\n", tb, a/b, ta, (a-b)/1e6
            else       printf "  => kdf=%s opens %.0fx faster than kdf=%s (%.1f ms saved per open)\n", ta, b/a, tb, (b-a)/1e6
        }
    }'
    cat <<'EOF'
     Same key, same tables, same ciphertext — the ONLY difference is how the
     seal key is derived. Pick the tier by whether an attacker has to GUESS the
     passphrase, not by this table: see wbc_kdf_tier in include/wbcrypto.h.
EOF
fi

cat <<EOF

  Primary tier (all metrics)  : $BLOB_TIER — $(tier_desc "$BLOB_TIER")
  Secondary tier (open + kdf) : $BLOB2_TIER — $(tier_desc "$BLOB2_TIER")
  The tier lives in the blob header, so it is what every wbc_open of that blob
  costs, on any build. Change the primary with --kdf light|medium|heavy.

  Raw per-round CSVs are in $OUT/raw-*.csv (primary) and $OUT/raw2-*.csv
  (secondary) — compare rounds to spot thermal throttling (a later round much
  slower than an earlier one means the cooldown was too short; raise --cooldown).

  NOTE on $OUT/bench2-*.csv: those are the SECONDARY-tier reduction and hold only
  open + kdf by design (--only). Feeding them to bench_compare.sh works but prints
  MISSING for the six tier-independent metrics — that is the filter, not a broken
  run. The full-table comparison above is bench-plain.csv vs bench-omvll.csv.

  Wall clock: the two NDK builds dominate a full run. Once they are warm,
  --no-build skips both and the whole thing is the device runs alone.
EOF
