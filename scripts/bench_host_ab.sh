#!/usr/bin/env bash
# bench_host_ab.sh — interleaved host A/B of a VM change, on YOUR machine.
#
# Why this exists: single before/after runs taken minutes apart are not
# comparable. This machine's own speed drifts (thermals, power mode, background
# load), and that drift is easily larger than the effect being measured. The
# giveaway in a bad comparison is kdf_argon2id moving: it is pure libsodium,
# always built -O2, untouched by any VM change — so if IT moved, the machine
# moved, and every other number moved with it.
#
# So: build both variants, run them INTERLEAVED (A B A B ...) so drift hits both
# equally, take the min of each metric across rounds, and print kdf_argon2id as
# the control. If the control differs by more than a couple of percent between
# the two builds, the run is contaminated — quiet the machine and repeat.
#
# Usage:
#   ./scripts/bench_host_ab.sh                        # HEAD vs master, -O2 and -O3
#   ./scripts/bench_host_ab.sh --base 96ca50d         # against a specific commit
#   ./scripts/bench_host_ab.sh --opt -O2              # just one opt level
#   ./scripts/bench_host_ab.sh --rounds 4
#   ./scripts/bench_host_ab.sh --scope tree --tool ladder   # codegen / ISA changes
#
# --scope vm    (default) takes only src/vm/vm.{h,cpp} from the baseline commit.
#               Right for interpreter changes.
# --scope tree  takes the whole src/ + include/ from the baseline. Needed when the
#               change spans the emitter, the ISA, the handlers or the blob format
#               — with --scope vm those files would come from the working tree on
#               BOTH sides and the "baseline" would silently contain the change.
#
# --tool bench  (default) runs wb_bench, which needs a blob.
# --tool ladder runs wb_ladder, which generates its own white-box and needs NO
#               blob. This is the only option that works across a blob-FORMAT
#               change, where one blob cannot be read by both builds.
#
# The benchmark sources always come from the working tree, so both sides run
# identical measurement code no matter what the scope is.
set -euo pipefail
cd "$(dirname "$0")/.."
REPO=$(pwd)

BASE_REF="master"
ROUNDS=3
OPTS=(-O2 -O3)
BLOB="$REPO/sealed.blob"
PASS="demo"
SCOPE="vm"
TOOL="bench"
while [ $# -gt 0 ]; do
    case "$1" in
        --base)   BASE_REF="$2"; shift 2 ;;
        --rounds) ROUNDS="$2"; shift 2 ;;
        --opt)    OPTS=("$2"); shift 2 ;;
        --blob)   BLOB="$2"; shift 2 ;;
        --pass)   PASS="$2"; shift 2 ;;
        --scope)  SCOPE="$2"; shift 2 ;;
        --tool)   TOOL="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 1 ;;
    esac
done
case "$SCOPE" in vm|tree) ;; *) echo "--scope must be vm or tree" >&2; exit 1 ;; esac
case "$TOOL" in
    # CONTROL is a metric no VM change can affect: Argon2id is pure libsodium,
    # aes_ref is plain AES. If IT moves, the machine moved and nothing else in the
    # table is trustworthy.
    bench)  BIN="wb_bench"; CONTROL="kdf_argon2id"
            METRICS="kdf_argon2id vm_run encrypt_block crypt_ctr_4k open" ;;
    ladder) BIN="wb_ladder"; CONTROL="aes_ref_total"
            METRICS="aes_ref_total wb_interp vm_run" ;;
    *) echo "--tool must be bench or ladder" >&2; exit 1 ;;
esac

if [ "$TOOL" = "bench" ]; then
    [ -f "$BLOB" ] || { echo "no blob at $BLOB — run ./scripts/gen_blob.sh first" >&2; exit 1; }
    BENCH_ARGS="--blob $BLOB --pass $PASS"
    if [ "$SCOPE" = "tree" ]; then
        echo "NOTE: --scope tree with --tool bench shares ONE blob between the two" >&2
        echo "      builds. If the change altered the blob format, the baseline build" >&2
        echo "      will fail to open it — use --tool ladder, which needs no blob." >&2
    fi
else
    BENCH_ARGS=""
fi
command -v git >/dev/null || { echo "git required" >&2; exit 1; }

TMP="${TMPDIR:-/tmp}/wbab.$$"
mkdir -p "$TMP"
cleanup() {
    local rc=$?
    git worktree remove --force "$TMP/base" 2>/dev/null || true
    # Keep the scratch dir (and the build logs in it) when something went wrong;
    # deleting it on failure is what makes a broken build undiagnosable.
    if [ "$rc" -ne 0 ]; then
        echo "(exit $rc — leaving $TMP in place for inspection)" >&2
    else
        rm -rf "$TMP"
    fi
}
trap cleanup EXIT

if [ "$SCOPE" = "vm" ]; then
    BASE_PATHS="src/vm/vm.h src/vm/vm.cpp"
    echo "==> baseline: $BASE_REF ($BASE_PATHS)   current: working tree"
    echo "    tool: $BIN   scope: $SCOPE"
    # Worktree at HEAD, then rewind just the VM files.
    git worktree add --detach --quiet "$TMP/base" HEAD
    # shellcheck disable=SC2086
    git -C "$TMP/base" checkout --quiet "$BASE_REF" -- $BASE_PATHS
else
    echo "==> baseline: $BASE_REF (whole tree)   current: working tree"
    echo "    tool: $BIN   scope: $SCOPE"
    # Check the worktree out AT the baseline commit rather than rewinding paths
    # inside a HEAD worktree. `git checkout <ref> -- <paths>` only overwrites
    # files that exist in <ref>; files ADDED since (a new example, a new test)
    # survive from HEAD and then fail to compile against the older headers.
    git worktree add --detach --quiet "$TMP/base" "$BASE_REF"
fi
# The measurement HARNESS always comes from the working tree — it is the
# instrument, not the code under test:
#   bench/    so both sides run identical timing code;
#   build.sh  because the baseline's copy may predate the benchmark target
#             entirely (master has no wb_ladder rule, and no BUILD_DIR/OPT_LEVEL
#             support, so it would quietly build the wrong thing in the wrong
#             place at the wrong -O level).
rm -rf "$TMP/base/bench"
cp -R "$REPO/bench" "$TMP/base/bench"
cp "$REPO/build.sh" "$TMP/base/build.sh"

# The "current" side builds straight from $REPO, so it picks up uncommitted work
# too. Only the baseline side is pinned to a commit.
if [ "$SCOPE" = "vm" ]; then
    # shellcheck disable=SC2086
    if git -C "$TMP/base" diff --quiet HEAD -- $BASE_PATHS; then
        echo "ERROR: baseline and HEAD are identical over $BASE_PATHS; nothing to" >&2
        echo "       compare. For a change outside src/vm/vm.{h,cpp}, use --scope tree." >&2
        exit 1
    fi
fi
echo "    (baseline prepared)"

# Share the fetched libsodium SOURCE tree (it is gitignored, so the worktree
# would otherwise re-download it).
ln -sfn "$REPO/third_party/libsodium" "$TMP/base/third_party/libsodium"

# libsodium is identical in every build here (build.sh always compiles it -O2,
# and no change under test touches it), so compile it once and reuse the archive
# for the remaining build dirs. Deliberately NOT seeded from $REPO/build: that
# archive may have been produced by a different toolchain or even a different
# platform, and linking a foreign archive fails with a wall of undefined
# symbols. The seed is only ever an archive this script just built.
#
# Seed BOTH libsodium.a and the sodium/ object directory: build.sh rebuilds the
# archive only when libsodium.a is absent, but it assembles libwbcrypto.a /
# libwbprovision.a from $BUILD/sodium/*.o every time. Copying just the archive
# leaves that glob empty and the static libs link with no libsodium at all.
SEED_DIR=""
build_one() {  # build_one <srcdir> <builddir> <opt>
    local src="$1" out="$2" opt="$3"
    mkdir -p "$out"
    if [ -n "$SEED_DIR" ] && [ ! -f "$out/libsodium.a" ]; then
        cp "$SEED_DIR/libsodium.a" "$out/libsodium.a"
        cp -R "$SEED_DIR/sodium" "$out/sodium"
    fi
    ( cd "$src" && OPT_LEVEL="$opt" BUILD_DIR="$out" ./build.sh >"$out/build.log" 2>&1 ) \
        || { echo "build failed ($src $opt) — see $out/build.log" >&2; exit 1; }
    if [ -z "$SEED_DIR" ] && [ -f "$out/libsodium.a" ] && [ -d "$out/sodium" ]; then
        SEED_DIR="$out"
    fi
}

# Pull one metric's min_ns out of a --csv run.
metric() { awk -F, -v m="$2" '$1==m {print $4}' "$1"; }
ct_of()  { awk -F= '/^# ct=/ {print $2}' "$1"; }

# Smallest min_ns for one metric across all rounds of one build.
# min-of-mins, not a mean: under additive noise the minimum is the
# least-contaminated estimate of the true cost.
min_metric() {  # min_metric <b|c> <opt> <metric>
    local pfx="$1" opt="$2" m="$3" r v best=""
    for r in $(seq 1 "$ROUNDS"); do
        v=$(metric "$TMP/$pfx.$opt.$r.csv" "$m")
        if [ -n "$v" ]; then
            if [ -z "$best" ]; then
                best="$v"
            else
                best=$(awk -v a="$best" -v b="$v" 'BEGIN{print (b<a)?b:a}')
            fi
        fi
    done
    printf '%s' "$best"
}

for OPT in "${OPTS[@]}"; do
    echo
    echo "=================  OPT_LEVEL=$OPT  ================="
    BASE_B="$TMP/b$OPT"; CUR_B="$TMP/c$OPT"
    echo "--> building baseline..."; build_one "$TMP/base" "$BASE_B" "$OPT"
    echo "--> building current..." ; build_one "$REPO"     "$CUR_B"  "$OPT"

    for r in $(seq 1 "$ROUNDS"); do
        printf "    round %d/%d " "$r" "$ROUNDS"
        # shellcheck disable=SC2086
        "$BASE_B/$BIN" $BENCH_ARGS --csv >"$TMP/b.$OPT.$r.csv" 2>/dev/null \
            || { echo "baseline $BIN failed (a blob-format change? try --tool ladder)" >&2; exit 1; }
        printf "."
        # shellcheck disable=SC2086
        "$CUR_B/$BIN" $BENCH_ARGS --csv >"$TMP/c.$OPT.$r.csv" 2>/dev/null \
            || { echo "current $BIN failed" >&2; exit 1; }
        printf ". done\n"
    done

    # Equivalence gate: a build whose ciphertext moved is not a faster build.
    bct=$(ct_of "$TMP/b.$OPT.1.csv"); cct=$(ct_of "$TMP/c.$OPT.1.csv")
    if [ "$bct" != "$cct" ]; then
        echo "  ERROR: ciphertext differs ($bct vs $cct) — the change broke the VM." >&2
        exit 1
    fi
    echo "  ct: $bct (identical)"
    echo
    printf "  %-16s %14s %14s %9s\n" metric baseline current delta
    printf "  %-16s %14s %14s %9s\n" ---------------- -------------- -------------- ---------
    # shellcheck disable=SC2086
    for m in $METRICS; do
        bmin=$(min_metric b "$OPT" "$m")
        cmin=$(min_metric c "$OPT" "$m")
        if [ -z "$bmin" ] || [ -z "$cmin" ]; then continue; fi
        awk -v m="$m" -v b="$bmin" -v c="$cmin" -v ctl="$CONTROL" 'BEGIN{
            d = (b>0) ? (c-b)/b*100.0 : 0;
            tag = (m==ctl) ? "  <- CONTROL" : "";
            printf "  %-16s %11.0f ns %11.0f ns %+8.1f%%%s\n", m, b, c, d, tag;
        }'
    done
    echo
    # Sanity: the control must not move. If it did, nothing else here is trustworthy.
    kb=$(min_metric b "$OPT" "$CONTROL")
    kc=$(min_metric c "$OPT" "$CONTROL")
    awk -v b="$kb" -v c="$kc" -v ctl="$CONTROL" 'BEGIN{
        d=(b>0)?(c-b)/b*100.0:0; if (d<0) d=-d;
        if (d > 2.0)
            printf "  WARNING: the CONTROL (%s) moved %.1f%%. It is unaffected by any VM\n           change, so this run is contaminated by machine drift — quiet the\n           machine and repeat. Do not trust the deltas above.\n", ctl, d;
        else
            printf "  control steady (%.1f%%) — the deltas above are the code change.\n", d;
    }'
done

echo
echo "Reminder: -O2 vs -O3 is a separate question from the code change. Compare"
echo "the two blocks above to each other for that; compare within a block for"
echo "the effect of the VM change itself."
