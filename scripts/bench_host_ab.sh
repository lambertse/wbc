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
#
# Only src/vm/vm.{h,cpp} are taken from the baseline commit; everything else
# (including the benchmark itself) comes from the working tree, so the two
# builds differ ONLY by the VM change under test.
set -euo pipefail
cd "$(dirname "$0")/.."
REPO=$(pwd)

BASE_REF="master"
ROUNDS=3
OPTS=(-O2 -O3)
BLOB="$REPO/sealed.blob"
PASS="demo"
while [ $# -gt 0 ]; do
    case "$1" in
        --base)   BASE_REF="$2"; shift 2 ;;
        --rounds) ROUNDS="$2"; shift 2 ;;
        --opt)    OPTS=("$2"); shift 2 ;;
        --blob)   BLOB="$2"; shift 2 ;;
        --pass)   PASS="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 1 ;;
    esac
done

[ -f "$BLOB" ] || { echo "no blob at $BLOB — run ./scripts/gen_blob.sh first" >&2; exit 1; }
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

echo "==> baseline: $BASE_REF (src/vm/vm.{h,cpp} only)   current: working tree"
git worktree add --detach --quiet "$TMP/base" HEAD
git -C "$TMP/base" checkout --quiet "$BASE_REF" -- src/vm/vm.h src/vm/vm.cpp
# The "current" side builds straight from $REPO, so it picks up uncommitted work
# too. Only the baseline side is pinned to a commit.
if ! git -C "$TMP/base" diff --quiet HEAD -- src/vm/vm.h src/vm/vm.cpp; then
    echo "    (baseline differs from HEAD in the VM files — good, there is something to measure)"
else
    echo "ERROR: baseline and HEAD have identical src/vm/vm.{h,cpp}; nothing to compare." >&2
    exit 1
fi

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
        "$BASE_B/wb_bench" --blob "$BLOB" --pass "$PASS" --csv >"$TMP/b.$OPT.$r.csv" 2>/dev/null
        printf "."
        "$CUR_B/wb_bench"  --blob "$BLOB" --pass "$PASS" --csv >"$TMP/c.$OPT.$r.csv" 2>/dev/null
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
    for m in kdf_argon2id vm_run encrypt_block crypt_ctr_4k open; do
        bmin=$(min_metric b "$OPT" "$m")
        cmin=$(min_metric c "$OPT" "$m")
        if [ -z "$bmin" ] || [ -z "$cmin" ]; then continue; fi
        awk -v m="$m" -v b="$bmin" -v c="$cmin" 'BEGIN{
            d = (b>0) ? (c-b)/b*100.0 : 0;
            tag = (m=="kdf_argon2id") ? "  <- CONTROL" : "";
            printf "  %-16s %11.0f ns %11.0f ns %+8.1f%%%s\n", m, b, c, d, tag;
        }'
    done
    echo
    # Sanity: the control must not move. If it did, nothing else here is trustworthy.
    kb=$(min_metric b "$OPT" kdf_argon2id)
    kc=$(min_metric c "$OPT" kdf_argon2id)
    awk -v b="$kb" -v c="$kc" 'BEGIN{
        d=(b>0)?(c-b)/b*100.0:0; if (d<0) d=-d;
        if (d > 2.0)
            printf "  WARNING: the CONTROL moved %.1f%%. libsodium is identical in both\n           builds, so this run is contaminated by machine drift — quiet\n           the machine and repeat. Do not trust the deltas above.\n", d;
        else
            printf "  control steady (%.1f%%) — the deltas above are the code change.\n", d;
    }'
done

echo
echo "Reminder: -O2 vs -O3 is a separate question from the code change. Compare"
echo "the two blocks above to each other for that; compare within a block for"
echo "the effect of the VM change itself."
