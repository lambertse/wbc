#!/usr/bin/env bash
# bench_compare.sh — join two wb_bench CSVs and print the O-MVLL cost ratio.
#
#   ./scripts/bench_compare.sh <plain.csv> <omvll.csv>
#
# Inputs are produced by `wb_bench --csv`. Pure awk, no Python dependency.
#
# Beyond the ratio table it does two things that are easy to get wrong by hand:
#
#  * asserts the `# ct=` lines match. Both builds run the SAME pushed blob, so
#    they must produce identical ciphertext. If they don't, an obfuscation pass
#    broke the VM and every timing below is meaningless — so that's a hard error.
#  * asserts the `# kdf_tier=` lines match. `open` and `kdf` mean different
#    things at different tiers, so comparing across them is meaningless.
#  * derives `open - kdf`. At the Argon2id tiers (medium/heavy) raw `open` is
#    ~99% KDF — identical, unobfuscated libsodium in both builds — which
#    flattens its ratio to ~1.0x and hides the real cost of the flattened +
#    MBA'd loader in trusted_storage.cpp. At tier `none` the KDF is HKDF and
#    costs microseconds, so `open` is the loader and the subtraction finally
#    resolves.
set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <plain.csv> <omvll.csv>" >&2
    exit 2
fi
PLAIN="$1"; OMVLL="$2"
for f in "$PLAIN" "$OMVLL"; do
    [ -f "$f" ] || { echo "bench_compare: no such file: $f" >&2; exit 1; }
done

meta() {  # meta <file> <key> -> value from the "# key=value" header line
    awk -v k="$2" '$0 ~ "^# "k"=" { sub(/^# [^=]*=/, ""); print; exit }' "$1"
}

CT_PLAIN=$(meta "$PLAIN" ct);          CT_OMVLL=$(meta "$OMVLL" ct)
LBL_PLAIN=$(meta "$PLAIN" label);      LBL_OMVLL=$(meta "$OMVLL" label)
TIER_PLAIN=$(meta "$PLAIN" kdf_tier);  TIER_OMVLL=$(meta "$OMVLL" kdf_tier)
: "${LBL_PLAIN:=plain}"; : "${LBL_OMVLL:=omvll}"

# Same label on both sides means this is an A/A, not an A/B: the caller handed
# over the same CSV twice (or two runs of the same build). Every ratio would be
# exactly 1.00x and look like "obfuscation is free" — the most expensive kind of
# wrong answer this script can produce. Refuse rather than print it.
if [ "$LBL_PLAIN" = "$LBL_OMVLL" ]; then
    echo "bench_compare: both inputs carry '# label=$LBL_PLAIN' — this is an A/A comparison, not an A/B." >&2
    echo "               $PLAIN" >&2
    echo "               $OMVLL" >&2
    exit 1
fi

echo
echo "=== wb_bench comparison: $LBL_PLAIN  vs  $LBL_OMVLL ==="
echo "  blob geometry : code=$(meta "$PLAIN" code_len) B  data=$(meta "$PLAIN" data_len) B (copied per block)"

# --- cross-build equivalence (hard gate) ------------------------------------
if [ -z "$CT_PLAIN" ] || [ -z "$CT_OMVLL" ]; then
    echo "  ciphertext    : MISSING '# ct=' header — cannot verify equivalence" >&2
    exit 1
fi
if [ "$CT_PLAIN" != "$CT_OMVLL" ]; then
    {
        echo
        echo "  FAIL: the two builds produce DIFFERENT ciphertext for the same blob:"
        echo "        $LBL_PLAIN = $CT_PLAIN"
        echo "        $LBL_OMVLL = $CT_OMVLL"
        echo "  An obfuscation pass has broken the VM, so the timings would be"
        echo "  meaningless. Bring passes up one at a time in"
        echo "  third_party/omvll/omvll_config.py to find the culprit."
    } >&2
    exit 1
fi
echo "  ciphertext    : $CT_PLAIN  (identical in both builds — VM semantics preserved)"

# The tier sets the scale of both `open` and `kdf`, so a mismatch makes the whole
# lower half of this report a comparison between different quantities. Both runs
# are supposed to use the SAME pushed blob, so a mismatch also means the two runs
# did not — worth failing on rather than footnoting.
if [ -n "$TIER_PLAIN" ] && [ -n "$TIER_OMVLL" ]; then
    if [ "$TIER_PLAIN" != "$TIER_OMVLL" ]; then
        {
            echo
            echo "  FAIL: the two runs used blobs sealed at DIFFERENT KDF tiers:"
            echo "        $LBL_PLAIN = $TIER_PLAIN"
            echo "        $LBL_OMVLL = $TIER_OMVLL"
            echo "  'open' and 'kdf' are not comparable across tiers. Both runs must"
            echo "  use the same blob."
        } >&2
        exit 1
    fi
    echo "  kdf tier      : $TIER_PLAIN"
else
    # Pre-v4 CSVs have no such header. Say so instead of silently assuming.
    echo "  kdf tier      : (not recorded — CSV predates the tiered KDF)"
fi
echo

# --- ratio table ------------------------------------------------------------
# Everything below is min-based. Under additive noise (scheduler, thermals, a
# neighbour process) min is the least-contaminated estimate of the true cost, so
# a ratio of mins is the most stable cross-build comparison available. MB/s from
# the CSV is median-derived, so it is rescaled to the min for consistency.
awk -F, -v lp="$LBL_PLAIN" -v lo="$LBL_OMVLL" '
function fmt(ns) {
    return (ns >= 1e6) ? sprintf("%.2f ms", ns / 1e6) : sprintf("%.0f ns", ns)
}
FNR == 1 { file++ }
/^#/ || $1 == "metric" { next }
# metric,iters,median_ns,min_ns,max_ns,mb_s
file == 1 { p_med[$1] = $3 + 0; p_min[$1] = $4 + 0; p_mbs[$1] = $6 + 0; order[++n] = $1 }
file == 2 { o_med[$1] = $3 + 0; o_min[$1] = $4 + 0; o_mbs[$1] = $6 + 0 }
END {
    printf "  %-16s %13s %13s %9s %11s %11s\n", "metric", lp, lo, "ratio", "MB/s " lp, "MB/s " lo
    printf "  %-16s %13s %13s %9s %11s %11s\n", "----------------", "-------------", \
           "-------------", "---------", "-----------", "-----------"
    for (i = 1; i <= n; i++) {
        m = order[i]
        if (!(m in o_min)) {
            printf "  %-16s %13s %13s %9s\n", m, fmt(p_min[m]), "MISSING", "-"
            continue
        }
        r = (p_min[m] > 0) ? o_min[m] / p_min[m] : 0
        # mb_s was computed at median_ns; rescale to min_ns (exact: bytes cancel).
        pmb = (p_mbs[m] > 0 && p_min[m] > 0) ? p_mbs[m] * p_med[m] / p_min[m] : 0
        omb = (o_mbs[m] > 0 && o_min[m] > 0) ? o_mbs[m] * o_med[m] / o_min[m] : 0
        if (pmb > 0)
            printf "  %-16s %13s %13s %8.2fx %11.3f %11.3f\n", \
                   m, fmt(p_min[m]), fmt(o_min[m]), r, pmb, omb
        else
            printf "  %-16s %13s %13s %8.2fx %11s %11s\n", \
                   m, fmt(p_min[m]), fmt(o_min[m]), r, "-", "-"
    }

    # --- derived: vm_run minus the per-block DATA copy ----------------------
    # Well-conditioned (the copy is a small, stable slice of vm_run).
    if (("vm_run" in p_min) && ("data_copy" in p_min) &&
        ("vm_run" in o_min) && ("data_copy" in o_min)) {
        pv = p_min["vm_run"] - p_min["data_copy"]
        ov = o_min["vm_run"] - o_min["data_copy"]
        r  = (pv > 0) ? ov / pv : 0
        printf "\n  %-16s %13s %13s %8.2fx   <- interpreter dispatch + handlers,\n", \
               "vm_run - copy", fmt(pv), fmt(ov), r
        printf "  %-16s %13s %13s %9s      DATA copy removed\n", "", "", "", ""
    }

    # --- derived: open minus the KDF ---------------------------------------
    # At the Argon2id tiers this is ILL-CONDITIONED: the loader (a ~0.4 MB AEAD
    # decrypt + a header parse, well under 1 ms) sits inside a ~60-250 ms KDF whose
    # own run-to-run variation is larger than the signal. Report a value only when
    # the difference clears 2x the one-sided sampling spread in BOTH builds;
    # otherwise state the bound. Printing a ratio of two unresolved differences
    # would be inventing precision, and can even come out negative.
    #
    # At tier `none` the KDF is HKDF (microseconds), so the subtraction becomes
    # well-conditioned and this line reports the loader for real. Same code path —
    # the guard simply stops firing.
    if (("open" in p_min) && ("kdf" in p_min) &&
        ("open" in o_min) && ("kdf" in o_min)) {
        pl = p_min["open"] - p_min["kdf"]
        ol = o_min["open"] - o_min["kdf"]
        pm = 2 * ((p_med["open"] - p_min["open"] > p_med["kdf"] - p_min["kdf"]) \
                  ? p_med["open"] - p_min["open"] : p_med["kdf"] - p_min["kdf"])
        om = 2 * ((o_med["open"] - o_min["open"] > o_med["kdf"] - o_min["kdf"]) \
                  ? o_med["open"] - o_min["open"] : o_med["kdf"] - o_min["kdf"])
        if (pl > pm && ol > om) {
            r = (pl > 0) ? ol / pl : 0
            printf "\n  %-16s %13s %13s %8.2fx   <- trusted_storage.cpp loader\n", \
                   "open - kdf", fmt(pl), fmt(ol), r
            printf "  %-16s %13s %13s %9s      (flatten+MBA), KDF removed\n", "", "", "", ""
        } else {
            bound = (pm > om) ? pm : om
            printf "\n  %-16s %13s %13s %9s   <- NOT RESOLVABLE: the loader is\n", \
                   "open - kdf", "< " fmt(pm), "< " fmt(om), "n/a"
            printf "  %-16s %13s %13s %9s      under %s in both builds, i.e. lost\n", \
                   "", "", "", "", fmt(bound)
            printf "  %-16s %13s %13s %9s      inside the KDF. Heavy passes on\n", "", "", "", ""
            printf "  %-16s %13s %13s %9s      trusted_storage.cpp are affordable.\n", "", "", "", ""
            printf "  %-16s %13s %13s %9s      Re-seal at --kdf light to measure it.\n", "", "", "", ""
        }
    }
}' "$PLAIN" "$OMVLL"

cat <<'EOF'

  How to read this
  ----------------
  Times are per-iteration MINIMA; ratio = obfuscated / plain (1.00x = free).

  vm_run          the interpreter itself (vm.cpp + handlers.cpp). These are the
                  HOT tuple in omvll_config.py: break_control_flow only, with
                  flatten/MBA/opaque-constants deliberately excluded. Expect a
                  modest ratio. A 5-20x here means the hot-path exclusions are
                  NOT taking effect — debug the targeting, not the VM.
  data_copy       the DATA image vm::Run copies per block. Not obfuscated by any
                  pass, so it dilutes vm_run's ratio. Its share is strongly
                  device-dependent — ~4% of vm_run on an aarch64 Linux host but
                  ~30% on an arm64 phone — so on a phone `vm_run - copy` moves a
                  LOT, and its ratio is the honest one for the interpreter.
                  (An older note here claimed ~2% universally; that was a host
                  measurement. Trust the two columns above, not this text.)
  encrypt_block   the same work through the C ABI. wbcrypto.cpp is sensitive but
                  not hot, so this wrapper IS fully flattened. Expect a worse
                  ratio than vm_run; the gap is the SDK-glue cost.
  wrap_key        the whole white-box cost of a real use: two blocks to wrap a
                  session key. Fixed — it does not grow with the payload.
  open            dominated by the blob's KDF tier, so at medium/heavy its ratio
                  is near 1.00x by construction and says nothing about the
                  obfuscated loader. See `open - kdf`, which at those tiers
                  reports a BOUND rather than a value — the loader is genuinely
                  too cheap to resolve through the KDF. Re-seal the blob with
                  `--kdf light` and `open` becomes the loader, measurable.
  kdf             the blob's own key derivation: Argon2id at medium/heavy, HKDF
                  at light. Vendored libsodium either way, so it is the control
                  metric — if THIS moved between builds, the machine moved and
                  every other number moved with it.

  A note on picking the tier, since it is the one dial on `open`: it trades
  offline passphrase-guessing resistance for startup latency, and nothing else.
  It does not touch the white-box, the VM or the tables. `light` is correct only
  for a high-entropy machine-generated passphrase — see wbc_kdf_tier in
  include/wbcrypto.h.
EOF
