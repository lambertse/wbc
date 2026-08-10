// wb_bench — throughput/latency benchmark for the shipped white-box runtime.
//
//   wb_bench --blob FILE [--pass P] [--min-time MS] [--reps N] [--open-reps N]
//            [--csv] [--label TAG] [--only METRIC,...]
//
// Built twice from identical sources (O-MVLL plugin on / off) and compared, this
// answers the question docs/ANTI-TAMPER.md poses but cannot currently verify:
// "Benchmark wbc_encrypt_block after enabling CFF/MBA and pick a level you can
// afford." Drive both builds + the device run with scripts/bench_android.sh.
//
// ┌─ WHY THIS FILE IS NAMED `wb_bench.cpp` ────────────────────────────────────┐
// │ O-MVLL targeting in third_party/omvll/omvll_config.py matches module names  │
// │ by SUBSTRING, not by basename equality:                                    │
// │     return any(s in n for s in _SENSITIVE_MODULES)   # contains "vm.cpp"    │
// │ So a harness named `bench_wbvm.cpp` would match "vm.cpp" (...wb|vm.cpp|),   │
// │ also satisfy `_is_hot`, and get break_control_flow injected into the TIMING │
// │ LOOP — in the obfuscated build only, misattributing harness overhead to the │
// │ library. (This is live, not theoretical: tests/test_vm.cpp matches too.)    │
// │ Any future benchmark/harness file must avoid containing "vm.cpp",           │
// │ "handlers.cpp", "assembler.cpp", "fwcrypt.cpp", "fw_schedule",              │
// │ "trusted_storage.cpp", "wbcrypto.cpp" or "wbcrypto_provision.cpp" as a      │
// │ substring of its path, or it becomes part of what it measures.              │
// └────────────────────────────────────────────────────────────────────────────┘
//
// Links libwbcrypto (the RUNTIME set) only — same shape as src/tools/wb_encrypt.cpp
// — so this measures exactly what ships and cannot accidentally time the
// provisioning surface (white-box generation / the bytecode assembler).
#include <sodium.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <set>
#include <string>
#include <vector>

#include "measure.h"  // bench::Measure / bench::Result — shared with wb_ladder
#include "storage/trusted_storage.h"
#include "vm/vm.h"
#include "wbcrypto.h"

namespace {

using bench::Measure;
using bench::Result;

// ---- KDF parameters ---------------------------------------------------------
// Taken from the blob being benchmarked, via storage::PeekTier +
// storage::ParamsForTier. These used to be duplicated INTERACTIVE constants with
// a comment warning they would drift; now that the cost is a per-blob tier, a
// duplicate would not merely drift, it would time a KDF the blob does not use.
constexpr size_t kKeyBytes = crypto_aead_xchacha20poly1305_ietf_KEYBYTES;  // 32
constexpr size_t kSaltBytes = crypto_pwhash_SALTBYTES;                    // 16

// Buffer size for the bulk-mode measurements: large enough to amortize the
// per-call cost of the SDK entry point over many blocks, small enough to stay
// in L1/L2 on a phone.
constexpr size_t kBulkBytes = 4096;

std::string ToHex(const uint8_t* p, size_t n) {
    static const char* h = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        s.push_back(h[p[i] >> 4]);
        s.push_back(h[p[i] & 0xF]);
    }
    return s;
}

bool ParseHex16(const std::string& s, std::array<uint8_t, 16>& out) {
    if (s.size() != 32) return false;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (int i = 0; i < 16; ++i) {
        int hi = nib(s[2 * i]), lo = nib(s[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

int Usage() {
    std::fprintf(stderr,
                 "usage: wb_bench --blob FILE [--pass P] [--min-time MS] [--reps N]\n"
                 "                [--open-reps N] [--csv] [--label TAG] [--only M,...]\n"
                 "\n"
                 "  --blob FILE    sealed blob to benchmark (required; generate with\n"
                 "                 scripts/gen_blob.sh on the HOST, never on device)\n"
                 "  --pass P       blob passphrase (default: empty)\n"
                 "  --min-time MS  target duration of one timed batch (default 300)\n"
                 "  --reps N       timed batches per metric (default 7)\n"
                 "  --open-reps N  reps for wbc_open / the KDF (default 5)\n"
                 "  --csv          machine-readable output for scripts/bench_compare.sh\n"
                 "  --label TAG    tag echoed into the output (e.g. plain / omvll)\n"
                 "  --only LIST    comma-separated metric names to run (default: all).\n"
                 "                 e.g. --only open,kdf — for a second pass over a blob\n"
                 "                 sealed at a different KDF tier, where the\n"
                 "                 tier-independent metrics would just be repeated work.\n"
                 "                 An unknown name is an error, not a silent no-op.\n");
    return 2;
}

// Metric selection. Empty set = run everything, which is the default and what
// every existing caller gets.
std::set<std::string> g_only;
bool Want(const char* name) { return g_only.empty() || g_only.count(name) != 0; }

// Every metric name this binary can emit — used to reject a typo in --only
// rather than silently producing a CSV with a metric missing, which downstream
// would read as "that metric did not exist in this build".
const char* const kAllMetrics[] = {"vm_run",     "data_copy",    "encrypt_block",
                                   "wrap_key",   "unwrap_key",   "bulk_seal_4k",
                                   "open",       "kdf"};

}  // namespace

int main(int argc, char** argv) {
    std::string blob_path, pass, label = "unlabeled";
    double min_ms = 300.0;
    int reps = 7, open_reps = 5;
    bool csv = false;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&]() { return (i + 1 < argc) ? std::string(argv[++i]) : std::string(); };
        if (a == "--blob") blob_path = next();
        else if (a == "--pass") pass = next();
        else if (a == "--label") label = next();
        else if (a == "--min-time") min_ms = std::strtod(next().c_str(), nullptr);
        else if (a == "--reps") reps = std::atoi(next().c_str());
        else if (a == "--open-reps") open_reps = std::atoi(next().c_str());
        else if (a == "--csv") csv = true;
        else if (a == "--only") {
            std::string list = next();
            for (size_t p = 0; p < list.size();) {
                size_t c = list.find(',', p);
                if (c == std::string::npos) c = list.size();
                std::string m = list.substr(p, c - p);
                if (!m.empty()) g_only.insert(m);
                p = c + 1;
            }
            if (g_only.empty()) {
                std::fprintf(stderr, "--only needs at least one metric name\n");
                return Usage();
            }
        }
        else if (a == "-h" || a == "--help") return Usage();
        else { std::fprintf(stderr, "unknown arg: %s\n", a.c_str()); return Usage(); }
    }
    if (blob_path.empty()) return Usage();
    for (const std::string& m : g_only) {
        bool known = false;
        for (const char* k : kAllMetrics) if (m == k) { known = true; break; }
        if (!known) {
            std::fprintf(stderr, "wb_bench: --only: unknown metric '%s'. Known:", m.c_str());
            for (const char* k : kAllMetrics) std::fprintf(stderr, " %s", k);
            std::fprintf(stderr, "\n");
            return 2;
        }
    }
    if (reps < 1) reps = 1;
    if (open_reps < 1) open_reps = 1;
    if (min_ms < 1.0) min_ms = 1.0;

    // crypto_pwhash requires an initialized libsodium.
    if (sodium_init() < 0) {
        std::fprintf(stderr, "wb_bench: libsodium init failed\n");
        return 1;
    }

    std::ifstream f(blob_path, std::ios::binary);
    if (!f) {
        std::fprintf(stderr, "wb_bench: cannot read %s\n", blob_path.c_str());
        return 1;
    }
    std::vector<uint8_t> blob((std::istreambuf_iterator<char>(f)),
                              std::istreambuf_iterator<char>());
    if (blob.empty()) {
        std::fprintf(stderr, "wb_bench: %s is empty\n", blob_path.c_str());
        return 1;
    }

    // Which KDF this blob actually uses. Read from the header, so the `kdf`
    // metric below times the same derivation `open` pays for instead of a
    // hardcoded tier. A stale blob from an older format version fails here with
    // a clear message rather than as a confusing unseal failure.
    storage::KdfTier tier;
    if (!storage::PeekTier(blob.data(), blob.size(), tier)) {
        std::fprintf(stderr,
                     "wb_bench: %s is not a readable v4 WBTS blob (regenerate it "
                     "with scripts/gen_blob.sh)\n",
                     blob_path.c_str());
        return 1;
    }
    const storage::KdfParams kdf_params = storage::ParamsForTier(tier);

    // Internal path: unseal once into a vm::Program so vm::Run can be timed
    // directly, separately from the SDK wrapper around it.
    vm::Program prog;
    if (!storage::Unseal(blob, pass, prog)) {
        std::fprintf(stderr,
                     "wb_bench: cannot unseal %s (wrong --pass, or a blob from a "
                     "different build?)\n",
                     blob_path.c_str());
        return 1;
    }

    // Public path.
    wbc_ctx* ctx = nullptr;
    if (wbc_status s = wbc_open(blob.data(), blob.size(), pass.c_str(), &ctx); s != WBC_OK) {
        std::fprintf(stderr, "wb_bench: wbc_open failed: %s\n", wbc_strerror(s));
        return 1;
    }

    // ---- correctness gate --------------------------------------------------
    // Never report throughput for a build that computes the wrong answer: an
    // obfuscation pass that breaks the VM would otherwise look like a speedup.
    // The blob's key is unknown here, so the checks are key-agnostic (internal
    // path == public path, ECB == per-block, CTR round-trips). Cross-build
    // equivalence is covered by the `ct=` line, which bench_compare.sh asserts
    // is identical between the plain and obfuscated builds.
    std::array<uint8_t, 16> pt{};
    if (!ParseHex16("00112233445566778899aabbccddeeff", pt)) return 1;

    int gate_failures = 0;
    std::array<uint8_t, 16> ct_vm = vm::Run(prog, pt);
    uint8_t ct_sdk[16] = {0};
    if (wbc_encrypt_block(ctx, pt.data(), ct_sdk) != WBC_OK ||
        std::memcmp(ct_vm.data(), ct_sdk, 16) != 0) {
        std::fprintf(stderr, "wb_bench: GATE FAIL vm::Run != wbc_encrypt_block\n");
        ++gate_failures;
    }
    {   // The shipped data path: wrap a session key, unwrap it, get it back.
        uint8_t sk[WBC_SESSION_KEY_BYTES], sk2[WBC_SESSION_KEY_BYTES];
        uint8_t wrapped[WBC_WRAPPED_KEY_BYTES];
        if (wbc_random(sk, sizeof sk) != WBC_OK ||
            wbc_wrap_key(ctx, sk, wrapped) != WBC_OK ||
            wbc_unwrap_key(ctx, wrapped, sk2) != WBC_OK ||
            std::memcmp(sk, sk2, sizeof sk) != 0) {
            std::fprintf(stderr, "wb_bench: GATE FAIL wrap/unwrap does not round-trip\n");
            ++gate_failures;
        }
    }
    if (gate_failures) {
        std::fprintf(stderr,
                     "wb_bench: %d correctness failure(s) — refusing to report timings\n",
                     gate_failures);
        wbc_close(ctx);
        return 1;
    }

    // ---- measurements ------------------------------------------------------
    uint64_t sink = 0;  // folds every result so the work cannot be elided
    std::vector<Result> results;

    if (Want("vm_run")) {   // Interpreter alone. vm.cpp/handlers.cpp are the HOT tuple in
        // omvll_config.py: break_control_flow only, heavy passes excluded.
        std::array<uint8_t, 16> blk = pt;
        results.push_back(Measure("vm_run", min_ms, reps, 16, 0, true, sink, [&](uint64_t n) {
            uint64_t acc = 0;
            for (uint64_t i = 0; i < n; ++i) {
                blk[0] = static_cast<uint8_t>(i);  // vary input; defeats any CSE
                acc += vm::Run(prog, blk)[0];
            }
            return acc;
        }));
    }
    if (Want("data_copy")) {   // The DATA image copy vm::Run performs on EVERY block (ctx.data =
        // prog.data in vm.cpp). At data_len ~400 KB this is a large slice of
        // vm_run, and it is plain allocation + libc memmove, which O-MVLL never
        // touches — so it dilutes the interpreter's ratio towards 1.0x exactly as
        // Argon2id dilutes `open`. Same remedy: measure it, subtract it.
        //
        // NB: this copy is NOT dead weight to be optimized away — it is also the
        // per-block reset that defeats differential fault analysis. See the note
        // on vm::Run in src/vm/vm.h; two ways of removing it were measured and
        // both were rejected.
        results.push_back(
            Measure("data_copy", min_ms, reps, prog.data.size(), 0, true, sink, [&](uint64_t n) {
                uint64_t acc = 0;
                for (uint64_t i = 0; i < n; ++i) {
                    std::vector<uint8_t> d = prog.data;
                    acc += d.front() + d.back();
                }
                return acc;
            }));
    }
    if (Want("encrypt_block")) {   // Same work through the C ABI. wbcrypto.cpp is sensitive but NOT hot, so
        // this wrapper gets flatten_functions + obfuscate_constants +
        // obfuscate_struct_access. The delta against vm_run is the SDK-glue cost.
        uint8_t in[16], out[16];
        std::memcpy(in, pt.data(), 16);
        results.push_back(Measure("encrypt_block", min_ms, reps, 16, 0, true, sink, [&](uint64_t n) {
            uint64_t acc = 0;
            for (uint64_t i = 0; i < n; ++i) {
                in[0] = static_cast<uint8_t>(i);
                if (wbc_encrypt_block(ctx, in, out) != WBC_OK) return acc;
                acc += out[0];
            }
            return acc;
        }));
    }
    if (Want("wrap_key") || Want("unwrap_key")) {   // wrap_key: the ENTIRE white-box cost of a real use, and the only one that
        // matters — it is two blocks plus a random IV regardless of how big the
        // payload is. Not byte-rated on purpose: a MB/s figure over 32 bytes
        // would invite exactly the "so N MB takes N/rate" extrapolation that the
        // key-wrapping design exists to make wrong.
        uint8_t sk[WBC_SESSION_KEY_BYTES], wrapped[WBC_WRAPPED_KEY_BYTES];
        if (wbc_random(sk, sizeof sk) != WBC_OK) { wbc_close(ctx); return 1; }
        results.push_back(
            Measure("wrap_key", min_ms, reps, 0, 0, true, sink, [&](uint64_t n) {
                uint64_t acc = 0;
                for (uint64_t i = 0; i < n; ++i) {
                    sk[0] = static_cast<uint8_t>(i);
                    if (wbc_wrap_key(ctx, sk, wrapped) != WBC_OK) return acc;
                    acc += wrapped[0];
                }
                return acc;
            }));
        results.push_back(
            Measure("unwrap_key", min_ms, reps, 0, 0, true, sink, [&](uint64_t n) {
                uint64_t acc = 0;
                uint8_t out[WBC_SESSION_KEY_BYTES];
                for (uint64_t i = 0; i < n; ++i) {
                    wrapped[WBC_BLOCK_BYTES] = static_cast<uint8_t>(i);
                    if (wbc_unwrap_key(ctx, wrapped, out) != WBC_OK) return acc;
                    acc += out[0];
                }
                return acc;
            }));
    }
    if (Want("bulk_seal_4k")) {   // The other half of the only path: conventional AEAD over the payload.
        // This is what actually scales with data, and it is NOT white-box
        // protected — see the caveat in wbcrypto.h.
        uint8_t sk[WBC_SESSION_KEY_BYTES];
        if (wbc_random(sk, sizeof sk) != WBC_OK) { wbc_close(ctx); return 1; }
        std::vector<uint8_t> in(kBulkBytes), out(kBulkBytes + WBC_BULK_OVERHEAD);
        for (size_t i = 0; i < in.size(); ++i) in[i] = static_cast<uint8_t>(i);
        results.push_back(
            Measure("bulk_seal_4k", min_ms, reps, kBulkBytes, 0, true, sink, [&](uint64_t n) {
                uint64_t acc = 0;
                size_t out_len = 0;
                for (uint64_t i = 0; i < n; ++i) {
                    if (wbc_bulk_seal(sk, in.data(), in.size(), out.data(), &out_len) != WBC_OK)
                        return acc;
                    acc += out[0];
                }
                return acc;
            }));
        wbc_wipe(sk, sizeof sk);
    }
    if (Want("open")) {   // Cold gate path. trusted_storage.cpp gets the heaviest pass set
        // (flatten + MBA + opaque constants + string encoding). At the high tier
        // Argon2id dominates the wall clock and this number alone hides that
        // cost — hence the `kdf` line below and the `open - kdf` derivation. At
        // the `none` tier there is no KDF worth the name, so `open` IS the loader.
        results.push_back(Measure("open", min_ms, open_reps, 0, 1, true, sink, [&](uint64_t n) {
            uint64_t acc = 0;
            for (uint64_t i = 0; i < n; ++i) {
                wbc_ctx* c = nullptr;
                if (wbc_open(blob.data(), blob.size(), pass.c_str(), &c) != WBC_OK) return acc;
                acc += (c != nullptr);
                wbc_close(c);
            }
            return acc;
        }));
    }
    if (Want("kdf")) {   // The KDF alone, whichever one THIS blob's tier selects. Vendored
        // libsodium is not in _SENSITIVE_MODULES, so this is identical in both
        // builds and can be subtracted out to isolate the obfuscated loader.
        //
        // The metric is always emitted, under the same name at every tier, even
        // though the `none` tier's HKDF is microseconds. Do NOT skip it: the
        // noise floor in scripts/bench_compare.sh is
        // `min[open] - min[kdf]`, and awk reads a missing key as 0 — an absent
        // row would silently turn that into the whole of `open` and print a
        // confident, meaningless "loader work" figure.
        uint8_t salt[kSaltBytes] = {0};
        uint8_t key[kKeyBytes] = {0};
        results.push_back(Measure("kdf", min_ms, open_reps, 0, 1, true, sink, [&](uint64_t n) {
            uint64_t acc = 0;
            for (uint64_t i = 0; i < n; ++i) {
                salt[0] = static_cast<uint8_t>(i);
                if (tier == storage::KdfTier::kNone) {
                    uint8_t prk[crypto_kdf_hkdf_sha256_KEYBYTES];
                    if (crypto_kdf_hkdf_sha256_extract(
                            prk, salt, sizeof salt,
                            reinterpret_cast<const unsigned char*>(pass.data()),
                            pass.size()) != 0)
                        return acc;
                    // Same info string as storage::DeriveKey; the cost does not
                    // depend on its contents, only its presence.
                    if (crypto_kdf_hkdf_sha256_expand(key, sizeof key, "WBTS-v4-seal-key",
                                                      16, prk) != 0)
                        return acc;
                } else if (crypto_pwhash(key, sizeof key, pass.data(), pass.size(), salt,
                                         kdf_params.ops, kdf_params.mem,
                                         crypto_pwhash_ALG_ARGON2ID13) != 0) {
                    return acc;
                }
                acc += key[0];
            }
            return acc;
        }));
    }

    // NOTE: there is deliberately no large-payload pass here any more. The SDK
    // offers no way to push bulk data through the white-box (wbc_encrypt_ecb and
    // wbc_crypt_ctr were removed in 2.0.0), so "how long does 5 MB take?" is now
    // answered by wrap_key + bulk_seal_4k: a fixed ~0.5 ms of white-box work
    // plus conventional AEAD over the payload. examples/keywrap.c shows the
    // end-to-end number.

    // ---- report ------------------------------------------------------------
    const std::string ct_hex = ToHex(ct_vm.data(), 16);
    if (csv) {
        std::printf("# label=%s\n", label.c_str());
        std::printf("# ct=%s\n", ct_hex.c_str());
        // The tier decides what `open` and `kdf` mean, so it belongs next to the
        // ciphertext as part of "which blob produced these numbers".
        std::printf("# kdf_tier=%s\n", storage::TierName(tier));
        std::printf("# code_len=%zu\n", prog.code.size());
        std::printf("# data_len=%zu\n", prog.data.size());
        std::printf("# block_off=%u\n", prog.block_off);
        std::printf("# sink=%llu\n", static_cast<unsigned long long>(sink));
        // max_ns is carried so bench_compare.sh can compute the same noise floor
        // and refuse to report a difference smaller than the spread of its inputs.
        std::printf("metric,iters,median_ns,min_ns,max_ns,mb_s\n");
        for (const Result& r : results) {
            std::printf("%s,%llu,%.3f,%.3f,%.3f,%.4f\n", r.name.c_str(),
                        static_cast<unsigned long long>(r.iters), r.median_ns, r.min_ns, r.max_ns,
                        r.mb_s);
        }
        wbc_close(ctx);
        return 0;
    }

    std::printf("wb_bench (%s) — %s\n", label.c_str(), wbc_version());
    std::printf("  blob      : %s\n", blob_path.c_str());
    std::printf("  ct        : %s\n", ct_hex.c_str());
    if (tier == storage::KdfTier::kNone) {
        std::printf("  kdf tier  : %s (HKDF-SHA256 — `open` is essentially all loader)\n",
                    storage::TierName(tier));
    } else {
        std::printf("  kdf tier  : %s (Argon2id %zu MiB / %llu passes — expect it to "
                    "dominate `open`)\n",
                    storage::TierName(tier), kdf_params.mem / (1024 * 1024),
                    kdf_params.ops);
    }
    // data_len is a PER-BLOCK cost, not a one-off: vm::Run copies the whole DATA
    // image into the context on every block (see ctx.data = prog.data in vm.cpp).
    std::printf("  geometry  : code=%zu B  data=%zu B (copied per block)  block_off=%u\n",
                prog.code.size(), prog.data.size(), prog.block_off);
    std::printf("  sampling  : min-time=%.0f ms  reps=%d  open-reps=%d\n\n", min_ms, reps,
                open_reps);

    std::printf("  %-16s %12s %14s %14s %12s\n", "metric", "iters", "median", "min", "MB/s");
    std::printf("  %-16s %12s %14s %14s %12s\n", "----------------", "------------",
                "--------------", "--------------", "------------");
    for (const Result& r : results) {
        // Sub-microsecond block latencies read better in ns; open/KDF in ms.
        char med[32], mn[32];
        if (r.median_ns >= 1e6) {
            std::snprintf(med, sizeof med, "%.2f ms", r.median_ns / 1e6);
            std::snprintf(mn, sizeof mn, "%.2f ms", r.min_ns / 1e6);
        } else {
            std::snprintf(med, sizeof med, "%.0f ns", r.median_ns);
            std::snprintf(mn, sizeof mn, "%.0f ns", r.min_ns);
        }
        if (r.mb_s > 0) {
            std::printf("  %-16s %12llu %14s %14s %12.3f\n", r.name.c_str(),
                        static_cast<unsigned long long>(r.iters), med, mn, r.mb_s);
        } else {
            std::printf("  %-16s %12llu %14s %14s %12s\n", r.name.c_str(),
                        static_cast<unsigned long long>(r.iters), med, mn, "-");
        }
    }

    // ---- derived lines -----------------------------------------------------
    // Subtract the large unobfuscated costs that sit inside these metrics. Only
    // legitimate when the difference clears the measurement's own noise floor —
    // `open - kdf` does NOT (see below), so it is reported as an upper bound
    // instead of a value. Reporting a difference smaller than the spread of its
    // own inputs would be inventing precision; it can even come out negative.
    const Result* vm = nullptr;
    const Result* copy = nullptr;
    const Result* open = nullptr;
    const Result* kdf = nullptr;
    const Result* wrap = nullptr;
    const Result* seal = nullptr;
    for (const Result& r : results) {
        if (r.name == "vm_run") vm = &r;
        if (r.name == "data_copy") copy = &r;
        if (r.name == "open") open = &r;
        if (r.name == "kdf") kdf = &r;
        if (r.name == "wrap_key") wrap = &r;
        if (r.name == "bulk_seal_4k") seal = &r;
    }

    // Subtractions use min_ns, not median_ns: under additive noise (scheduler,
    // thermals, a neighbour process) min is the least-contaminated estimate of the
    // true cost. A difference is only reported when it clears 2x the one-sided
    // spread (median - min) of its inputs — max - min would let one slow outlier
    // set the floor.
    std::printf("\n  derived  (min-based; a difference must clear 2x the sampling spread)\n");
    if (vm && copy) {
        // Well-conditioned: the copy is a small, stable fraction of vm_run.
        std::printf("    vm_run - data_copy : %.0f ns  (dispatch + handlers alone; the "
                    "per-block\n",
                    vm->min_ns - copy->min_ns);
        std::printf("                         DATA copy is only %.1f%% of vm_run, so vm_run's "
                    "ratio\n",
                    100.0 * copy->min_ns / vm->min_ns);
        std::printf("                         really is the interpreter's own cost)\n");
    }
    // What a payload actually costs now: a FIXED white-box charge (the wrap) plus
    // conventional AEAD that scales. Printed as a per-MiB projection of the AEAD
    // half only, because the wrap does not grow with the payload — which is the
    // whole point of the design and the thing a reader must not get wrong.
    if (wrap && seal && seal->mb_s > 0) {
        const double aead_s_per_mib = 1.048576 / seal->mb_s;  // MiB / (MB/s)
        std::printf("    per payload        : %.2f ms fixed (wrap) + %.1f ms per MiB (AEAD)\n",
                    wrap->min_ns / 1e6, aead_s_per_mib * 1000.0);
        std::printf("                         The wrap is 2 white-box blocks whatever the\n");
        std::printf("                         payload size, so only the AEAD term scales.\n");
    }
    if (open && kdf) {
        const double diff = open->min_ns - kdf->min_ns;
        const double margin =
            2.0 * std::max(open->median_ns - open->min_ns, kdf->median_ns - kdf->min_ns);
        const char* kdf_name =
            tier == storage::KdfTier::kNone ? "HKDF" : "Argon2id";
        std::printf("    open - kdf         : ");
        if (diff > margin) {
            std::printf("%.2f ms  (loader work; %s is %.1f%% of open)\n", diff / 1e6, kdf_name,
                        100.0 * kdf->min_ns / open->min_ns);
            if (tier == storage::KdfTier::kNone) {
                // At this tier the KDF is microseconds, so the subtraction is
                // well-conditioned for the first time and `open` finally reports
                // the loader itself: the header parse and the ~400 KB AEAD
                // decrypt. That is the number to watch when tuning the loader —
                // it is unmeasurable at the Argon2id tiers.
                std::printf("                         At tier `none` this IS the loader: header "
                            "parse plus\n");
                std::printf("                         the %zu KB AEAD decrypt of the table bank.\n",
                            prog.data.size() / 1024);
            } else {
                // Clearing the margin is NOT enough to make this the loader at an
                // Argon2id tier. `open` and `kdf` each allocate and fault in a
                // 16/64 MiB arena in a different context, so the difference
                // carries an allocation artifact that no amount of sampling
                // removes -- measured here, it overstates the loader several-fold
                // against a tier-`none` run of the same blob geometry. Treat it as
                // an upper bound and get the real figure from --kdf light.
                std::printf("                         UPPER BOUND, not the loader: the two "
                            "measurements\n");
                std::printf("                         fault in the Argon2 arena differently. Re-seal "
                            "at\n");
                std::printf("                         --kdf light for the loader's real cost.\n");
            }
        } else {
            // The honest answer: the flattened + MBA'd loader in
            // trusted_storage.cpp is too cheap to resolve through a ~200 ms KDF.
            // Note this is ILL-CONDITIONED, not merely under-sampled: the signal
            // (a ~0.5 MB AEAD decrypt plus a header parse, well under a
            // millisecond) is orders of magnitude below the KDF's own run-to-run
            // variation, so more reps narrow the bound only slowly and never make
            // the difference trustworthy. The bound is the deliverable, and it is
            // the answer that matters: heavy passes here are affordable.
            std::printf("NOT RESOLVABLE (< %.2f ms)\n", margin / 1e6);
            std::printf("                         %s is ~%.1f%% of open. The difference "
                        "(%.2f ms) is\n",
                        kdf_name, 100.0 * kdf->min_ns / open->min_ns, diff / 1e6);
            std::printf("                         inside the sampling margin (%.2f ms), so it "
                        "is not a\n",
                        margin / 1e6);
            std::printf("                         measurement. What this DOES establish: the\n");
            std::printf("                         obfuscated loader costs under %.2f ms of the "
                        "%.0f ms\n",
                        margin / 1e6, open->min_ns / 1e6);
            std::printf("                         open — heavy passes on trusted_storage.cpp are\n");
            std::printf("                         affordable. Pin the CPU and quiet the machine "
                        "to\n");
            std::printf("                         tighten it; the gap is ill-conditioned, so do "
                        "not\n");
            std::printf("                         expect reps alone to resolve it.\n");
        }
    }
    std::printf("\n  (sink=%llu — printed so the optimizer cannot discard the work)\n",
                static_cast<unsigned long long>(sink));

    wbc_close(ctx);
    return 0;
}
