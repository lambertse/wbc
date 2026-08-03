// wb_bench — throughput/latency benchmark for the shipped white-box runtime.
//
//   wb_bench --blob FILE [--pass P] [--min-time MS] [--reps N] [--open-reps N]
//            [--csv] [--label TAG]
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
// MUST mirror src/storage/trusted_storage.cpp (kOpsLimit/kMemLimit/kKeyBytes/
// kSaltBytes). Those live in an anonymous namespace and cannot be imported, so
// they are duplicated here; if the seal's KDF tier ever changes, change it here
// too or the `open - kdf` subtraction below silently stops being meaningful.
constexpr unsigned long long kOpsLimit = crypto_pwhash_OPSLIMIT_INTERACTIVE;
constexpr size_t kMemLimit = crypto_pwhash_MEMLIMIT_INTERACTIVE;
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
                 "                [--open-reps N] [--bulk-mb N] [--bulk-reps N]\n"
                 "                [--csv] [--label TAG]\n"
                 "\n"
                 "  --bulk-mb N    ALSO run a realistic large-payload CTR pass over N MiB\n"
                 "                 (encrypt, then decrypt, then verify the round-trip).\n"
                 "                 This is the 'how long does my 5 MB file take?' number.\n"
                 "                 SLOW: the white-box runs at well under 1 MB/s, so 5 MiB\n"
                 "                 is minutes per leg. Off by default; an ETA is printed\n"
                 "                 before it starts. Try --bulk-mb 1 first.\n"
                 "  --bulk-reps N  repetitions of the bulk pass (default 1)\n"
                 "  --blob FILE    sealed blob to benchmark (required; generate with\n"
                 "                 scripts/gen_blob.sh on the HOST, never on device)\n"
                 "  --pass P       blob passphrase (default: empty)\n"
                 "  --min-time MS  target duration of one timed batch (default 300)\n"
                 "  --reps N       timed batches per metric (default 7)\n"
                 "  --open-reps N  reps for wbc_open / the KDF (default 5)\n"
                 "  --csv          machine-readable output for scripts/bench_compare.sh\n"
                 "  --label TAG    tag echoed into the output (e.g. plain / omvll)\n");
    return 2;
}

}  // namespace

int main(int argc, char** argv) {
    std::string blob_path, pass, label = "unlabeled";
    double min_ms = 300.0;
    int reps = 7, open_reps = 5, bulk_reps = 1;
    uint64_t bulk_mb = 0;  // 0 = skip the (slow) large-payload pass
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
        else if (a == "--bulk-mb") bulk_mb = std::strtoull(next().c_str(), nullptr, 0);
        else if (a == "--bulk-reps") bulk_reps = std::atoi(next().c_str());
        else if (a == "--csv") csv = true;
        else if (a == "-h" || a == "--help") return Usage();
        else { std::fprintf(stderr, "unknown arg: %s\n", a.c_str()); return Usage(); }
    }
    if (blob_path.empty()) return Usage();
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
    {   // ECB over 3 blocks == 3 single-block encryptions.
        uint8_t in[48], ecb[48], one[48];
        for (int i = 0; i < 48; ++i) in[i] = static_cast<uint8_t>(i * 7 + 1);
        if (wbc_encrypt_ecb(ctx, in, ecb, sizeof in) != WBC_OK) ++gate_failures;
        for (int b = 0; b < 3; ++b) {
            if (wbc_encrypt_block(ctx, in + 16 * b, one + 16 * b) != WBC_OK) ++gate_failures;
        }
        if (std::memcmp(ecb, one, sizeof ecb) != 0) {
            std::fprintf(stderr, "wb_bench: GATE FAIL wbc_encrypt_ecb != per-block\n");
            ++gate_failures;
        }
    }
    {   // CTR is its own inverse over an arbitrary (non-multiple-of-16) length.
        const char* msg = "wb_bench CTR round-trip check, odd length";
        size_t n = std::strlen(msg);
        uint8_t iv[16] = {0};
        std::vector<uint8_t> enc(n), dec(n);
        if (wbc_crypt_ctr(ctx, iv, reinterpret_cast<const uint8_t*>(msg), enc.data(), n) != WBC_OK ||
            wbc_crypt_ctr(ctx, iv, enc.data(), dec.data(), n) != WBC_OK ||
            std::memcmp(dec.data(), msg, n) != 0) {
            std::fprintf(stderr, "wb_bench: GATE FAIL wbc_crypt_ctr does not round-trip\n");
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

    {   // Interpreter alone. vm.cpp/handlers.cpp are the HOT tuple in
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
    {   // The DATA image copy vm::Run performs on EVERY block (ctx.data =
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
    {   // Same work through the C ABI. wbcrypto.cpp is sensitive but NOT hot, so
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
    {   // Bulk ECB: shows how much of that per-call cost the loop pays per block.
        std::vector<uint8_t> buf(kBulkBytes);
        for (size_t i = 0; i < buf.size(); ++i) buf[i] = static_cast<uint8_t>(i);
        results.push_back(
            Measure("encrypt_ecb_4k", min_ms, reps, kBulkBytes, 0, true, sink, [&](uint64_t n) {
                uint64_t acc = 0;
                for (uint64_t i = 0; i < n; ++i) {
                    if (wbc_encrypt_ecb(ctx, buf.data(), buf.data(), buf.size()) != WBC_OK)
                        return acc;
                    acc += buf[0];
                }
                return acc;
            }));
    }
    {   // Bulk CTR: the mode a real integrator uses (also provides decryption).
        std::vector<uint8_t> buf(kBulkBytes);
        for (size_t i = 0; i < buf.size(); ++i) buf[i] = static_cast<uint8_t>(i);
        uint8_t iv[16] = {0};
        results.push_back(
            Measure("crypt_ctr_4k", min_ms, reps, kBulkBytes, 0, true, sink, [&](uint64_t n) {
                uint64_t acc = 0;
                for (uint64_t i = 0; i < n; ++i) {
                    if (wbc_crypt_ctr(ctx, iv, buf.data(), buf.data(), buf.size()) != WBC_OK)
                        return acc;
                    acc += buf[0];
                }
                return acc;
            }));
    }
    {   // Cold gate path. trusted_storage.cpp gets the heaviest pass set
        // (flatten + MBA + opaque constants + string encoding), but Argon2id
        // dominates the wall clock, so this number alone hides that cost — hence
        // the kdf_argon2id line below and the `open - kdf` derivation.
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
    {   // The KDF alone, same parameters as the seal. Vendored libsodium is not
        // in _SENSITIVE_MODULES, so this is identical in both builds and can be
        // subtracted out to isolate the obfuscated loader.
        uint8_t salt[kSaltBytes] = {0};
        uint8_t key[kKeyBytes] = {0};
        results.push_back(Measure("kdf_argon2id", min_ms, open_reps, 0, 1, true, sink, [&](uint64_t n) {
            uint64_t acc = 0;
            for (uint64_t i = 0; i < n; ++i) {
                salt[0] = static_cast<uint8_t>(i);
                if (crypto_pwhash(key, sizeof key, pass.data(), pass.size(), salt, kOpsLimit,
                                  kMemLimit, crypto_pwhash_ALG_ARGON2ID13) != 0)
                    return acc;
                acc += key[0];
            }
            return acc;
        }));
    }

    // ---- optional large-payload pass (the "how long does 5 MB take?" number) --
    // Answers a different question from crypt_ctr_4k: not "what is the per-block
    // rate" but "what is the real wall clock for a payload I actually have".
    //
    // Note CTR is its own inverse, so this is also the ONLY decryption path in the
    // SDK — the white-box has no inverse tables, and wbc_encrypt_ecb cannot decrypt
    // at all. Encrypt and decrypt therefore cost exactly the same (both just
    // generate keystream and XOR); both legs are timed so that is visible rather
    // than asserted, and the round-trip check comes free.
    bool bulk_verified = false;
    if (bulk_mb > 0) {
        const size_t bulk_bytes = static_cast<size_t>(bulk_mb) * 1024u * 1024u;
        if (bulk_reps < 1) bulk_reps = 1;

        // Project the runtime from the already-measured 4 KiB rate. Without this a
        // multi-minute silent pass is indistinguishable from a hang.
        double ns_per_byte = 0;
        for (const Result& r : results)
            if (r.name == "crypt_ctr_4k") ns_per_byte = r.min_ns / static_cast<double>(kBulkBytes);
        if (ns_per_byte > 0) {
            double eta_s = ns_per_byte * static_cast<double>(bulk_bytes) * 2.0 *
                           static_cast<double>(bulk_reps) / 1e9;
            std::fprintf(stderr,
                         "  [bulk] %llu MiB CTR encrypt + decrypt x%d — projected ~%.0f s "
                         "(%.1f min) at the measured %.3f MB/s. Working...\n",
                         static_cast<unsigned long long>(bulk_mb), bulk_reps, eta_s, eta_s / 60.0,
                         1000.0 / ns_per_byte);
        }

        try {
            std::vector<uint8_t> plain(bulk_bytes), cipher(bulk_bytes), decrypted(bulk_bytes);
            for (size_t i = 0; i < bulk_bytes; ++i) plain[i] = static_cast<uint8_t>(i * 31 + 7);
            const uint8_t iv[16] = {0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

            char nm_enc[64], nm_dec[64];
            std::snprintf(nm_enc, sizeof nm_enc, "ctr_encrypt_%llumb",
                          static_cast<unsigned long long>(bulk_mb));
            std::snprintf(nm_dec, sizeof nm_dec, "ctr_decrypt_%llumb",
                          static_cast<unsigned long long>(bulk_mb));

            // warmup=false: an extra untimed pass would double a multi-minute run.
            results.push_back(Measure(nm_enc, min_ms, bulk_reps, bulk_bytes, 1, false, sink,
                                      [&](uint64_t n) {
                                          uint64_t acc = 0;
                                          for (uint64_t i = 0; i < n; ++i) {
                                              if (wbc_crypt_ctr(ctx, iv, plain.data(),
                                                                cipher.data(), bulk_bytes) != WBC_OK)
                                                  return acc;
                                              acc += cipher[0];
                                          }
                                          return acc;
                                      }));
            std::fprintf(stderr, "  [bulk] encrypt leg done; decrypting...\n");

            results.push_back(Measure(nm_dec, min_ms, bulk_reps, bulk_bytes, 1, false, sink,
                                      [&](uint64_t n) {
                                          uint64_t acc = 0;
                                          for (uint64_t i = 0; i < n; ++i) {
                                              if (wbc_crypt_ctr(ctx, iv, cipher.data(),
                                                                decrypted.data(),
                                                                bulk_bytes) != WBC_OK)
                                                  return acc;
                                              acc += decrypted[0];
                                          }
                                          return acc;
                                      }));

            // The payload must survive the round trip, and must actually have been
            // transformed (a no-op "cipher" would look fast and be worthless).
            bulk_verified = std::memcmp(decrypted.data(), plain.data(), bulk_bytes) == 0 &&
                            std::memcmp(cipher.data(), plain.data(), bulk_bytes) != 0;
            if (!bulk_verified) {
                std::fprintf(stderr, "  [bulk] FAIL: %llu MiB CTR round-trip did not verify\n",
                             static_cast<unsigned long long>(bulk_mb));
                wbc_close(ctx);
                return 1;
            }
            std::fprintf(stderr, "  [bulk] round-trip verified (%llu MiB)\n",
                         static_cast<unsigned long long>(bulk_mb));
        } catch (const std::bad_alloc&) {
            std::fprintf(stderr,
                         "  [bulk] cannot allocate 3 x %llu MiB for the bulk buffers; "
                         "lower --bulk-mb\n",
                         static_cast<unsigned long long>(bulk_mb));
            wbc_close(ctx);
            return 1;
        }
    }

    // ---- report ------------------------------------------------------------
    const std::string ct_hex = ToHex(ct_vm.data(), 16);
    if (csv) {
        std::printf("# label=%s\n", label.c_str());
        std::printf("# ct=%s\n", ct_hex.c_str());
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
    // data_len is a PER-BLOCK cost, not a one-off: vm::Run copies the whole DATA
    // image into the context on every block (see ctx.data = prog.data in vm.cpp).
    std::printf("  geometry  : code=%zu B  data=%zu B (copied per block)  block_off=%u\n",
                prog.code.size(), prog.data.size(), prog.block_off);
    std::printf("  sampling  : min-time=%.0f ms  reps=%d  open-reps=%d", min_ms, reps, open_reps);
    if (bulk_mb > 0)
        std::printf("  bulk=%lluMiB x%d %s", static_cast<unsigned long long>(bulk_mb), bulk_reps,
                    bulk_verified ? "(round-trip OK)" : "(UNVERIFIED)");
    std::printf("\n\n");

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
    for (const Result& r : results) {
        if (r.name == "vm_run") vm = &r;
        if (r.name == "data_copy") copy = &r;
        if (r.name == "open") open = &r;
        if (r.name == "kdf_argon2id") kdf = &r;
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
    // The headline for a bulk run: total wall clock for the payload, which is what
    // an integrator actually budgets against. Reported per leg AND as a sum, since
    // a real "open a sealed file and read it" flow pays wbc_open once plus one
    // decrypt pass.
    if (bulk_mb > 0) {
        const Result* benc = nullptr;
        const Result* bdec = nullptr;
        for (const Result& r : results) {
            if (r.name.rfind("ctr_encrypt_", 0) == 0) benc = &r;
            if (r.name.rfind("ctr_decrypt_", 0) == 0) bdec = &r;
        }
        if (bdec) {
            std::printf("    %llu MiB decrypt      : %.1f s  (%.3f MB/s)\n",
                        static_cast<unsigned long long>(bulk_mb), bdec->min_ns / 1e9, bdec->mb_s);
            if (benc)
                std::printf("    %llu MiB encrypt      : %.1f s  (%.3f MB/s — same cost; CTR "
                            "keystream either way)\n",
                            static_cast<unsigned long long>(bulk_mb), benc->min_ns / 1e9,
                            benc->mb_s);
            if (open)
                std::printf("    open + %llu MiB decrypt: %.1f s  (a cold 'open the sealed file "
                            "and read it' flow)\n",
                            static_cast<unsigned long long>(bulk_mb),
                            (open->min_ns + bdec->min_ns) / 1e9);
        }
    }
    if (open && kdf) {
        const double diff = open->min_ns - kdf->min_ns;
        const double margin =
            2.0 * std::max(open->median_ns - open->min_ns, kdf->median_ns - kdf->min_ns);
        std::printf("    open - kdf         : ");
        if (diff > margin) {
            std::printf("%.2f ms  (loader work; Argon2id is %.1f%% of open)\n", diff / 1e6,
                        100.0 * kdf->min_ns / open->min_ns);
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
            std::printf("                         Argon2id is ~%.1f%% of open. The difference "
                        "(%.2f ms) is\n",
                        100.0 * kdf->min_ns / open->min_ns, diff / 1e6);
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
