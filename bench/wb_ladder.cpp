// wb_ladder — attribution: WHERE does the white-box's ~330 us per block go?
//
//   wb_ladder [--min-time MS] [--reps N] [--seed N] [--csv] [--label TAG]
//
// wb_bench measures the shipped runtime and answers "how fast is it" and "what
// does O-MVLL cost". It cannot answer "what is the cost MADE OF", because it only
// ever sees the fully-assembled VM. That question decides where optimization
// effort is worth spending, so it needs its own harness.
//
// Three rungs, same machine, same flags, each strictly containing the one above:
//
//   1. aes_ref        plain textbook AES-128            — the floor
//   2. wb_interp      the same round function as a Chow table network
//   3. vm::Run        that network compiled to obfuscated VM bytecode
//
// 1->2 is the cost of white-boxing (arithmetic becomes ~1,168 table lookups).
// 2->3 is the cost of the VM: interpreting ~13k bytecode instructions AND
// decrypting all ~58k of their bytes at fetch with a per-byte splitmix64.
//
// Unlike wb_bench this needs NO blob and NO passphrase: it generates its own
// white-box from a known key, so there is no Argon2id in the loop and nothing to
// provision first. It therefore links the PROVISIONING set (aes_ref, wb_interp,
// wb_generator, assembler), which is exactly why it is a separate binary —
// wb_bench deliberately links the runtime only so it can never time the
// provisioning surface.
//
// ┌─ NAMING CONSTRAINT ────────────────────────────────────────────────────────┐
// │ O-MVLL's config matches module names by SUBSTRING, so a harness whose path  │
// │ contains "vm.cpp", "handlers.cpp", "assembler.cpp", "fwcrypt.cpp",          │
// │ "fw_schedule", "trusted_storage.cpp", "wbcrypto.cpp" or                     │
// │ "wbcrypto_provision.cpp" would get obfuscation injected into its own timing  │
// │ loop in the obfuscated build. "wb_ladder.cpp" is clear of all of them; see   │
// │ bench/measure.h and scripts/bench_android.sh (which machine-checks it).      │
// └────────────────────────────────────────────────────────────────────────────┘
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "fw/fw_schedule.h"
#include "measure.h"
#include "vm/assembler.h"
#include "vm/handlers.h"
#include "vm/vm.h"
#include "wbaes/aes_ref.h"
#include "wbaes/wb_generator.h"
#include "wbaes/wb_interp.h"

namespace {

using bench::Measure;
using bench::Result;

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

int Usage() {
    std::fprintf(stderr,
                 "usage: wb_ladder [--min-time MS] [--reps N] [--seed N]\n"
                 "                 [--csv] [--label TAG]\n");
    return 2;
}

// Instruction/byte counts for the shipped program, so the per-instruction and
// per-fetched-byte costs can be reported rather than estimated. Counted by
// running the real dispatcher, not predicted from the emitter.
struct CodeStats {
    uint64_t instrs = 0;  // executed VM instructions per block
    uint64_t bytes = 0;   // decoded code bytes fetched per block
    bool valid = false;   // false => this mirror has drifted; do not report
};

// Counts instructions and fetched bytes for one block.
//
// This necessarily MIRRORS the dispatcher in vm.cpp (which reports nothing and
// should not grow a counter just for a benchmark), and a silent copy would drift
// the moment that loop changes. So it is self-validating: it also produces the
// output block, and the caller compares that against vm::Run. If the two ever
// disagree, the mirror is stale and the derived per-instruction figures are
// suppressed instead of being quietly wrong.
CodeStats CountProgram(const vm::Program& prog, const wbaes::Block& in,
                       std::array<uint8_t, 16>& out) {
    CodeStats st;
    vm::VMContext ctx;
    ctx.prog = &prog;
    ctx.data = prog.data;
    ctx.vip = 0;
    ctx.eff_root = prog.fw_root ^ fw::InterpFingerprint(prog.op_to_phys);
    ctx.key_reg = ctx.eff_root;
    for (int i = 0; i < 16; ++i) ctx.data[prog.block_off + i] = in[i];

    const auto& handlers = vm::Handlers();
    while (!ctx.halted && st.instrs < 100'000'000) {
        uint32_t ip = static_cast<uint32_t>(ctx.vip);
        ctx.ks = wbaes::Rng(fw::PrfSeed(ctx.eff_root, ctx.key_reg, ip));
        ctx.fold = fw::FoldInit();
        size_t before = ctx.vip;
        uint8_t phys = vm::FetchByte(ctx);
        if (ctx.halted) break;
        uint8_t logical = prog.phys_to_op[phys];
        if (logical >= vm::kOpCount || handlers[logical] == nullptr) break;
        handlers[logical](ctx);
        ctx.key_reg = fw::UpdateKeyReg(ctx.key_reg, ctx.fold, ip);
        // vip advances by the instruction's length, except on a taken jump where
        // the delta is meaningless. Count forward steps only.
        if (ctx.vip > before) st.bytes += ctx.vip - before;
        ++st.instrs;
    }
    for (int i = 0; i < 16; ++i) out[i] = ctx.data[prog.block_off + i];
    st.valid = true;
    return st;
}

void PrintHuman(const std::vector<Result>& rs, const CodeStats& st, const char* label,
                double min_ms, int reps, uint64_t seed, const std::string& ct,
                size_t code_len, uint64_t sink) {
    std::printf("wb_ladder (%s) — attribution ladder\n", label);
    std::printf("  seed      : %llu (self-generated white-box; no blob, no KDF)\n",
                (unsigned long long)seed);
    std::printf("  ct        : %s  (FIPS-197 vector, identical on all three rungs)\n",
                ct.c_str());
    if (st.valid) {
        std::printf("  program   : code=%zu B  %llu instr/block  %llu code bytes fetched/block\n",
                    code_len, (unsigned long long)st.instrs, (unsigned long long)st.bytes);
    } else {
        std::printf("  program   : code=%zu B  (instruction count unavailable — see warning)\n",
                    code_len);
    }
    std::printf("  sampling  : min-time=%.0f ms  reps=%d\n\n", min_ms, reps);

    std::printf("  %-18s %14s %14s %12s\n", "rung", "median", "min", "MB/s");
    std::printf("  %-18s %14s %14s %12s\n", "------------------", "--------------",
                "--------------", "------------");
    for (const auto& r : rs) {
        char med[32], mn[32];
        auto fmt = [](char* buf, size_t n, double ns) {
            if (ns >= 1e6) std::snprintf(buf, n, "%.2f ms", ns / 1e6);
            else           std::snprintf(buf, n, "%.0f ns", ns);
        };
        fmt(med, sizeof med, r.median_ns);
        fmt(mn, sizeof mn, r.min_ns);
        std::printf("  %-18s %14s %14s %12.3f\n", r.name.c_str(), med, mn, r.mb_s);
    }

    // Ratios are min-based: under additive noise the minimum is the
    // least-contaminated estimate of the true cost.
    const Result* tot = nullptr;
    const Result* kex = nullptr;
    const Result* net = nullptr;
    const Result* vmr = nullptr;
    for (const auto& r : rs) {
        if (r.name == "aes_ref_total") tot = &r;
        else if (r.name == "aes_keyexpand") kex = &r;
        else if (r.name == "wb_interp") net = &r;
        else if (r.name == "vm_run") vmr = &r;
    }
    if (!tot || !kex || !net || !vmr) return;

    // The comparable floor: AES encryption with the key schedule already done,
    // which is the state the white-box tables are always in.
    const double aes_only = tot->min_ns - kex->min_ns;

    std::printf("\n  attribution (min-based)\n");
    std::printf("    aes_ref (encrypt-only) : %.0f ns  (%.0f total - %.0f key schedule)\n",
                aes_only, tot->min_ns, kex->min_ns);
    if (aes_only <= 0) {
        std::printf("    WARNING: the key-schedule subtraction went non-positive; treat the\n");
        std::printf("             ratio below as unavailable.\n");
        return;
    }
    std::printf("    white-boxing   : %6.2fx vs aes_ref  (%.0f ns -> %.0f ns)\n",
                net->min_ns / aes_only, aes_only, net->min_ns);
    if (net->min_ns < aes_only) {
        std::printf("                     NOT A SPEEDUP FROM WHITE-BOXING, and not a usable\n");
        std::printf("                     floor: src/wbaes/aes_ref.h says aes_ref is a\n");
        std::printf("                     correctness oracle, 'intentionally simple and not\n");
        std::printf("                     constant-time / not for production'. Byte-at-a-time\n");
        std::printf("                     SubBytes and GF-multiply MixColumns lose to 1168\n");
        std::printf("                     cache-resident table lookups. A PRODUCTION AES\n");
        std::printf("                     (AES-NI / ARMv8 crypto ext) is single-digit ns per\n");
        std::printf("                     block, so the true cost of white-boxing is a large\n");
        std::printf("                     multiple, not a discount. This repo has no such\n");
        std::printf("                     implementation, so that figure is NOT measured here\n");
        std::printf("                     and this rung must not be quoted as one.\n");
    } else {
        std::printf("                     arithmetic replaced by ~1168 table lookups in a\n");
        std::printf("                     ~400 KB bank; unavoidable for a Chow construction.\n");
    }
    std::printf("    VM on top      : %6.1fx over the table network  (%.0f ns -> %.0f ns)\n",
                vmr->min_ns / net->min_ns, net->min_ns, vmr->min_ns);
    if (st.valid) {
        std::printf("                     interpreting %llu instr + decrypting %llu code bytes\n",
                    (unsigned long long)st.instrs, (unsigned long long)st.bytes);
    }
    std::printf("                     with a splitmix64 per byte. THIS is the obfuscation.\n");
    std::printf("    total          : %6.1fx vs aes_ref (same caveat as above)\n",
                vmr->min_ns / aes_only);
    if (st.valid && st.instrs) {
        std::printf("\n    per VM instruction : %6.1f ns   (%.0f ns / %llu instr)\n",
                    vmr->min_ns / (double)st.instrs, vmr->min_ns,
                    (unsigned long long)st.instrs);
    }
    if (st.valid && st.bytes) {
        std::printf("    per fetched byte   : %6.1f ns   (each pays one splitmix64 + a fold)\n",
                    vmr->min_ns / (double)st.bytes);
    }
    std::printf(
        "\n  Read this as a budget. The actionable number is the VM term (%.0fx above),\n"
        "  on top of the table network — that is where essentially all of the per-block\n"
        "  cost lives. Within it the decode chain is serial, so it is latency-bound (-O3\n",
        vmr->min_ns / net->min_ns);
    std::printf(
        "  measures the same as -O2): removing instructions helps, making the existing\n"
        "  ones individually cheaper mostly does not, and removing the DECODE would\n"
        "  help most and is exactly what must not be removed.\n"
        "\n  The aes_ref rung is a correctness oracle, not a performance baseline —\n"
        "  see the caveat above before quoting any 'cost of white-boxing' figure.\n");
    std::printf("\n  (sink=%llu — printed so the optimizer cannot discard the work)\n",
                (unsigned long long)sink);
}

void PrintCsv(const std::vector<Result>& rs, const CodeStats& st, const char* label,
              const std::string& ct, size_t code_len, uint64_t sink) {
    std::printf("# label=%s\n# ct=%s\n# code_len=%zu\n# instrs=%llu\n# code_bytes=%llu\n"
                "# sink=%llu\n",
                label, ct.c_str(), code_len, (unsigned long long)st.instrs,
                (unsigned long long)st.bytes, (unsigned long long)sink);
    std::printf("metric,iters,median_ns,min_ns,max_ns,mb_s\n");
    for (const auto& r : rs) {
        std::printf("%s,%llu,%.3f,%.3f,%.3f,%.6f\n", r.name.c_str(),
                    (unsigned long long)r.iters, r.median_ns, r.min_ns, r.max_ns, r.mb_s);
    }
}

}  // namespace

int main(int argc, char** argv) {
    double min_ms = 300.0;
    int reps = 7;
    uint64_t seed = 42;
    bool csv = false;
    const char* label = "unlabeled";

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto need = [&](const char* what) -> const char* {
            if (i + 1 >= argc) { std::fprintf(stderr, "%s needs a value\n", what); std::exit(Usage()); }
            return argv[++i];
        };
        if (a == "--min-time") min_ms = std::atof(need("--min-time"));
        else if (a == "--reps") reps = std::atoi(need("--reps"));
        else if (a == "--seed") seed = std::strtoull(need("--seed"), nullptr, 0);
        else if (a == "--csv") csv = true;
        else if (a == "--label") label = need("--label");
        else return Usage();
    }
    if (reps < 1) reps = 1;

    // FIPS-197 C.1: the one key/plaintext pair whose answer is published, so all
    // three rungs can be checked against it rather than against each other.
    const wbaes::Key128 key = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                               0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    const wbaes::Block pt = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                             0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    const char* kFipsCt = "69c4e0d86a7b0430d8cdb78070b4c55a";

    auto wb = wbaes::GenerateWhiteBox(key, seed, wbaes::WBLevel::Internal);
    vm::Program prog = vm::AssembleWhiteBox(*wb, seed ^ 0x9999, vm::ObfOptions::All());

    // Correctness gate FIRST. A ladder whose rungs compute different functions
    // is comparing unrelated work, so refuse to print timings in that case.
    wbaes::Block a_ct = wbaes::AesEncryptBlock(pt, key);
    wbaes::Block n_ct = wbaes::WhiteBoxEncrypt(*wb, pt);
    auto v_out = vm::Run(prog, pt);
    wbaes::Block v_ct{};
    for (int i = 0; i < 16; ++i) v_ct[i] = v_out[i];

    int bad = 0;
    const std::string a_hex = ToHex(a_ct.data(), 16);
    if (a_hex != kFipsCt) { std::fprintf(stderr, "aes_ref != FIPS vector (%s)\n", a_hex.c_str()); ++bad; }
    if (n_ct != a_ct) { std::fprintf(stderr, "wb_interp != aes_ref\n"); ++bad; }
    if (v_ct != a_ct) { std::fprintf(stderr, "vm::Run != aes_ref\n"); ++bad; }
    if (bad) {
        std::fprintf(stderr, "%d correctness failure(s) — refusing to report timings\n", bad);
        return 1;
    }

    // Instruction/byte counts, with the mirror validated against the real
    // dispatcher's output before its numbers are trusted.
    std::array<uint8_t, 16> mirror_out{};
    CodeStats st = CountProgram(prog, pt, mirror_out);
    if (mirror_out != v_out) {
        std::fprintf(stderr,
                     "warning: the instruction counter no longer matches vm::Run — the\n"
                     "         dispatcher in src/vm/vm.cpp has changed and CountProgram in\n"
                     "         this file needs the same change. Suppressing per-instruction\n"
                     "         figures; the three rung timings below are unaffected.\n");
        st.valid = false;
    }

    uint64_t sink = 0;
    std::vector<Result> rs;

    // Every body varies its input per iteration so nothing can be hoisted or
    // common-subexpression-eliminated out of the loop.
    // aes_ref is the FLOOR rung, but AesEncryptBlock re-runs KeyExpansion on
    // every call (aes_ref.cpp:93) while the white-box has the key baked into its
    // tables and does no key setup at all. Timed naively, that per-call schedule
    // dominates the 10 rounds and makes the white-box look FASTER than plain AES
    // — measured here as 1507 ns vs 767 ns, i.e. a nonsensical "0.5x cost of
    // white-boxing". So measure the schedule separately and subtract it, giving a
    // floor that is comparable to the other two rungs: encrypt-only, key already
    // prepared. Both raw numbers are still reported so the correction is visible
    // rather than hidden.
    rs.push_back(Measure("aes_keyexpand", min_ms, reps, 0, 0, true, sink, [&](uint64_t n) {
        uint64_t acc = 0;
        wbaes::Key128 k = key;
        for (uint64_t i = 0; i < n; ++i) {
            k[0] = static_cast<uint8_t>(i);
            auto rk = wbaes::KeyExpansion(k);
            acc += rk[0] + rk[175];
        }
        return acc;
    }));

    rs.push_back(Measure("aes_ref_total", min_ms, reps, 16, 0, true, sink, [&](uint64_t n) {
        uint64_t acc = 0;
        wbaes::Block b = pt;
        for (uint64_t i = 0; i < n; ++i) {
            b[0] = static_cast<uint8_t>(i);
            wbaes::Block o = wbaes::AesEncryptBlock(b, key);
            acc += o[0];
        }
        return acc;
    }));

    rs.push_back(Measure("wb_interp", min_ms, reps, 16, 0, true, sink, [&](uint64_t n) {
        uint64_t acc = 0;
        wbaes::Block b = pt;
        for (uint64_t i = 0; i < n; ++i) {
            b[0] = static_cast<uint8_t>(i);
            wbaes::Block o = wbaes::WhiteBoxEncrypt(*wb, b);
            acc += o[0];
        }
        return acc;
    }));

    rs.push_back(Measure("vm_run", min_ms, reps, 16, 0, true, sink, [&](uint64_t n) {
        uint64_t acc = 0;
        std::array<uint8_t, 16> b{};
        std::memcpy(b.data(), pt.data(), 16);
        for (uint64_t i = 0; i < n; ++i) {
            b[0] = static_cast<uint8_t>(i);
            auto o = vm::Run(prog, b);
            acc += o[0];
        }
        return acc;
    }));

    if (csv) PrintCsv(rs, st, label, a_hex, prog.code.size(), sink);
    else PrintHuman(rs, st, label, min_ms, reps, seed, a_hex, prog.code.size(), sink);
    return 0;
}
