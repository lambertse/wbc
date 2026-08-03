// measure.h — the shared timing harness for the benchmarks in this directory.
//
// Extracted from wb_bench.cpp so wb_ladder.cpp can reuse it verbatim rather than
// growing a second, subtly-different copy: the calibration rule, the min/median
// choice and the anti-elision `sink` are all load-bearing for whether the
// numbers mean anything, and two copies would drift.
//
// ┌─ NAMING CONSTRAINT — read before adding a file to bench/ ──────────────────┐
// │ O-MVLL targeting in third_party/omvll/omvll_config.py matches module names  │
// │ by SUBSTRING:                                                              │
// │     return any(s in n for s in _SENSITIVE_MODULES)   # contains "vm.cpp"    │
// │ so any harness whose PATH contains "vm.cpp", "handlers.cpp",                │
// │ "assembler.cpp", "fwcrypt.cpp", "fw_schedule", "trusted_storage.cpp",       │
// │ "wbcrypto.cpp" or "wbcrypto_provision.cpp" gets obfuscation passes injected  │
// │ into its own TIMING LOOP — in the obfuscated build only — and starts         │
// │ measuring itself. scripts/bench_android.sh machine-checks this.             │
// └────────────────────────────────────────────────────────────────────────────┘
#ifndef WBVM_BENCH_MEASURE_H
#define WBVM_BENCH_MEASURE_H

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace bench {

using Clock = std::chrono::steady_clock;

struct Result {
    std::string name;
    uint64_t iters = 0;    // iterations per timed batch (from calibration)
    double median_ns = 0;  // per-iteration
    double min_ns = 0;
    double max_ns = 0;  // carried into the CSV so bench_compare.sh sees the spread
    double mb_s = 0;    // 0 when the metric is not byte-oriented
};

// Time `body` and report per-iteration cost.
//
// `body(n)` must perform n iterations of the work and return a value derived
// from the results; the return is folded into `sink` (printed by the caller) so
// the optimizer cannot discard the work.
//
// fixed_batch == 0 auto-calibrates the batch size until one batch exceeds
// min_ms, which lets the same binary produce stable numbers on a slow phone and
// a fast desktop. Pass a non-zero fixed_batch for operations too expensive to
// calibrate (wbc_open / the KDF: ~100ms each, 64 MiB of Argon2id arena).
// `warmup` applies only to the fixed_batch path. Leave it true for wbc_open / the
// KDF (see below). Set it FALSE for the multi-minute bulk metrics, where an extra
// untimed pass would literally double the wall clock for no benefit — their
// buffers are far too large for cache warming to matter, and no one-off arena
// cost applies.
template <typename F>
Result Measure(const std::string& name, double min_ms, int reps, size_t bytes_per_iter,
               uint64_t fixed_batch, bool warmup, uint64_t& sink, F&& body) {
    uint64_t batch = fixed_batch ? fixed_batch : 1;
    if (!fixed_batch) {
        for (;;) {
            auto t0 = Clock::now();
            sink += body(batch);
            double ms = std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
            if (ms >= min_ms || batch >= (1ull << 34)) break;
            // Aim just past the target rather than doubling blindly; clamp the
            // growth so a near-zero first sample can't overshoot wildly.
            double factor = (ms > 1e-6) ? (min_ms / ms) * 1.2 : 8.0;
            if (factor < 2.0) factor = 2.0;
            if (factor > 64.0) factor = 64.0;
            batch = static_cast<uint64_t>(static_cast<double>(batch) * factor) + 1;
        }
    } else if (warmup) {
        // Fixed-batch metrics skip calibration, so without this the FIRST timed
        // rep pays one-off costs the others don't — for Argon2id, faulting in a
        // cold 64 MiB arena, which inflated the observed spread to ~35% and made
        // the `open - kdf` noise floor uselessly wide. The calibrated path is
        // already warmed by its calibration loop.
        sink += body(batch);
    }

    std::vector<double> per_iter;
    per_iter.reserve(static_cast<size_t>(reps));
    for (int r = 0; r < reps; ++r) {
        auto t0 = Clock::now();
        sink += body(batch);
        double ns = std::chrono::duration<double, std::nano>(Clock::now() - t0).count();
        per_iter.push_back(ns / static_cast<double>(batch));
    }
    std::sort(per_iter.begin(), per_iter.end());

    Result res;
    res.name = name;
    res.iters = batch;
    res.median_ns = per_iter[per_iter.size() / 2];
    res.min_ns = per_iter.front();
    res.max_ns = per_iter.back();
    // bytes/ns * 1000 == MB/s (MB = 1e6 bytes).
    res.mb_s = (bytes_per_iter && res.median_ns > 0)
                   ? (static_cast<double>(bytes_per_iter) / res.median_ns) * 1000.0
                   : 0.0;
    return res;
}

}  // namespace bench

#endif  // WBVM_BENCH_MEASURE_H
