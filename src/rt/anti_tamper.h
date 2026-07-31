// anti_tamper.h — layered anti-DBI / anti-tamper for the white-box runtime.
//
// STATUS: [unverified-here] Android/Linux code-drop. It is NOT wired into the
// default (host-verified) build; integrate it on the NDK build and validate on
// a real device — see docs/ANTI-TAMPER.md. Every check here is individually
// bypassable; the value comes from combining MANY cheap checks with the O-MVLL
// obfuscation (obfuscation/omvll_config.py) so that removing them is tedious,
// not from any single check.
//
// Design rules (from the hardening handover, P3):
//   * No single checkable boolean and no single choke point.
//   * On detection, DEGRADE SILENTLY — feed a wrong value into key derivation so
//     the cipher produces wrong output — rather than exit() at an obvious site.
#ifndef WBVM_RT_ANTI_TAMPER_H
#define WBVM_RT_ANTI_TAMPER_H

#include <cstddef>
#include <cstdint>

namespace rt {

// Bit flags for which checks tripped (returned by DetectInstrumentation).
enum : uint64_t {
    kTracerPresent   = 1ull << 0,  // /proc/self/status TracerPid != 0
    kDbiMapping      = 1ull << 1,  // frida/gum/gadget mapping in /proc/self/maps
    kPtraceBlocked   = 1ull << 2,  // PTRACE_TRACEME self-attach failed (already traced)
    kTimingAnomaly   = 1ull << 3,  // hot-path timing probe way over budget
};

// Run the layered environment checks. Returns 0 when the environment looks
// clean, or a non-zero OR of the flags above. Spread calls across the code base
// and combine results; do not gate one branch on one call.
uint64_t DetectInstrumentation();

// FNV-1a over a span of mapped code. Intended for a self-integrity check: hash a
// critical .text span at runtime and compare against a value baked in at build
// time; mismatch means the code was patched. Returns 0 for a null/empty span.
uint64_t TextChecksum(const void* start, size_t len);

// Fold the checks into a "degradation mask": 0 when the environment is clean and
// the code span matches `expected_text_hash`, otherwise a value derived from
// what tripped. Mix this into the seal/KDF key material (e.g. XOR into the
// passphrase-derived input) so a hooked or patched process silently derives the
// wrong key and produces wrong ciphertext — never a clean, NOP-able branch.
uint64_t DegradationMask(const void* text_start, size_t text_len,
                         uint64_t expected_text_hash);

}  // namespace rt

#endif  // WBVM_RT_ANTI_TAMPER_H
