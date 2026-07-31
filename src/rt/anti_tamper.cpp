// anti_tamper.cpp — see anti_tamper.h. [unverified-here] Android/Linux drop.
//
// On non-Linux hosts everything compiles to conservative no-ops so the file is
// syntactically checkable in the dev environment; the real checks are the Linux
// path exercised on-device.
#include "rt/anti_tamper.h"

#include <cstring>

#if defined(__linux__)
#  include <fcntl.h>
#  include <sys/ptrace.h>
#  include <time.h>
#  include <unistd.h>
#endif

namespace rt {

namespace {

constexpr uint64_t kFnvOffset = 1469598103934665603ull;
constexpr uint64_t kFnvPrime = 1099511628211ull;

uint64_t Fnv1a(const uint8_t* p, size_t n, uint64_t h = kFnvOffset) {
    for (size_t i = 0; i < n; ++i) { h ^= p[i]; h *= kFnvPrime; }
    return h;
}

#if defined(__linux__)

// Read a small file into buf without stdio (avoids buffering/hook surface).
ssize_t ReadAll(const char* path, char* buf, size_t cap) {
    int fd = ::open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    size_t off = 0;
    for (;;) {
        ssize_t r = ::read(fd, buf + off, cap - off);
        if (r < 0) { ::close(fd); return -1; }
        if (r == 0) break;
        off += static_cast<size_t>(r);
        if (off >= cap) break;
    }
    ::close(fd);
    return static_cast<ssize_t>(off);
}

bool TracerAttached() {
    char buf[4096];
    ssize_t n = ReadAll("/proc/self/status", buf, sizeof buf - 1);
    if (n <= 0) return false;
    buf[n] = '\0';
    const char* p = std::strstr(buf, "TracerPid:");
    if (!p) return false;
    p += 10;
    while (*p == ' ' || *p == '\t') ++p;
    return *p != '0';  // any non-zero tracer pid
}

bool DbiMappingPresent() {
    // Scan the mapping list for the tell-tale names of common instrumentation
    // frameworks. Cheap and easily defeated alone; one of many layers.
    static const char* kNeedles[] = {"frida", "gum-js-loop", "gadget",
                                      "linjector", "/re.frida.", "libgadget"};
    int fd = ::open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    char buf[8192];
    ssize_t r;
    bool hit = false;
    // Read in chunks; needles are short so a per-chunk scan is adequate for a
    // defense-in-depth signal (a name split across a boundary just misses once).
    while (!hit && (r = ::read(fd, buf, sizeof buf - 1)) > 0) {
        buf[r] = '\0';
        for (const char* nd : kNeedles)
            if (std::strstr(buf, nd)) { hit = true; break; }
    }
    ::close(fd);
    return hit;
}

bool PtraceSelfAttachBlocked() {
    // If a debugger is already attached, PTRACE_TRACEME fails with EPERM.
    // (Best-effort; on some sandboxes ptrace is unavailable — treat failure as
    // "not conclusively clean" only in combination with other signals.)
    long rc = ::ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
    if (rc == 0) {
        ::ptrace(PTRACE_DETACH, 0, nullptr, nullptr);
        return false;  // we could trace ourselves -> no other tracer
    }
    return true;
}

uint64_t NowNs() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1000000000ull +
           static_cast<uint64_t>(ts.tv_nsec);
}

bool TimingAnomaly() {
    // A tight loop that should take well under the threshold natively; single-
    // stepping / heavy instrumentation blows the budget. Threshold is generous
    // to avoid false positives on cold/slow devices — tune per target.
    volatile uint64_t acc = 0;
    uint64_t t0 = NowNs();
    for (int i = 0; i < 20000; ++i) acc += (acc ^ static_cast<uint64_t>(i)) * 2654435761ull;
    uint64_t dt = NowNs() - t0;
    (void)acc;
    return dt > 5000000ull;  // 5 ms for ~20k trivial iterations => anomalous
}

#endif  // __linux__

}  // namespace

uint64_t DetectInstrumentation() {
    uint64_t flags = 0;
#if defined(__linux__)
    if (TracerAttached())          flags |= kTracerPresent;
    if (DbiMappingPresent())       flags |= kDbiMapping;
    if (PtraceSelfAttachBlocked()) flags |= kPtraceBlocked;
    if (TimingAnomaly())           flags |= kTimingAnomaly;
#endif
    return flags;
}

uint64_t TextChecksum(const void* start, size_t len) {
    if (!start || len == 0) return 0;
    return Fnv1a(static_cast<const uint8_t*>(start), len);
}

uint64_t DegradationMask(const void* text_start, size_t text_len,
                         uint64_t expected_text_hash) {
    uint64_t flags = DetectInstrumentation();
    uint64_t text = TextChecksum(text_start, text_len);
    // 0 iff the environment is clean AND the code span is intact. Otherwise a
    // value that differs from 0 in a way derived from which signal tripped, so
    // mixing it into key derivation yields a wrong (but deterministic-per-fault)
    // key rather than an obvious branch.
    uint64_t text_delta = text ^ expected_text_hash;  // 0 when intact
    uint64_t mask = flags;
    if (flags) mask = Fnv1a(reinterpret_cast<const uint8_t*>(&flags), sizeof flags);
    return mask ^ text_delta;
}

}  // namespace rt
