// device_binding.cpp — see device_binding.h. [unverified-here]
//
// Portable stub. The real implementation lives behind JNI on Android and is
// provided by the field integrator; keeping it a stub here lets the contract be
// compiled/reviewed in the dev environment without an Android runtime.
#include "rt/device_binding.h"

#include <cstring>

namespace rt {

bool DeviceKeyMaterial(const char* /*alias*/, uint8_t out[32]) {
    // No secure element available in this build: zero the buffer and report
    // failure so callers fall back to passphrase-only derivation. The Android
    // build replaces this TU with a JNI-backed implementation.
    std::memset(out, 0, 32);
    return false;
}

}  // namespace rt
