// device_binding.h — hardware-backed key binding for the seal. [unverified-here]
//
// STATUS: Android code-drop / contract stub. NOT wired into the default build or
// the current C ABI (which stays raw per the hardening decision). This defines
// how a field build should bind the sealed blob to the device so that stealing
// the blob + passphrase off-device is useless — the highest-value hardening item
// (handover P2.4). See docs/ANTI-TAMPER.md.
//
// Model: at provisioning time a random 32-byte "device secret" is generated and
// (a) wrapped/stored in the Android Keystore (StrongBox if available) as a
// non-exportable key, and (b) mixed into the seal KDF. At runtime the field app
// asks the Keystore to produce the same secret (or to unwrap a per-blob wrapping
// key); it never leaves the secure element in the clear. A blob provisioned for
// device A cannot be opened on device B because B's Keystore yields different
// material — defeating "steal the file + passphrase" without defeating the SE.
#ifndef WBVM_RT_DEVICE_BINDING_H
#define WBVM_RT_DEVICE_BINDING_H

#include <cstddef>
#include <cstdint>

namespace rt {

// Fill `out` (32 bytes) with hardware-bound key material for `alias`.
//
// Android implementation (JNI, not included here): call into a Java/Kotlin
// helper that uses AndroidKeyStore / StrongBox to derive or unwrap a
// non-exportable key bound to `alias` (e.g. HKDF over a Keystore HMAC, or
// unwrapping a per-install wrapping key). Return true on success.
//
// This stub returns false everywhere so callers fall back to passphrase-only
// derivation until the JNI bridge is provided. The intended integration is to
// mix the returned material into the seal KDF input (a new wbc_open variant that
// accepts extra key material), so a wrong/absent device secret silently yields
// the wrong AEAD key and the blob fails to open on the wrong device.
bool DeviceKeyMaterial(const char* alias, uint8_t out[32]);

}  // namespace rt

#endif  // WBVM_RT_DEVICE_BINDING_H
