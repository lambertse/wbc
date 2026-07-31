# omvll_config.py — TEMPLATE O-MVLL configuration for the White-box Crypto VM.
#
# O-MVLL (https://obfuscator.re/omvll) is an LLVM pass-plugin driven by this
# Python file. It obfuscates the *native machine code* of the interpreter and
# SDK — the layer this project ships as plain compiled C++.
#
# ┌─ IMPORTANT ────────────────────────────────────────────────────────────────┐
# │ The ObfuscationConfig API changes between O-MVLL releases. Treat this as a  │
# │ STARTING POINT and align the method names / return types with the version  │
# │ you installed (see the docs for your release). The targeting logic         │
# │ (_sensitive) is what you'll actually tune.                                 │
# │                                                                            │
# │ HARD-WON LESSON: target individual FUNCTIONS, never whole modules. Gating  │
# │ only on the module name obfuscates every function in the translation unit  │
# │ — including the hundreds of inlined libc++/STL template instantiations —   │
# │ which overwhelms the register allocator and crashes the backend (exit 139, │
# │ "Register Coalescer"). `_sensitive` therefore ALWAYS rejects library /     │
# │ runtime functions first via `_is_library_fn`. See docs/BUILD.md.           │
# └────────────────────────────────────────────────────────────────────────────┘
#
# Usage (the tested path is the Android NDK cross-compile — see docs/BUILD.md):
#   export OMVLL_CONFIG=$PWD/third_party/omvll/omvll_config.py
#   export OMVLL_PYTHONPATH=$PWD/third_party/python/Lib   # plugin's embedded CPython
#   cmake -GNinja -B build \
#     -DCMAKE_TOOLCHAIN_FILE=$NDK/build/cmake/android.toolchain.cmake \
#     -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-24 -DOMVLL=ON
#   cmake --build build -j
# (-DOMVLL=ON fetches the plugin + CPython stdlib; OMVLL_PYTHONPATH still needed.)
#
# See docs/BUILD.md (Option C) for the full setup and toolchain constraints.

import omvll
from functools import lru_cache


# --- Targeting ---------------------------------------------------------------
# Match on the module (translation-unit) path. These are the sensitive native
# surfaces; everything else is left untouched to keep build time and size sane.
_SENSITIVE_MODULES = (
    "vm.cpp", "handlers.cpp", "assembler.cpp",   # the interpreter + compiler
    "fwcrypt.cpp", "fw_schedule",                # the firmware decode schedule
    "trusted_storage.cpp",                       # sealing / KDF (holds WBTS magic)
    "wbcrypto.cpp", "wbcrypto_provision.cpp",    # SDK glue (runtime + provisioning)
)

# HOT interpreter path — the fetch/decode/dispatch loop and handler bodies run
# thousands of times per 16-byte block, so any heavy pass here multiplies by the
# VM op count (control-flow flattening can cost 5-20x throughput). These TUs are
# still "sensitive" for LIGHT passes (break_control_flow), but the HEAVY ones
# (flatten, MBA, opaque constants, struct-access) are kept OFF here. The static
# value of obfuscating the interpreter is low anyway: it is data-oblivious, so a
# dynamic attacker who traces one block recovers it regardless. Obfuscate the
# COLD code that gates a cheap offline attack (seal/unseal + loader in
# trusted_storage.cpp, the assembler, the SDK glue) heavily instead. See the
# "performance trap" in the Pass-2 O-MVLL addendum / docs/ANTI-TAMPER.md.
_HOT_MODULES = ("vm.cpp", "handlers.cpp")

# COLD gate TUs where MBA (arithmetic obfuscation) is worth its cost. These run
# ONCE (seal/unseal + KDF wiring; the bytecode compiler), so the heavy pass adds
# static-analysis resistance at ~no runtime cost. MBA is the most crash-prone
# O-MVLL pass, so it is scoped to this small set (not all sensitive TUs); if the
# backend crashes on it, shrink this tuple further or set obfuscate_arithmetic
# back to `return False`.
_MBA_MODULES = ("trusted_storage.cpp", "assembler.cpp")

def _is_hot(mod):
    return any(h in _mod_name(mod) for h in _HOT_MODULES)

def _wants_mba(mod):
    return any(m in _mod_name(mod) for m in _MBA_MODULES)

def _is_library_fn(func):
    name = getattr(func, "name", "") or ""
    dem  = getattr(func, "demangled_name", "") or ""
    if name.startswith(("_ZSt", "_ZNSt", "_ZNKSt")):
        return True
    if dem.startswith("std::") or "std::__" in dem:
        return True
    markers = ("__ndk1", "allocator", "__split_buffer", "__libcpp",
               "_ConstructTransaction", "__unwrap", "__rewrap",
               # Compiler / exception-handling runtime helpers. O-MVLL clones
               # functions with numeric suffixes; for these EH helpers a clone
               # can lose its linkonce/weak attribute and leak as a strong
               # global, producing a duplicate-symbol link error
               # (e.g. `__clang_call_terminate.21`). Never obfuscate them.
               "__clang_call_terminate", "__cxa_", "__gxx_personality")
    return any(m in name for m in markers)

def _mod_name(mod):
    # Be tolerant of API differences in how the module name is exposed.
    return getattr(mod, "name", str(mod))


def _sensitive(mod, func):
    if _is_library_fn(func):
        return False
    n = _mod_name(mod)
    return any(s in n for s in _SENSITIVE_MODULES)


# --- Config ------------------------------------------------------------------
# Bring passes up GRADUALLY, not all at once. A known-stable starting point is
# break_control_flow + flatten_functions only. obfuscate_arithmetic (MBA) is the
# heaviest and the most likely to reintroduce a backend crash at -O2/-O3 — enable
# it last, on the smallest function set.
class Config(omvll.ObfuscationConfig):
    def __init__(self):
        super().__init__()

    # Control-flow flattening — high value on the COLD gate code (seal/unseal,
    # loader, SDK glue), but excluded from the HOT interpreter path (per-VM-op,
    # 5-20x throughput cost for protection a dynamic attacker ignores).
    def flatten_functions(self, mod, func):
        return _sensitive(mod, func) and not _is_hot(mod)

    # Jump-into-the-middle / bogus CFG — lighter than flattening, so it is left
    # ON even for the hot path (breaks linear disassembly at modest cost).
    def break_control_flow(self, mod, func):
        return _sensitive(mod, func)

    # Arithmetic obfuscation (MBA) — rewrites arithmetic/logic into opaque
    # mixed boolean-arithmetic, the strongest STATIC hardening of the code's
    # semantics. Enabled ONLY on the cold gate TUs (_MBA_MODULES): they run once,
    # so there is no runtime cost, and the small set limits MBA's backend-crash
    # risk. NOT on the hot interpreter (per-op cost) and NOT globally. A bare
    # `True` uses O-MVLL's default rounds. If the backend crashes on this pass,
    # shrink _MBA_MODULES or return False.
    def obfuscate_arithmetic(self, mod, func):
        return _wants_mba(mod) and not _is_library_fn(func)

    # Opaque / encrypted constants — hides the WBTS seal magic, the SplitMix64 /
    # FNV constants, and S-box references so they are not recoverable by a
    # constant scan. Excluded from the hot path (per-op constant materialization
    # is costly).
    def obfuscate_constants(self, mod, func):
        return _sensitive(mod, func) and not _is_hot(mod)

    # Opaque struct-field access — excluded from the hot path: the dispatch loop
    # touches VMContext fields every op, so obfuscating that access is per-op.
    def obfuscate_struct_access(self, mod, func, struct):
        return _sensitive(mod, func) and not _is_hot(mod)

    # String encoding — encrypts string literals in the sensitive host/runtime
    # TUs (e.g. the "WBTS" magic in trusted_storage.cpp) so `strings` does not
    # reveal them. A bare `True` enables encoding (O-MVLL default); return
    # omvll.StringEncOptLocal() instead for in-function decode (stronger vs
    # memory dumps) on the most sensitive TUs.
    def obfuscate_string(self, mod, func, string):
        return _sensitive(mod, func) and not _is_hot(mod)

    # Anti-hooking — OFF. It conflicts with control-flow flattening: CFF clones
    # functions (the `foo (.3)` / `foo.25` suffixes), and the anti-hook pass then
    # fails on the clone with
    #     error: Cannot inject a hooking prologue in the function <fn> since there is one.
    # (observed on NDK r29 / O-MVLL v1.9.1 with flatten_functions enabled). The
    # anti-hook / anti-DBI capability is provided instead by src/rt/anti_tamper.*
    # (TracerPid / Frida-map / ptrace / timing, degrading silently into key
    # derivation). If you ever want O-MVLL's version, enable it only on a function
    # set that is NOT also flattened.
    def anti_hooking(self, mod, func):
        return False


@lru_cache(maxsize=1)
def omvll_get_config():
    return Config()
