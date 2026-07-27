# omvll_config.py — TEMPLATE O-MVLL configuration for the White-box Crypto VM.
#
# O-MVLL (https://obfuscator.re/omvll) is an LLVM pass-plugin driven by this
# Python file. It obfuscates the *native machine code* of the interpreter, SDK,
# and freestanding runtime — the layer this project ships as plain compiled C++.
#
# ┌─ IMPORTANT ────────────────────────────────────────────────────────────────┐
# │ The ObfuscationConfig API changes between O-MVLL releases. Treat this as a  │
# │ STARTING POINT and align the method names / return types with the version  │
# │ you installed (see the docs for your release). The targeting logic         │
# │ (_sensitive / _is_freestanding) is what you'll actually tune.              │
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
#   export OMVLL_CONFIG=$PWD/obfuscation/omvll_config.py
#   export OMVLL_PYTHONPATH=/path/to/Python-3.10.x/Lib   # plugin's embedded CPython
#   cmake -GNinja -B build \
#     -DCMAKE_TOOLCHAIN_FILE=$NDK/build/cmake/android.toolchain.cmake \
#     -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-24 \
#     -DOMVLL_PLUGIN=$PWD/obfuscation/omvll_ndk_r29.dylib
#   cmake --build build -j
#
# See docs/BUILD.md (Option C) for the full setup and docs/OBFUSCATION.md for the
# toolchain constraints and the freestanding caveat (some passes are NOT no-libc
# safe).

import omvll
from functools import lru_cache


# --- Targeting ---------------------------------------------------------------
# Match on the module (translation-unit) path. These are the sensitive native
# surfaces; everything else is left untouched to keep build time and size sane.
_SENSITIVE_MODULES = (
    "vm.cpp", "handlers.cpp", "assembler.cpp",   # the interpreter + compiler
    "fwcrypt.cpp", "fw_schedule",                # the firmware decode schedule
    "trusted_storage.cpp",                       # sealing / KDF
    "wbcrypto.cpp",                              # SDK glue
    "wb_stub", "selftest.c",                     # freestanding device runtime
)
# Modules that must stay libc-free: only CFG/arithmetic/opaque passes are safe
# here — NO string encoding, NO anti-hooking (they emit decoder stubs / libc).
_FREESTANDING_MODULES = ("wb_stub", "selftest.c")

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

def _is_freestanding(mod, _func):
    n = _mod_name(mod)
    return any(s in n for s in _FREESTANDING_MODULES)


# --- Config ------------------------------------------------------------------
# Bring passes up GRADUALLY, not all at once. A known-stable starting point is
# break_control_flow + flatten_functions only. obfuscate_arithmetic (MBA) is the
# heaviest and the most likely to reintroduce a backend crash at -O2/-O3 — enable
# it last, on the smallest function set. String encoding and anti-hooking are NOT
# freestanding-safe (they emit decoder stubs / libc calls); keep them off for the
# wb_stub / selftest.c freestanding modules.
class Config(omvll.ObfuscationConfig):
    def __init__(self):
        super().__init__()

    # Control-flow flattening — safe everywhere (no libc), high value on the
    # dispatcher and handlers.
    def flatten_functions(self, mod, func):
        return _sensitive(mod, func)

    # Jump-into-the-middle / bogus CFG — safe, breaks linear disassembly.
    def break_control_flow(self, mod, func):
        return _sensitive(mod, func)

    # Arithmetic obfuscation (MBA) on the native code — complements the
    # bytecode-level MBA. Safe for freestanding.
    def obfuscate_arithmetic(self, mod, func):
        return None

    def obfuscate_constants(self, mod, func):
        return False

    # Opaque struct-field access — safe.
    def obfuscate_struct_access(self, mod, func, struct):
        return _sensitive(mod, func)

    # String encoding — NOT freestanding-safe (adds a decoder stub). Host code
    # only; the crypto has no meaningful strings anyway, so default off.
    def obfuscate_string(self, mod, func, string):
        return False

    # Anti-hooking — NOT freestanding-safe (calls into libc / syscalls). Enable
    # only on host SDK/CLI code if you want it, never on the stub.
    def anti_hooking(self, mod, func):
        return _sensitive(mod, func) and not _is_freestanding(mod, func) and False


@lru_cache(maxsize=1)
def omvll_get_config():
    return Config()
