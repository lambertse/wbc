# Native-Code Obfuscation (O-MVLL and friends)

This project obfuscates at the **bytecode/data** level (white-box tables, VM
bytecode, context-keyed firmware). It leaves the **native machine code** of the
interpreter, handlers, SDK, and freestanding runtime as plain compiled C++. A
compiler-level obfuscator like **[O-MVLL](https://obfuscator.re/omvll)** hardens
exactly that layer, so the two are **complementary** — stack them for defense in
depth.

## What each layer covers

| Surface | This project | Native obfuscator (O-MVLL) |
|---|---|---|
| AES key | diffused into tables | — (it's data) |
| "Is this AES?" | VM + blinding/MBA/opaque on **bytecode** | CFF/opaque/MBA on the **interpreter code** |
| Interpreter, handlers, assembler | **plain C++** | control-flow flattening, opaque predicates, bogus CFG |
| Firmware decode schedule (`src/fw/`) | it *is* the protection | native obf so the key schedule isn't trivially lifted |
| Trusted-storage KDF/seal | lightweight | native obf |
| Freestanding stub (`wb_stub.h`) | key diffusion only | strong on AArch64/Android (its target) |

Because native obfuscation is **semantics-preserving**, the full test suite
(`VM == interp == AES`) is a perfect regression guard for the obfuscated build.

## Toolchain constraints (read first)

- O-MVLL is an **LLVM pass-plugin** (`-fpass-plugin=OMVLL.{so,dylib}`) plus a
  Python config (`omvll_config.py`). It must be loaded into the clang from the
  **exact NDK it was built against** (an ABI match, not just a major version), and
  its embedded CPython needs a **3.10** stdlib via `OMVLL_PYTHONPATH`.
- O-MVLL supports **AArch64 / AArch32 only** — the tested path is an **Android
  `arm64-v8a` cross-compile**, not a macOS/x86-64 host build. `zig`'s bundled
  clang won't match the plugin.
- Each plugin is pinned to a specific NDK. This repo ships the
  **NDK r29 / O-MVLL v1.9.1** plugin (`obfuscation/omvll_ndk_r29.dylib`, Mach-O
  arm64). See [BUILD.md → Option C](BUILD.md#option-c--with-native-code-obfuscation-o-mvll)
  for the full, step-by-step setup (NDK install, macOS code-signing, Python
  stdlib, CMake/Ninja invocation) — that is the authoritative build recipe.

## How to build with it

The obfuscated build is the **CMake + Android NDK cross-compile** documented in
[BUILD.md → Option C](BUILD.md#option-c--with-native-code-obfuscation-o-mvll);
that page is the authoritative, step-by-step recipe (NDK install, macOS
code-signing, Python stdlib, environment). The short version:

```sh
# Env exported (ANDROID_HOME, NDK, PLUGIN, OMVLL_CONFIG, OMVLL_PYTHONPATH,
# DYLD_LIBRARY_PATH) and NDK clang re-signed — see BUILD.md.
rm -rf build
cmake -GNinja -B build \
  -DCMAKE_TOOLCHAIN_FILE="$NDK/build/cmake/android.toolchain.cmake" \
  -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-24 \
  -DCMAKE_BUILD_TYPE=Release \
  -DOMVLL_PLUGIN="$PLUGIN"          # do NOT also add -fpass-plugin via CMAKE_CXX_FLAGS
cmake --build build -j
```

`build.sh` is a **host** build, not the O-MVLL path; use it for the host-side
correctness gate (below). It exposes opt-in, pass-through `EXTRA_CXXFLAGS` /
`EXTRA_CFLAGS` / `EXTRA_LDFLAGS` (all empty by default) if you ever need to feed a
host-compatible plugin, but that is not the tested configuration.

## What to obfuscate

Heavy obfuscation is slow and bloats size, so target the sensitive translation
units (the template `obfuscation/omvll_config.py` matches these by module name):

- `src/vm/vm.cpp`, `src/vm/handlers.cpp`, `src/vm/assembler.cpp` — the interpreter
  and the tables→bytecode compiler.
- `src/fw/fwcrypt.cpp` + `fw_schedule.h` — the decode key schedule (highest value).
- `src/storage/trusted_storage.cpp` — sealing / KDF.
- `src/sdk/wbcrypto.cpp` — SDK glue.
- `freestanding/wb_stub.h` (via a TU that includes it) — the on-device crypto.

Leave the offline white-box compiler (`src/wbaes/wb_generator.cpp`) and the test
oracle (`aes_ref.cpp`) alone — they run on a trusted host and the tables they
emit are already obfuscated by construction.

**Target functions, never whole modules (hard-won lesson).** Gating a pass on
the *module* name obfuscates *every* function in that translation unit — including
the hundreds of inlined libc++/STL template instantiations — which overwhelms the
register allocator and crashes the LLVM backend (exit 139, "Register Coalescer").
The template's `_sensitive` therefore rejects library/runtime functions first via
`_is_library_fn`, which also excludes exception-handling runtime helpers
(`__clang_call_terminate`, `__cxa_`, `__gxx_personality`) — a cloned copy of those
can otherwise leak as a strong global and cause a `duplicate symbol` link error.
Bring passes up **gradually** (start with `break_control_flow` +
`flatten_functions`; add MBA last). O-MVLL writes per-module logs to
`build/omvll-logs/` — use them to confirm which passes ran on which functions.

## The freestanding caveat (important)

The device runtime is compiled `-ffreestanding -nostdlib -fno-builtin`, and the
build has a **gate that fails if any libc call is emitted**. Some O-MVLL passes
violate that:

- **Safe on the stub:** control-flow flattening, break-control-flow, opaque
  constants/predicates, arithmetic (MBA).
- **NOT safe on the stub:** string encoding (emits a decoder stub), anti-hooking
  (calls libc/syscalls). The template disables these for `wb_stub`/`selftest`.

If a pass trips the no-libc gate, either exclude the stub from that pass in
`omvll_config.py`, or obfuscate the stub separately for its real Android target (NDK
clang) where libc *is* present at that point.

## Verify the obfuscated build

Obfuscation is semantics-preserving, so correctness is checked on the **host**
build (the Android `arm64-v8a` artifacts don't run on the macOS host):

1. `./build.sh test` on the host — all 8 suites must still pass; any failure means
   a pass broke correctness (bisect by narrowing the `omvll_config.py` targeting).
2. The freestanding gate (`check: freestanding runtime …` line) must still pass —
   note it lives only in `build.sh`, not the CMake/NDK path.
3. The Android build was confirmed to **compile and link**; functional
   verification there needs an AArch64 device or emulator.
4. Spot-check hardening statically: the obfuscated `libwbcrypto.so` should show
   flattened control flow in a disassembler and a larger `.text`.

## Performance & targeting (the hot-path trap)

O-MVLL only raises the cost of *statically* reading the native code. It does not
move the cryptanalytic key-extraction ceiling and does not stop a dynamic
attacker who dumps memory — so treat it as a P2 pass behind external encodings
and the dynamic-path defenses (see docs/THREATMODEL.md and docs/ANTI-TAMPER.md).

Target **cold, high-value** code heavily; leave the **hot interpreter loop**
nearly untouched:

- The VM executes thousands of ops per 16-byte block. Flattening / MBA / opaque
  passes inside `vm.cpp` (dispatch loop) and `handlers.cpp` (handler bodies)
  multiply by that op count — potentially 5-20x throughput for protection a
  dynamic attacker ignores (the interpreter is data-oblivious). `omvll_config.py`
  therefore lists these in `_HOT_MODULES` and keeps the heavy passes OFF there,
  leaving only light `break_control_flow`.
- Obfuscate the code that gates a *cheap offline* attack: `trusted_storage.cpp`
  (seal/unseal + the blob loader), `assembler.cpp`, and the SDK glue. These run
  once, so flatten/opaque/string them freely.
- **Benchmark** `wbc_encrypt_block` / `wbc_crypt_ctr` before/after and treat a
  regression beyond budget as a build failure.

Note on external playbooks: O-MVLL config examples from generic hardening guides
often name translation units (`seal.cpp`, `loader.cpp`, `binding.cpp`) and
strings (`ro.arch`, device props) that **do not exist in this project**. Map any
such guidance onto the real TUs above — a config gated on a non-existent module
name silently obfuscates nothing.

## Other options

- **OLLVM forks** (Hikari, Arkari, Pluto) — older LLVM pass sets (CFF, bogus CFG,
  substitution). Same `-fpass-plugin`/`-mllvm` style integration.
- **Tigress** — a source-to-source **C** obfuscator (virtualization, flattening,
  jitting). Works on the C SDK surface and the freestanding stub (both are C);
  not on the C++ core.
- **Post-link packers** (VMProtect/Themida, x86 only) — wrap the final binary;
  orthogonal to source-level passes.

Whatever you pick, keep this project's tests as the correctness gate and the
no-libc check as the freestanding gate.
