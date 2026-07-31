# Build Guide

The White-box Crypto VM is a C++17 project. Its only third-party dependency is
**libsodium** (the seal's Argon2id KDF + XChaCha20-Poly1305 AEAD), vendored from
source. It builds two ways: a self-contained `build.sh` (the tested path) and a
portable `CMakeLists.txt` for standard toolchains.

## Requirements

- A **C++17 compiler** (`clang++` 8+, `g++` 9+, or `zig c++`).
- **libsodium source**, vendored with a pinned version + SHA256. Both `build.sh`
  and CMake fetch it automatically at build/configure time; to do it by hand:

  ```sh
  ./third_party/fetch_deps.sh libsodium  # populates third_party/libsodium/ (not committed)
  ```

  The build compiles libsodium from source (no autotools/`configure` needed —
  portable C is selected automatically), so no system crypto library is
  required. `fetch_deps.sh` is idempotent — it skips deps already vendored.

## Runtime vs provisioning (what ships)

The build produces two library flavours; **only the runtime ships to devices**:

| Library | Contents | Ships? |
|---|---|---|
| `libwbcrypto.{a,so}` | runtime only: open a sealed blob + encrypt (`wbc_open`, `wbc_encrypt_*`) + libsodium | **yes** |
| `libwbprovision.a` | adds the keygen surface: reference AES, `GenerateWhiteBox`, assembler, `wbc_seal_key` | **no** (build host only) |

The shared library is built with `-fvisibility=hidden` + a linker version script
(`src/sdk/wbcrypto.map`) so it exports **only** `wbc_*`, and it is stripped
(`-Wl,--strip-all`, no build-id) so it ships no symbol table or DWARF. On the NDK
path an extra `llvm-strip --remove-section=.comment` post-link step reaches the
shipped `.so` (the NDK toolchain otherwise injects `-g`). Verify with
`readelf --dyn-syms` (only `wbc_*`) and `nm` (no `GenerateWhiteBox`/`AesEncrypt*`).

## Option A — `build.sh` (recommended, no CMake needed)

The script discovers a compiler automatically, in this order:

1. `$CXX` if set
2. system `c++` / `g++` / `clang++`
3. a Zig toolchain: `$ZIG_CXX`, `zig` on `PATH`, or `./toolchain/zig-*/zig`

```sh
./build.sh            # build the library, the two CLI tools, and all tests
./build.sh test       # build, then run every test suite
```

Force a specific compiler:

```sh
CXX=/path/to/clang++ ./build.sh test
CXX=/path/to/zig-cxx ./build.sh test    # a wrapper that runs `zig c++ "$@"`
```

Outputs land in `./build/`:

| Output               | Purpose                                             |
|----------------------|-----------------------------------------------------|
| `wb_keygen`          | seal an AES key into a blob                          |
| `wb_encrypt`         | encrypt a block through a sealed blob               |
| `libwbcrypto.a` / `.so` | the shipped C-ABI runtime SDK (see [../include/wbcrypto.h](../include/wbcrypto.h)) |
| `libwbprovision.a`   | host-only provisioning lib (adds the keygen surface; not shipped) |
| `libsodium.a`        | vendored crypto dependency (built once)             |
| `example`            | C integration demo (full lifecycle → links `libwbprovision.a`) |
| `test_*`             | one executable per test suite                        |

Source layout: `src/wbaes/` (white-box compiler), `src/vm/` (the VM),
`src/fw/` (the context-keyed firmware toolchain), `src/obf/` (obfuscation
primitives), `src/storage/` (trusted storage), `src/sdk/` (C ABI).

## Option B — CMake (standard toolchains)

```sh
cmake -S . -B build
cmake --build build -j
ctest --test-dir build --output-on-failure
```

This mirrors `build.sh`; the CLI tools appear as `build/wb_keygen` and
`build/wb_encrypt`.

## Option C — with native-code obfuscation (O-MVLL)

You can additionally obfuscate the *native machine code* of the SDK/VM by loading
an LLVM pass-plugin such as **[O-MVLL](https://obfuscator.re/omvll)** at compile
time. This is complementary to the project's own bytecode/data obfuscation — see
**[ANTI-TAMPER.md](ANTI-TAMPER.md)** for the rationale and what to target. This
section covers just the build steps.

> **The tested path is an Android NDK cross-compile, driven by CMake + Ninja, on
> a macOS (Apple Silicon) host.** O-MVLL only supports **AArch64 / AArch32**, so
> the obfuscated artifacts target `arm64-v8a`; they build and link on the host
> but do not *run* there (see [Verify](#verify-the-obfuscated-build)). `build.sh`
> is a host build and is **not** the O-MVLL path — its role here is only the
> host-side correctness gate. The steps below are distilled from a real,
> reproduced setup; confirm the current version matrix on the
> [releases page](https://github.com/open-obfuscator/o-mvll/releases), as O-MVLL
> pins each plugin to a specific NDK.

### The known-good configuration

| Component | Value |
|---|---|
| Host | macOS (Apple Silicon); clang `dlopen`s **Mach-O only** |
| NDK | **r29** = `29.0.14206865` (`$ANDROID_HOME/ndk/29.0.14206865`) |
| O-MVLL | **v1.9.1** (the release paired with NDK r29) |
| Plugin file | `third_party/omvll/omvll_ndk_r29.dylib` — **Mach-O arm64**, *not* an ELF `.so` |
| Target ABI | `arm64-v8a` (O-MVLL supports AArch64 / AArch32 only) |
| Build | Ninja + CMake with the NDK toolchain file |
| Python stdlib | a CPython **3.10** `Lib/` directory, via `OMVLL_PYTHONPATH` |

O-MVLL pins each prebuilt plugin to a **specific** NDK/LLVM; the plugin must be
loaded by the clang from that NDK or it won't load / will crash. As a rough guide
(verify on the releases page — this is not authoritative): recent releases target
**r26d** (v1.3.0–v1.8.0) or **r29** (v1.9.0–v1.9.1). This repo pins the
**r29 / v1.9.1** plugin, fetched on demand by `third_party/fetch_deps.sh omvll`.

### Environment (export in the shell that runs both cmake and the build)

```sh
export ANDROID_HOME="$HOME/Library/Android/sdk"
export NDK="$ANDROID_HOME/ndk/29.0.14206865"
export PLUGIN="$PWD/third_party/omvll/omvll_ndk_r29.dylib"
export OMVLL_CONFIG="$PWD/third_party/omvll/omvll_config.py"
export OMVLL_PYTHONPATH="$PWD/third_party/python/Lib"   # see step 4
# macOS uses DYLD_LIBRARY_PATH (not LD_LIBRARY_PATH); the dir is darwin-x86_64
# even on Apple Silicon:
export DYLD_LIBRARY_PATH="$NDK/toolchains/llvm/prebuilt/darwin-x86_64/lib64"
```

The env vars must be live in the **same shell** that runs cmake *and* the build;
a fresh terminal without them will fail.

### Setup, in order (each step fixes a real failure)

1. **Install a matching NDK/plugin pair.** This repo pins the r29 / v1.9.1
   plugin (fetched into `third_party/omvll/`, not committed), so install NDK r29:
   ```sh
   ./third_party/fetch_deps.sh omvll   # -> third_party/omvll/omvll_ndk_r29.dylib (+ python)
   "$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" "ndk;29.0.14206865"
   cat "$NDK/source.properties"      # expect: Pkg.Revision = 29.0.14206865
   ```
   (`-DOMVLL=ON` at configure time fetches the plugin automatically too.)
   `sdkmanager` needs **JDK 17+** (it fails with "requires JDK 17 or later" on
   JDK 11). Either `brew install openjdk@17` and put it on `JAVA_HOME`/`PATH`, or
   for a one-off: `SKIP_JDK_VERSION_CHECK=1 sdkmanager "ndk;29.0.14206865"`.

2. **Verify the plugin is the right binary format.** macOS clang `dlopen`s
   Mach-O only — an ELF `.so` (e.g. a Linux `omvll_ndk_r25c.so`) can never load
   on a Mac:
   ```sh
   file "$PLUGIN"
   # want: Mach-O 64-bit dynamically linked shared library arm64
   # NOT:  ELF 64-bit LSB shared object, x86-64
   ```

3. **Re-sign the NDK clang so it can load the plugin (macOS hardened runtime).**
   Otherwise loading fails with *"code signature … not valid … different Team
   IDs"*. Re-sign the NDK compiler binaries ad-hoc with library-validation
   disabled — **do not disable SIP**:
   ```sh
   cat > /tmp/omvll.entitlements << 'EOF'
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
   <plist version="1.0">
   <dict>
       <key>com.apple.security.cs.disable-library-validation</key><true/>
       <key>com.apple.security.cs.allow-unsigned-executable-memory</key><true/>
       <key>com.apple.security.cs.allow-dyld-environment-variables</key><true/>
       <key>com.apple.security.cs.allow-jit</key><true/>
       <key>com.apple.security.cs.disable-executable-page-protection</key><true/>
   </dict>
   </plist>
   EOF

   BIN="$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin"
   codesign --force --options runtime -s - --entitlements /tmp/omvll.entitlements "$BIN/clang"
   codesign --force --options runtime -s - --entitlements /tmp/omvll.entitlements "$(readlink -f "$BIN/clang++")"
   ```
   If ad-hoc (`-s -`) still trips, use a real identity from
   `security find-identity -v -p codesigning`.

4. **Point the plugin's embedded Python at a 3.10 stdlib.** The plugin embeds a
   CPython VM and aborts with *"failed to get the Python codec of the filesystem
   encoding"* when it falls back to a nonexistent build-machine path. Fetch the
   matching CPython **3.10** source (only its pure-Python `Lib/` is used — no need
   to build it). `fetch_deps.sh omvll` vendors it for you (the O-MVLL release
   tarball bundles a version-matched `Python-3.10.7`), or fetch it standalone:
   ```sh
   ./third_party/fetch_deps.sh python     # -> third_party/python/ (pinned + SHA256)
   export OMVLL_PYTHONPATH="$PWD/third_party/python/Lib"
   ls "$OMVLL_PYTHONPATH/abc.py"      # sanity: must exist
   ```
   Also ensure `OMVLL_CONFIG` points at the config file, or the plugin reports
   `No module named 'omvll_config'`.

### Configure and build

`-DOMVLL=ON` fetches the pinned plugin (if absent) and adds `-fpass-plugin` to
every target (plus `-Wl,-z,muldefs` — see fix for duplicate symbols below). To
point at your own plugin build instead, set `-DOMVLL_PLUGIN="$PLUGIN"`. Pass the
plugin **only** this way; do **not** also inject `-fpass-plugin` via
`CMAKE_CXX_FLAGS`, or it double-applies.

```sh
rm -rf build                          # wipe stale cache whenever toolchain/NDK/plugin change
cmake -GNinja -B build \
  -DCMAKE_TOOLCHAIN_FILE="$NDK/build/cmake/android.toolchain.cmake" \
  -DANDROID_ABI=arm64-v8a \
  -DANDROID_PLATFORM=android-24 \
  -DCMAKE_BUILD_TYPE=Release \
  -DOMVLL=ON
cmake --build build -j
```

Configure prints `native-code obfuscation: -fpass-plugin=…` when the plugin is
set. If the build crashes while *loading* the plugin, see
[Troubleshooting O-MVLL](#troubleshooting-o-mvll).

> **Targeting matters — see [ANTI-TAMPER.md](ANTI-TAMPER.md) and the template
> `third_party/omvll/omvll_config.py`.** The config targets individual *functions* and
> excludes STL/libc++/EH-runtime symbols. An empty or module-wide config silently
> obfuscates *everything* (including inlined STL), which overwhelms the backend —
> see the two crash entries in troubleshooting.
>
> **libsodium note:** CMake applies `-fpass-plugin` globally, so it also loads on
> the 119 vendored `third_party/libsodium` TUs. The function-gating in
> `omvll_config.py` rejects them (not in `_SENSITIVE_MODULES`), so no passes
> apply — but the plugin still runs on them (extra build time, extra crash
> surface). If the NDK build hits a backend crash, exclude `third_party/libsodium`
> from the plugin first (compile it in a separate target without `-fpass-plugin`).

### Single-command obfuscated build via `build.sh` (host plugin)

`build.sh` can produce an obfuscated build in one command — it exposes
pass-through `EXTRA_CXXFLAGS` / `EXTRA_CFLAGS` / `EXTRA_LDFLAGS` — but only for a
**host** build, and only with a plugin that fits that model. The r29 plugin this
repo ships does **not** qualify, for two reasons:

- **ABI:** `-fpass-plugin` needs the plugin's LLVM to exactly match the compiler
  loading it. `omvll_ndk_r29.dylib` is built against **NDK r29's** clang;
  `build.sh`'s compiler (AppleClang, zig, or system) is a different LLVM build, so
  it crashes at plugin load (the exit-139 ABI-mismatch case).
- **Target:** the r29 plugin is for the Android `arm64-v8a` cross-compile, whereas
  `build.sh` builds *host* binaries and then runs them (`./build.sh test`). NDK
  clang would emit Android ELF binaries that can't execute on the host.

So the one-command path requires an O-MVLL plugin built for a **host-targeting
clang you actually have** (a macOS/AppleClang- or matching upstream-clang build).
Given such a plugin:

```sh
export OMVLL_CONFIG="$PWD/third_party/omvll/omvll_config.py"
export OMVLL_PYTHONPATH="$PWD/third_party/python/Lib"   # plugin's embedded CPython
CXX=/path/to/matching/clang++  CC=/path/to/matching/clang  ZIG_BIN= \
EXTRA_CXXFLAGS="-fpass-plugin=/path/to/host-OMVLL.dylib" \
EXTRA_CFLAGS="-fpass-plugin=/path/to/host-OMVLL.dylib" \
  ./build.sh test
```

or
```sh

export PYTHONHOME="$(pyenv root)/versions/3.10.7"
export NDK=/Users/tri.le/Library/Android/sdk/ndk/29.0.14206865
export OMVLL_CONFIG="$PWD/third_party/omvll/omvll_config.py"
export OMVLL_PYTHONPATH="$PWD/third_party/python/Lib"

rm -rf build
cmake -GNinja -B build \
  -DCMAKE_TOOLCHAIN_FILE=$NDK/build/cmake/android.toolchain.cmake \
  -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-24 \
  -DCMAKE_BUILD_TYPE=Release \
  -DOMVLL_PLUGIN=$PWD/third_party/omvll/omvll_ndk_r29.dylib
cmake --build build -j
```
```

```

Set `ZIG_BIN=` empty (as above) so the zig toolchain doesn't shadow your `CXX`.
When any `EXTRA_*` var is set, the build prints
`obfuscation flags: cxx='…' c='…' ld='…'` so you can confirm they applied. Two
caveats:

- **Don't add `-Wl,-z,muldefs` on macOS** — that's a GNU-ld/lld flag and Apple's
  `ld64` rejects it. You don't need it: the real fix for the duplicate
  `__clang_call_terminate` symbol is the `_is_library_fn` exclusion already in
  `third_party/omvll/omvll_config.py`. Reserve `EXTRA_LDFLAGS="-Wl,-z,muldefs"` for
  lld-based (NDK / Linux) links.

If you only have the pinned r29 plugin, use the CMake + NDK path above instead —
that is the tested configuration.

### Verify the obfuscated build

Obfuscation is semantics-preserving, so the correctness gate is the **host** test
suite — run it via `build.sh` on the host (or a host CMake build), where all 7
suites must still pass; a failure means a pass broke something (narrow the
targeting in `third_party/omvll/omvll_config.py`).

The Android `arm64-v8a` artifacts from the CMake/NDK path above were confirmed to
**compile and link cleanly**, but they do not execute on the macOS host.
**Functional verification of the obfuscated Android build requires an AArch64
device or emulator.** A quick static sanity
check that obfuscation did something: the obfuscated `libwbcrypto.so` should show
a larger `.text` and flattened control flow in a disassembler.

### Debugging aids

O-MVLL writes an `omvll-logs/` directory where the compiler runs (under `build/`
for this Ninja setup):

- `build/omvll-logs/omvll-init.log` — confirms the config was found and loaded.
- `build/omvll-logs/omvll-module-logs/aarch64/<file>.cpp-omvll-*.log` — per module,
  which passes ran on which functions.

Pin the location by setting `omvll.config.output_folder` in the config's
`__init__` if needed.

### Troubleshooting O-MVLL

Failures that happen while LLVM *loads the plugin* (a stack trace full of
`omvll.dylib` / `PassPlugin::Load`) are a plugin/environment problem, not a bug in
the sources.

**`failed to get the Python codec of the filesystem encoding`
(or `No module named 'encodings'`).** The plugin's embedded CPython can't locate
its 3.10 standard library. Set **`OMVLL_PYTHONPATH`** — O-MVLL's *own* variable —
to a matching CPython **3.10** source `Lib/` directory (the one containing
`abc.py`), *not* an installed/pyenv Python and *not* `PYTHONHOME` (see step 4).
The `omvll` module is **built into the plugin** — do not `pip install` it or put
it on `PYTHONPATH`; the PyPI `omvll` package is only for editor autocomplete. (You
can put `OMVLL_PYTHONPATH`/`OMVLL_CONFIG` in an `omvll.yml` at the repo root
instead of exporting them.)

**`No module named 'omvll_config'`.** `OMVLL_CONFIG` is unset or points at the
wrong path. Also do NOT name the config `omvll.py` — it shadows `import omvll`
(you'd then see `module 'omvll' has no attribute '__file__'`). Use
`omvll_config.py` (O-MVLL's default); the template in this repo is
`third_party/omvll/omvll_config.py`.

**`code signature … not valid … different Team IDs`, or "Signature does not
match".** macOS hardened runtime is refusing to let the NDK clang load a
differently-signed dylib. Redo the codesign step (step 3). (For a *downloaded*
plugin also clear the Gatekeeper quarantine:
`xattr -r -d com.apple.quarantine "$PLUGIN"`.)

**`unable to load plugin … no such file` / `invalid ELF/Mach-O`.** `$PLUGIN` is
wrong/not unpacked, or it's the wrong binary format for the host — re-check
`file "$PLUGIN"` reports **Mach-O arm64** (step 2).

**Backend crash (exit 139) in `Register Coalescer`, on inlined `std::…vector` /
`__split_buffer` / allocator internals — for every sensitive file.** A pass is
running on code it shouldn't, almost always inlined STL. Root cause: targeting by
*module* obfuscates every function in the translation unit, including hundreds of
inlined libc++ templates, which overwhelms the register allocator. Fix: target
individual **functions** and reject STL/libc++ symbols — the template's
`_is_library_fn` / `_sensitive` already do this; tighten `_is_library_fn` if a new
marker slips through. Bring passes up gradually (start with `break_control_flow` +
`flatten_functions`; add MBA last).

**Link error `duplicate symbol: __clang_call_terminate.N` (or another `__cxa_` /
`__gxx_personality` clone).** O-MVLL clones functions with numeric suffixes and a
cloned EH/runtime helper can lose its `linkonce`/weak attribute and leak as a
strong global, defined in two TUs. Fix: exclude compiler/EH runtime helpers in
`_is_library_fn` (`__clang_call_terminate`, `__cxa_`, `__gxx_personality` — the
template already does) so no clone is created. Belt-and-suspenders: `-Wl,-z,muldefs`
(added automatically when `OMVLL_PLUGIN` is set) tolerates any residual duplicate.

**Compile error `Cannot inject a hooking prologue in the function <fn> (.N) since
there is one.`** The anti-hooking pass is trying to add a prologue to a function
that already has one. Two causes, check in order:
1. **The plugin is applied twice** — you passed both `-DCMAKE_CXX_FLAGS=-fpass-plugin=…`
   *and* `-DOMVLL_PLUGIN=…`. Look at the failing compile line: `-fpass-plugin=…`
   appears **twice**. Every pass then runs twice; anti-hook injects a prologue on
   the first run and errors on the second. Fix: pass the plugin **once** — use
   `-DOMVLL_PLUGIN=…` alone (it adds the single `-fpass-plugin` + `-Wl,-z,muldefs`
   for you). This is the most common cause.
2. **Anti-hook vs control-flow flattening** — even applied once, CFF clones
   functions (the `foo (.3)` / `foo.25` suffixes) and anti-hook then chokes on the
   clone. Fix: leave `anti_hooking` **off** in `omvll_config.py` (the template
   ships it off); runtime anti-hook / anti-DBI is provided by `src/rt/anti_tamper.*`
   instead. (Both reproduced on NDK r29 / O-MVLL v1.9.1.)

**Segfault (exit 139) inside `omvll.dylib` at
`llvm::PassBuilder::registerModuleAnalyses` / `RunOptimizationPipeline`, for every
file.** An **ABI mismatch**: the plugin was built against a *different* LLVM than
the clang loading it. `-fpass-plugin` needs the *exact same* LLVM build (point
release + build config), not merely the same major version. Use the clang from the
**NDK the plugin was built for** (r29 for this repo's plugin), or **skip O-MVLL** —
the project builds and passes all host tests without it.

## Bootstrapping a compiler with Zig (no system compiler / no root)

If the machine has no compiler and no `apt`/root access, a single self-contained
Zig toolchain provides a full clang-based `zig c++`:

```sh
# 1. download the toolchain for your platform from https://ziglang.org/download/
#    (e.g. zig-<arch>-linux-<ver>.tar.xz) and extract it into ./toolchain/
mkdir -p toolchain && tar -xf zig-*.tar.xz -C toolchain

# 2. build.sh auto-detects ./toolchain/zig-*/zig, or make a wrapper:
printf '#!/bin/sh\nexec "%s/zig" c++ "$@"\n' "$PWD/toolchain/zig-<...>" > zig-cxx
chmod +x zig-cxx
CXX=$PWD/zig-cxx ./build.sh test
```

> Note: `.tar.xz` needs `xz` to extract. If `xz` is unavailable, decompress with
> any XZ-capable tool first (e.g. the pure-JS `xz-decompress` npm package),
> then `tar -xf` the resulting `.tar`.

The first `zig c++` invocation builds libc++ once (emitting nullability
warnings) and then caches it; subsequent builds are fast and quiet.

## Compiler flags

`build.sh` compiles with `-std=c++17 -O2 -Isrc -Iinclude -Itests
-Wall -Wextra` (plus anything in `EXTRA_CXXFLAGS`/`EXTRA_CFLAGS`, see
[Option C](#option-c--with-native-code-obfuscation-o-mvll)). The full build is a
few seconds; there is no incremental object cache — every test binary is linked
against the library sources directly, which keeps the build script trivial and
dependency-free.

## Running the tests

```sh
./build.sh test
```

Expected output — seven passing suites:

```
[PASS] test_aes_ref     reference AES vs FIPS-197
[PASS] test_wbaes       white-box == AES at each stratum (+ random keys)
[PASS] test_vm          VM output == interpreter == AES (plain + hardened)
[PASS] test_obf         MBA / opaque / opcode-blinding primitives
[PASS] test_fw          context-keyed firmware: decode == AES, tamper cascade
[PASS] test_sdk         C-ABI SDK: seal/open/ECB/CTR, error paths
[PASS] test_e2e         seal→unseal→run, key-absence, anti-tamper
```
