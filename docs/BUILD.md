# Build Guide

The White-box Crypto VM is a C++17 project. Its only third-party dependency is
**libsodium** (the seal's KDFs — Argon2id and HKDF-SHA256 — plus its
XChaCha20-Poly1305 AEAD), vendored from source.

**There are two jobs here, on two different machines, and every script is named for
the one it does.** Getting this straight up front saves most of the confusion:

| Script | Machine | Produces | You need it to... |
|---|---|---|---|
| `scripts/build_android.sh` | NDK cross-compile | `build-android/libwbcrypto.a` | ship the runtime — **this is the only artifact that ships** |
| `scripts/gen_blob.sh` | your host | `build-host/wb_keygen`, `wb_encrypt`, a `.blob` | seal a key offline; this is what the consumer's packer calls |
| `scripts/build_host.sh` | your host | `build/test_*`, `wb_keygen`, `wb_encrypt` | run the correctness suite |
| `scripts/bench_android.sh` | NDK + a device | two `wb_bench` builds + a ratio table | measure what O-MVLL costs |

Note what is *absent*: no host build produces a shipping library. `libwbcrypto.a`
exists to be linked into an Android `.so`, so it comes from the NDK path and nowhere
else — there is no host copy to mix up with the real one, and no `.so` at all (see
below).

## Runtime vs provisioning (what ships)

The source set is split in two, and **only the runtime half ever reaches a device**:

| Half | Contents | In `libwbcrypto.a`? |
|---|---|---|
| runtime | open a sealed blob, `wbc_encrypt_block`, `wbc_wrap_key`/`wbc_unwrap_key`, `wbc_wipe`, + libsodium | **yes** |
| provisioning | reference AES, `GenerateWhiteBox`, the assembler, `wbc_seal_key` | **no** — host only |

`CMakeLists.txt` enforces the split structurally: `wbcrypto_static` is built from
`wbvm_runtime_obj` only, so `wbc_seal_key` *cannot* be linked into it by accident,
and `scripts/build_android.sh` asserts it afterwards with `llvm-nm` (it `die()`s if
`wbc_seal_key` is defined, or if `wbc_blob_kdf_tier` is missing). That matters
because the provisioning half contains the white-box *generator* — the code that
turns a raw AES key into a table network — which must never ship inside an app.

**There is no shared library.** A `libwbcrypto.so` used to be built alongside the
archive, with its own version script, strip step and macOS/ELF link-flag
divergence. It was a second way to ship the same code that nobody linked: the
consumer links the archive into its own `.so`. Symbol hiding moved with it — an
archive has no dynamic symbol table, so `wbc_*` stays visible there *by design*
(that is how the consumer resolves it), and the hiding happens one link later, in
the consumer's `.so`, via `-Wl,--exclude-libs,ALL` or a version script. **Verify it
there, on the `.so` you actually ship**; nothing in this repo can tell you whether
that step worked.

The archive is the artifact that used to leak: the strip steps only ever touched the
`.so`, so `libwbcrypto.a` kept the DWARF the NDK's `-g` produced — 46% of its size,
and with it the build machine's username and full source layout in
`.debug_str`/`.debug_line`. Two flags close it, both directory-scope in
`CMakeLists.txt` so they reach the libsodium objects as well as ours: `-g0` in
Release (the fix), and `-ffile-prefix-map=<src>=.` for the configs that legitimately
keep DWARF — which also covers `.rodata`, since a `Debug` build has no `NDEBUG` and
libsodium's `assert()`s then bake `__FILE__` in. An archive-level `llvm-strip
--strip-debug` backs this up on the NDK path (`--strip-debug`, never `--strip-all`:
an archive's symbol table is what the consumer links against).
`scripts/build_android.sh` asserts the result and fails the build if a host path
survives, so this cannot regress silently. Verify by hand with
`strings -a build-android/libwbcrypto.a | grep -E '/Users/|/home/'`.

## Requirements

- A **C++17 compiler** (`clang++` 8+, `g++` 9+, or `zig c++`).
- **libsodium source**, vendored with a pinned version + SHA256. Both `scripts/build_host.sh`
  and CMake fetch it automatically at build/configure time; to do it by hand:

  ```sh
  ./third_party/fetch_deps.sh libsodium  # populates third_party/libsodium/ (not committed)
  ```

  The build compiles libsodium from source (no autotools/`configure` needed —
  portable C is selected automatically), so no system crypto library is
  required. `fetch_deps.sh` is idempotent — it skips deps already vendored.

## The host correctness build — `scripts/build_host.sh`

Needs no CMake. It discovers a compiler automatically, in this order:

1. `$ZIG_BIN` (a `zig` binary; drives `zig c++` and `zig ar` together)
2. `$CXX` if set
3. system `c++` / `g++` / `clang++`
4. a Zig toolchain: `zig` on `PATH`, or `./toolchain/zig-*/zig`

```sh
./scripts/build_host.sh            # build the two CLI tools and all tests
./scripts/build_host.sh test       # build, then run every test suite
```

Force a specific compiler:

```sh
CXX=/path/to/clang++ ./scripts/build_host.sh test
ZIG_BIN=/path/to/zig ./scripts/build_host.sh test    # brings zig ar/cc along too
```

Outputs land in `./build/`:

| Output               | Purpose                                             |
|----------------------|-----------------------------------------------------|
| `test_*`             | one executable per test suite — the reason this script exists |
| `wb_keygen`          | seal an AES key into a blob                          |
| `wb_encrypt`         | encrypt a block through a sealed blob               |
| `libsodium.a`        | vendored crypto dependency (built once)             |

**No library, no benchmark.** `libwbcrypto.a` comes from
`scripts/build_android.sh`; `wb_bench` is only meaningful under the NDK (see
[Benchmarks](#benchmarks--what-does-o-mvll-actually-cost)). Each binary here links
the full source set directly, so there is no intermediate archive to keep in sync.

> **`build/` is not toolchain-stamped.** `libsodium.a` is cached and reused when
> present, so switching compilers (say, adding `ZIG_BIN` to a tree previously built
> with system `clang++`) reuses an incompatible archive and fails at link with
> `undefined symbol: sodium_init` and friends — a confusing error with an easy fix:
> `rm -rf build`. `gen_blob.sh` keys its own cache to compiler+platform to avoid
> exactly this; this script does not.

Source layout: `src/wbaes/` (white-box compiler), `src/vm/` (the VM),
`src/fw/` (the context-keyed firmware toolchain), `src/obf/` (obfuscation
primitives), `src/storage/` (trusted storage), `src/sdk/` (C ABI).

## CMake directly (what the Android script wraps)

`CMakeLists.txt` is the single source of truth for the build graph, and
`scripts/build_android.sh` is a thin wrapper that hands it the NDK toolchain file.
You can also drive it on the host — useful mainly to check that a change configures
and to build `wbcrypto_static` for a link test:

```sh
cmake -S . -B build-cmake
cmake --build build-cmake -j
ctest --test-dir build-cmake --output-on-failure
```

Targets: `wbcrypto_static` (→ `libwbcrypto.a`, the shipped artifact), `wbvm` (the
full source set, for the tools and tests), `wb_keygen`, `wb_encrypt`, `wb_bench`,
and one executable per `tests/test_*.cpp`.

> Prefer `scripts/build_host.sh` for the test suite: it needs no CMake, and this
> container has no system compiler, so a bare `cmake -S . -B ...` will fail
> compiler detection unless you point `CMAKE_C_COMPILER`/`CMAKE_CXX_COMPILER` at a
> `zig cc`/`zig c++` wrapper.

## With native-code obfuscation (O-MVLL)

You can additionally obfuscate the *native machine code* of the SDK/VM by loading
an LLVM pass-plugin such as **[O-MVLL](https://obfuscator.re/omvll)** at compile
time. This is complementary to the project's own bytecode/data obfuscation.

> **The tested path is an Android NDK cross-compile, driven by CMake + Ninja, on
> a macOS (Apple Silicon) host.** O-MVLL only supports **AArch64 / AArch32**, so
> the obfuscated artifacts target `arm64-v8a`; they build and link on the host
> but do not *run* there (see [Verify](#verify-the-obfuscated-build)).
> `scripts/build_host.sh` is a host build and is **not** the O-MVLL path — its
> role here is only the host-side correctness gate. The steps below are distilled
> from a real, reproduced setup; confirm the current version matrix on the
> [releases page](https://github.com/open-obfuscator/o-mvll/releases), as O-MVLL
> pins each plugin to a specific NDK.

### What gets obfuscated, and the naming trap

`third_party/omvll/omvll_config.py` targets the sensitive **functions** (never whole
modules — that overwhelms the backend; see the file's header) in the hot TUs:
`vm.cpp`, `handlers.cpp`, `assembler.cpp`, `trusted_storage.cpp`, `fwcrypt.cpp`,
and the SDK glue. Enabled passes:

- control-flow flattening + bogus control flow (everywhere sensitive),
- opaque/encrypted **constants** and **string encoding** on the sensitive TUs —
  this is what removes the `WBTS` magic and the SplitMix64/FNV constants from a
  `strings`/constant scan,
- MBA arithmetic (heaviest — bring up last; dial back if the register coalescer
  crashes),
- anti-hooking on the runtime/SDK TUs.

> **The config matches module names by SUBSTRING**
> (`any(s in n for s in _SENSITIVE_MODULES)`), so the *filenames above are
> load-bearing*. A file whose path merely CONTAINS one of them gets obfuscated
> too — which matters most for `bench/`: a benchmark named so that its path
> contains `vm.cpp` or `handlers.cpp` would be obfuscated along with the code it
> is trying to measure, silently corrupting its own numbers and invalidating the
> A/B below. Do not rename a `bench/` file into that shape, and do not add a
> `_SENSITIVE_MODULES` entry short enough to collide with one.

Benchmark `wbc_encrypt_block` after enabling CFF/MBA and pick a level you can
afford — see [Benchmarks](#benchmarks--what-does-o-mvll-actually-cost) below.
Note `wbc_open`'s cost is dominated by the blob's KDF tier (~96-99% of it at
`--kdf medium`/`heavy`), so the obfuscated loader there is reported as a bound
rather than a value; the practical upshot is that heavy passes on the cold gate
code are affordable. Re-seal at `--kdf light` and the loader becomes directly
measurable (~1 ms), which is the honest way to check that claim rather than
inferring it from a bound. See [ARCHITECTURE §6.1](ARCHITECTURE.md).

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

**One command:** `./scripts/build_android.sh` wraps everything below — it validates
the environment first (the failure modes here are opaque; a missing
`OMVLL_PYTHONPATH` aborts thirty seconds into a compile with *"failed to get the
Python codec of the filesystem encoding"*), defaults `OMVLL_CONFIG` /
`OMVLL_PYTHONPATH` to their in-repo paths, and then **verifies the artifact**: that
`libwbcrypto.a` embeds no host paths, carries no DWARF in Release, defines
`wbc_blob_kdf_tier`, and does **not** define `wbc_seal_key`.

```sh
./scripts/build_android.sh                   # obfuscated release, -> build-android/
./scripts/build_android.sh --no-omvll        # obfuscation off
./scripts/build_android.sh --target wb_bench # one target
```

It is a *wrapper*, not a second build system: CMake stays the single source of
truth. Note the default output directory is **`build-android/`**, not `build/` —
`scripts/build_host.sh` caches `libsodium.a` and skips rebuilding when the file is present, so
sharing one directory between the host and cross builds means the next `./scripts/build_host.sh`
silently links an ELF archive and fails with `undefined symbol: sodium_memzero`.
Keep the two trees separate and neither needs an `rm -rf`.

**Do not use `scripts/build_host.sh` for the ELF build.** It selects its `.so` link flags from
`uname -s` — the *host* OS — so cross-compiling from macOS takes the Mach-O branch,
feeds `-dead_strip`/`-exported_symbol` to an ELF linker, hits its
"linker rejected the symbol-hygiene flags" fallback, and relinks **without the
version script**. The result loads fine and exports `vm::*`, `wbaes::*` and
`storage::*`. That is the exact regression the artifact check above exists to catch.

The rest of this section is what the wrapper runs, for reference or manual use.

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

> **Targeting matters — see [What gets obfuscated](#what-gets-obfuscated-and-the-naming-trap)
> above and the template `third_party/omvll/omvll_config.py`.** The config targets individual *functions* and
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

### Can `scripts/build_host.sh` do this in one command? Effectively, no.

It exposes pass-through `EXTRA_CXXFLAGS` / `EXTRA_LDFLAGS`, so it *can* load a
plugin — but only for a **host** build, and only with a plugin that fits that
model. The r29 plugin this repo ships does **not** qualify, for two reasons:

- **ABI:** `-fpass-plugin` needs the plugin's LLVM to exactly match the compiler
  loading it. `omvll_ndk_r29.dylib` is built against **NDK r29's** clang;
  `scripts/build_host.sh`'s compiler (AppleClang, zig, or system) is a different LLVM build, so
  it crashes at plugin load (the exit-139 ABI-mismatch case).
- **Target:** the r29 plugin is for the Android `arm64-v8a` cross-compile, whereas
  `scripts/build_host.sh` builds *host* binaries and then runs them (`./scripts/build_host.sh test`). NDK
  clang would emit Android ELF binaries that can't execute on the host.

So the one-command path requires an O-MVLL plugin built for a **host-targeting
clang you actually have** (a macOS/AppleClang- or matching upstream-clang build).
Given such a plugin:

```sh
export OMVLL_CONFIG="$PWD/third_party/omvll/omvll_config.py"
export OMVLL_PYTHONPATH="$PWD/third_party/python/Lib"   # plugin's embedded CPython
CXX=/path/to/matching/clang++  CC=/path/to/matching/clang  ZIG_BIN= \
EXTRA_CXXFLAGS="-fpass-plugin=/path/to/host-OMVLL.dylib" \
  ./scripts/build_host.sh test
```

The equivalent for the real (Android) build, spelled out — this is exactly what
`scripts/build_android.sh` runs for you, so prefer the script:

```sh
export NDK="$HOME/Library/Android/sdk/ndk/29.0.14206865"   # your NDK root
export PYTHONHOME="$(pyenv root)/versions/3.10.7"          # only if CPython is under pyenv
export OMVLL_CONFIG="$PWD/third_party/omvll/omvll_config.py"
export OMVLL_PYTHONPATH="$PWD/third_party/python/Lib"

rm -rf build-android
cmake -GNinja -B build-android \
  -DCMAKE_TOOLCHAIN_FILE="$NDK/build/cmake/android.toolchain.cmake" \
  -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-24 \
  -DCMAKE_BUILD_TYPE=Release \
  -DOMVLL_PLUGIN="$PWD/third_party/omvll/omvll_ndk_r29.dylib"
cmake --build build-android -j
```

> Use `build-android/`, not `build/`: the latter is `scripts/build_host.sh`'s tree,
> and its cached `libsodium.a` would then be an Android archive that the next host
> build happily reuses and fails to link.

Set `ZIG_BIN=` empty (as above) so the zig toolchain doesn't shadow your `CXX`.
When any `EXTRA_*` var is set, the build prints
`obfuscation flags: cxx='…' ld='…'` so you can confirm they applied. Two
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
suite — run it via `scripts/build_host.sh` on the host (or a host CMake build), where all 7
suites must still pass; a failure means a pass broke something (narrow the
targeting in `third_party/omvll/omvll_config.py`).

The Android `arm64-v8a` artifacts from the CMake/NDK path above were confirmed to
**compile and link cleanly**, but they do not execute on the macOS host.
**Functional verification of the obfuscated Android build requires an AArch64
device or emulator.** A quick static sanity
check that obfuscation did something: the obfuscated `libwbcrypto.a` should show
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
   ships it off). Note this leaves runtime anti-hook / anti-DBI **unaddressed** —
   there is no replacement in this SDK. (Both reproduced on NDK r29 / O-MVLL v1.9.1.)

**Segfault (exit 139) inside `omvll.dylib` at
`llvm::PassBuilder::registerModuleAnalyses` / `RunOptimizationPipeline`, for every
file.** An **ABI mismatch**: the plugin was built against a *different* LLVM than
the clang loading it. `-fpass-plugin` needs the *exact same* LLVM build (point
release + build config), not merely the same major version. Use the clang from the
**NDK the plugin was built for** (r29 for this repo's plugin), or **skip O-MVLL** —
the project builds and passes all host tests without it.

## Benchmarks — what does O-MVLL actually cost?

[the O-MVLL section](#with-native-code-obfuscation-o-mvll) tells you to benchmark
`wbc_encrypt_block` after enabling CFF/MBA and pick a level you can
afford. `bench/wb_bench.cpp` plus `scripts/bench_android.sh` are how
you do that.

One command builds `wb_bench` **twice from identical sources** — plugin on, plugin
off — pushes both to a connected arm64 device along with **one** host-generated
blob, runs them interleaved, and prints a ratio table:

```sh
# in the same shell you use for a normal obfuscated build (the O-MVLL env below)
./scripts/bench_android.sh
```

Useful flags: `--rounds N`, `--cooldown SEC`, `--cpu N`, `--blob FILE`,
`--pass P`, `--kdf TIER`, `--reps N`, `--no-build`, `--serial S`.

The script regenerates `$BLOB` when it is missing **or** left over from an older
blob format version — checking only for existence used to mean a stale blob got
pushed to the device, where it failed as an opaque mid-run error.

**It measures two KDF tiers every run.** `wbc_open`'s cost is set by the blob's
tier, not by the obfuscator, and the tiers differ by ~100x — so reporting one
alone invites reading a 250 ms `open` as "the loader is slow". The primary blob
(`--kdf`, default heavy) gets the full metric set; a contrasting-tier blob
(`sealed-light.blob` beside it) is re-measured for `open`/`kdf` only via
`wb_bench --only open,kdf`, since those are the only tier-dependent metrics. The
extra pass costs seconds at heavy and milliseconds at light. Output ends with:

```
  === wbc_open across KDF tiers (min over 2 round(s)) ===

  tier              plain          omvll       kdf alone
  --------  -------------  -------------  --------------
  heavy         264.70 ms      260.99 ms      265.24 ms*
  light           2.14 ms        2.20 ms            3 us

  * kdf alone came out >= open: it is timed in a separate loop, so at the
    Argon2id tiers it is NOT a subset of open and the two are not subtractable.

  => kdf=light opens 124x faster than kdf=heavy (262.6 ms saved per open)
```

Tiers in that table are always read back out of the blob headers, never echoed
from the `--kdf` flag — so a reused blob can never be reported as a tier it is
not. The column is headed `kdf alone` rather than "of which KDF" deliberately: it
is a separate measurement, not a decomposition of `open`, and at the Argon2id
tiers it can exceed `open` outright (starred when it does). Same ill-conditioning
as under *Reading `open - kdf`* below.

For a quick **host** baseline (no obfuscation — the plugin cannot load into a host
compiler, see the O-MVLL section):

```sh
./scripts/gen_blob.sh                                   # -> sealed.blob, pass "demo"
./scripts/build_host.sh && ./build/wb_bench --blob sealed.blob --pass demo
```

`wb_bench` prints the blob's KDF tier, and that tier sets the scale of both
`open` and `kdf`. To see the difference, seal the same key three ways:

```sh
for t in light medium heavy; do
    ./scripts/gen_blob.sh --key 000102030405060708090a0b0c0d0e0f --pass demo \
        --seed 42 --kdf $t --out b-$t.blob
    ./build/wb_bench --blob b-$t.blob --pass demo | grep -E 'kdf tier|^  (open|kdf) '
done
```

Measured on aarch64 Linux (min-of-5): `open` = 1.03 ms / 45.3 ms / 195.5 ms for
light / medium / heavy. On an arm64 phone, heavy is ~254 ms. The tier changes
nothing else — the ciphertext is identical, which `bench_compare.sh` asserts, and
it refuses to compare two runs whose blobs were sealed at different tiers.
See [ARCHITECTURE §6.1](ARCHITECTURE.md) for when each tier is sound; `light`
requires a high-entropy machine-generated passphrase.

`./scripts/build_host.sh test` does **not** run the benchmark: it asserts nothing, so it has no
business in the test suite. It is likewise not registered with `ctest`.

### What it measures, and why it is split up

| metric | surface | O-MVLL passes applied there |
|---|---|---|
| `vm_run` | `vm::Run` — the interpreter | `break_control_flow` only (HOT tuple) |
| `data_copy` | the per-block DATA image copy | none — plain allocation + memmove |
| `encrypt_block` | `wbc_encrypt_block` (KAT primitive) | flatten + constants + struct-access + strings |
| `wrap_key` / `unwrap_key` | `wbc_wrap_key` / `wbc_unwrap_key` — the real data path | as above |
| `open` | `wbc_open` | flatten + **MBA** + constants + strings |
| `kdf` | the blob's own derivation alone — `crypto_pwhash` at medium/heavy, HKDF-SHA256 at light | none — vendored libsodium |

`--only METRIC,...` restricts the run to named metrics (an unknown name is an
error, not a silent no-op). `bench_android.sh` uses `--only open,kdf` for its
second, contrasting-tier pass; it is also handy for iterating on one number
without paying for the whole set.

The splits exist because two large, **unobfuscated** costs sit inside the numbers
you actually care about and drag their ratios towards a meaningless 1.00x:

- `vm::Run` copies the whole DATA image (~400 KB) on **every** block
  (`ctx.data = prog.data` in `src/vm/vm.cpp`). Measured separately as `data_copy`
  so it can be subtracted. Its share is strongly device-dependent: ~4% of
  `vm_run` on an aarch64 Linux host, but **~30% on an arm64 phone** (200,518 of
  669,697 ns) — v3 cut `vm_run` by 34% while the fixed-size copy stayed put, and
  memcpy is relatively slower there. `wb_bench` prints the live percentage; trust
  that over any figure quoted here, and do not budget from the host number when
  targeting a phone.

  This copy looks like obvious waste (only the trailing 48 bytes are ever
  written) but **it is load-bearing**: restoring the read-only table bank before
  each block is what washes out an injected fault before the next block can
  observe it, i.e. the defence against differential fault analysis. Both ways of
  removing it have been implemented and measured, and both were rejected:
  reusing the buffer and *verifying* it per block instead is **~39% slower**
  (streaming both images through cache evicts the table bank, so the next
  block's ~3k scattered lookups miss to DRAM) *and* is a weaker guarantee;
  reusing the buffer and still restoring saves only the allocation, which is
  **not measurable**. Leave it alone.
- `wbc_open` is dominated by the blob's KDF tier — ~96-99% of it at
  `--kdf medium`/`heavy`, and ~0% at `--kdf light`. Measured separately as `kdf`,
  which times whichever derivation the blob's own header selects.

### "How long does my 5 MB payload take?"

There is no `--bulk-mb`, and no benchmark here can answer this on its own, because
the SDK does not move payloads. Since 2.0.0 there is no way to push data through
the white-box (`wbc_encrypt_ecb` and `wbc_crypt_ctr` are gone, replaced by
`wbc_wrap_key` / `wbc_unwrap_key` over exactly one session key), and the AEAD
helpers that used to move the payload were removed too — the caller supplies its
own cipher.

The cost model is two terms, and **only the term we do not own scales**:

- **fixed, ours:** `wrap_key` — two white-box blocks, ~0.5 ms, *regardless of
  payload size*. `wb_bench` prints this as `per payload`.
- **scaling, yours:** your cipher over the payload. A ChaCha20 or
  XChaCha20-Poly1305 pass runs at roughly GB/s, so ~1-2 ms per MiB; measure it in
  your own benchmark, not here.

For reference, native-lib-encryption's `rt_roundtrip` reports ~13.7 ms total for a
5.5 MB `.text` on an aarch64 host: 1.1 ms `wbc_open`, 0.83 ms `wbc_unwrap_key`, and
11.8 ms of its own ChaCha20. Against ~85 s if the payload itself went through the
VM. That is the shape to expect — the white-box terms are flat and small, and the
only line that grows with the data is the caller's.

Note the payload leg is **not** white-box protected, and the session key is
plaintext in memory for its lifetime — see the README's Performance section and the
memory-exposure caveat in `include/wbcrypto.h` for what that does and does not cost
you.

### Reading `open - kdf`

**At `--kdf medium`/`heavy` this subtraction is ill-conditioned** and the tooling
will usually refuse to give you a number. The obfuscated loader in
`trusted_storage.cpp` does a ~0.4 MB AEAD decrypt plus a header parse — around a
millisecond — inside a 60-250 ms KDF whose own run-to-run variation is larger than
that. So `wb_bench` reports a **bound** ("NOT RESOLVABLE (< X ms)") unless the
difference clears 2x the sampling spread.

That bound is the useful answer: the flattened + MBA'd loader costs less than a few
ms of the whole `wbc_open`, i.e. **heavy passes on the cold gate code are
affordable** — exactly the bet `omvll_config.py` makes. More reps tighten the bound
only slowly; a quiet, CPU-pinned device helps more.

Beware the case where it *does* clear the margin at an Argon2id tier: that is
still not the loader. `open` and `kdf` each allocate and fault in a 16/64 MiB
Argon2 arena in a different context, and the difference carries that allocation
artifact. Measured here it overstated the loader several-fold — 8.96 ms at
`heavy` against a ground truth of 1.03 ms. `wb_bench` labels such a value
UPPER BOUND for that reason.

**Re-seal the same blob at `--kdf light` to measure the loader for real.** The
HKDF path costs microseconds, so the subtraction becomes well-conditioned and
`open` *is* the loader. Measured on aarch64 Linux, `open` = **1.03 ms** at
`light` against **195.5 ms** at `heavy` — the first honest figure this repo has
had for the loader's own cost.

### Measurement hygiene (already handled by the script)

- **Interleaved A/B** (`plain, omvll, plain, omvll`). Thermal drift over a session
  is monotonic, so running all of one build then all of the other biases the ratio
  by an unknown amount in favour of whichever ran first.
- **One shared, host-generated blob**, so both builds execute byte-identical
  bytecode. Never seal on device: `AssembleWhiteBox` is in `assembler.cpp`, which is
  in `_MBA_MODULES`, so in-process sealing would itself diverge between builds.
- **CPU pinning** to the highest-max-freq core via `taskset` (degrades gracefully),
  because big.LITTLE migration mid-measurement dwarfs the effect being measured.
- **Min-based statistics.** Under additive noise the minimum is the least
  contaminated estimator, so ratios and subtractions use per-iteration minima.
- **A correctness gate before any timing**, plus a `# ct=` line that
  `bench_compare.sh` asserts is identical across builds. An obfuscation pass that
  breaks the VM is a hard error, never a suspiciously good throughput number.

### Adding another benchmark file — read this first

`omvll_config.py` matches module names by **substring**:

```python
return any(s in n for s in _SENSITIVE_MODULES)   # tuple contains "vm.cpp"
```

So a harness named `bench_wbvm.cpp` matches `"vm.cpp"` (`...wb|vm.cpp|`), also
satisfies `_is_hot`, and gets `break_control_flow` injected **into its own timing
loop in the obfuscated build only**. (This is not hypothetical: `tests/test_vm.cpp`
matches too, and is obfuscated today.) Keep harness filenames free of `vm.cpp`,
`handlers.cpp`, `assembler.cpp`, `fwcrypt.cpp`, `fw_schedule`,
`trusted_storage.cpp`, `wbcrypto.cpp` and `wbcrypto_provision.cpp` as substrings —
`bench_android.sh` preflight-warns if `wb_bench.cpp` ever starts matching.

## Bootstrapping a compiler with Zig (no system compiler / no root)

If the machine has no compiler and no `apt`/root access, a single self-contained
Zig toolchain provides a full clang-based `zig c++`:

```sh
# 1. download the toolchain for your platform from https://ziglang.org/download/
#    (e.g. zig-<arch>-linux-<ver>.tar.xz) and extract it into ./toolchain/
mkdir -p toolchain && tar -xf zig-*.tar.xz -C toolchain

# 2. scripts/build_host.sh auto-detects ./toolchain/zig-*/zig, or make a wrapper:
printf '#!/bin/sh\nexec "%s/zig" c++ "$@"\n' "$PWD/toolchain/zig-<...>" > zig-cxx
chmod +x zig-cxx
CXX=$PWD/zig-cxx ./scripts/build_host.sh test
```

> Note: `.tar.xz` needs `xz` to extract. If `xz` is unavailable, decompress with
> any XZ-capable tool first (e.g. the pure-JS `xz-decompress` npm package),
> then `tar -xf` the resulting `.tar`.

The first `zig c++` invocation builds libc++ once (emitting nullability
warnings) and then caches it; subsequent builds are fast and quiet.

## Compiler flags

`scripts/build_host.sh` compiles with `-std=c++17 -O2 -Isrc -Iinclude -Itests
-Wall -Wextra` (plus anything in `EXTRA_CXXFLAGS`, see
[the O-MVLL section](#with-native-code-obfuscation-o-mvll)). The full build is a
few seconds; there is no incremental object cache — every test binary is linked
against the library sources directly, which keeps the build script trivial and
dependency-free.

## Running the tests

```sh
./scripts/build_host.sh test
```

Expected output — seven passing suites:

```
[PASS] test_aes_ref     reference AES vs FIPS-197
[PASS] test_wbaes       white-box == AES at each stratum (+ random keys)
[PASS] test_vm          VM output == interpreter == AES (plain + hardened)
[PASS] test_obf         MBA / opaque / opcode-blinding primitives
[PASS] test_fw          context-keyed firmware: decode == AES, tamper cascade
[PASS] test_sdk         C-ABI SDK: seal/open, key wrap, KDF tiers, error paths
[PASS] test_e2e         seal→unseal→run, key-absence, anti-tamper
```
