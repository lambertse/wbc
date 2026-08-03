# Portable build for standard toolchains. Mirrors build.sh (the tested path in
# the dev environment, which has no system cmake). Dependencies are vendored
# automatically at configure time by third_party/fetch_deps.sh. Usage:
#   cmake -S . -B build && cmake --build build && ctest --test-dir build
cmake_minimum_required(VERSION 3.16)
# C is enabled because the SDK integration example (examples/example.c) is C and
# libsodium (the seal's KDF/AEAD dependency) is C.
project(whitebox_crypto_vm C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# ---- symbol & size hygiene -------------------------------------------------
# Hide everything by default; only the wbc_* C ABI (visibility("default") in
# wbcrypto.h) plus the version script below end up exported. gc-sections drops
# dead code. This, with the strip step further down, reverses the shipped
# build's regressions (named internals + DWARF).
set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN ON)
add_compile_options(-ffunction-sections -fdata-sections)

# ---- third-party dependency fetcher ----------------------------------------
# third_party/fetch_deps.sh vendors deps into third_party/ (pinned + SHA256,
# idempotent). CMake runs it at configure time so a fresh checkout never fails
# with "dependency not vendored" — it replaces the old manual step you could
# forget. Targets: libsodium | python | omvll | all.
find_program(BASH_PROGRAM bash)
function(fetch_dep target)
  if(NOT BASH_PROGRAM)
    message(FATAL_ERROR "bash not found; run ./third_party/fetch_deps.sh ${target} by hand")
  endif()
  message(STATUS "==> fetching third-party dependency: ${target}")
  execute_process(
    COMMAND ${BASH_PROGRAM} ${CMAKE_SOURCE_DIR}/third_party/fetch_deps.sh ${target}
    RESULT_VARIABLE _fetch_rc)
  if(NOT _fetch_rc EQUAL 0)
    message(FATAL_ERROR "fetch_deps.sh ${target} failed (rc=${_fetch_rc}); check network/URL")
  endif()
endfunction()

# Opt-in native-code obfuscation (see docs/BUILD.md).
# -DOMVLL=ON fetches the pinned O-MVLL plugin (+ its matching CPython 3.10 stdlib)
# into third_party/ and wires -fpass-plugin automatically. The fully tested path
# is an Android NDK cross-compile; the plugin, third_party/omvll/
# omvll_ndk_r29.dylib, is a Mach-O arm64 dylib paired with NDK r29:
#   cmake -GNinja -B build \
#     -DCMAKE_TOOLCHAIN_FILE=$NDK/build/cmake/android.toolchain.cmake \
#     -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-24 -DOMVLL=ON
# Advanced: set OMVLL_PLUGIN to your own plugin build to override the fetched one.
# Do NOT also pass -fpass-plugin via CMAKE_CXX_FLAGS — that double-applies it.
option(OMVLL "Fetch and enable O-MVLL native-code obfuscation" OFF)
set(OMVLL_PLUGIN "" CACHE STRING "Path to an LLVM pass-plugin to load (overrides -DOMVLL)")
if(OMVLL AND NOT OMVLL_PLUGIN)
  fetch_dep(omvll)
  set(OMVLL_PLUGIN ${CMAKE_SOURCE_DIR}/third_party/omvll/omvll_ndk_r29.dylib)
endif()
if(OMVLL_PLUGIN)
  # Restore the plugin binary if it was deleted. This also covers the explicit
  # -DOMVLL_PLUGIN path (not just -DOMVLL=ON): if it points at the vendored
  # location, re-fetch it; if it points at a custom build that's missing, fail
  # loudly rather than handing clang a nonexistent -fpass-plugin.
  if(NOT EXISTS ${OMVLL_PLUGIN})
    if(OMVLL_PLUGIN STREQUAL "${CMAKE_SOURCE_DIR}/third_party/omvll/omvll_ndk_r29.dylib")
      fetch_dep(omvll)
    else()
      message(FATAL_ERROR "OMVLL_PLUGIN=${OMVLL_PLUGIN} not found. Build your plugin, "
        "point at the vendored one (third_party/omvll/omvll_ndk_r29.dylib), or use -DOMVLL=ON.")
    endif()
  endif()
  # O-MVLL embeds a CPython VM that aborts ("failed to get the Python codec of
  # the filesystem encoding") without a 3.10 stdlib at OMVLL_PYTHONPATH. Ensure
  # it's vendored whenever obfuscation is on — including the explicit
  # -DOMVLL_PLUGIN path, not just -DOMVLL=ON — so a deleted third_party/python is
  # transparently restored. Point OMVLL_PYTHONPATH at third_party/python/Lib.
  if(NOT EXISTS ${CMAKE_SOURCE_DIR}/third_party/python/Lib/abc.py)
    fetch_dep(python)
  endif()
  message(STATUS "==> O-MVLL obfuscation: ON  (-fpass-plugin=${OMVLL_PLUGIN})")
  add_compile_options(-fpass-plugin=${OMVLL_PLUGIN})
  add_link_options(-Wl,-z,muldefs)
else()
  message(STATUS "==> O-MVLL obfuscation: OFF (pass -DOMVLL=ON to fetch+enable)")
endif()

# ---- vendored libsodium (seal KDF + AEAD) ----------------------------------
set(SODIUM_ROOT ${CMAKE_SOURCE_DIR}/third_party/libsodium/libsodium-1.0.20)
set(SODIUM_INC ${SODIUM_ROOT}/src/libsodium/include)
if(NOT EXISTS ${SODIUM_INC}/sodium.h)
  fetch_dep(libsodium)
endif()
if(NOT EXISTS ${SODIUM_INC}/sodium.h)
  message(FATAL_ERROR "libsodium still missing after fetch; run ./third_party/fetch_deps.sh libsodium")
endif()
file(GLOB_RECURSE SODIUM_SOURCES CONFIGURE_DEPENDS ${SODIUM_ROOT}/src/libsodium/*.c)
add_library(sodium_obj OBJECT ${SODIUM_SOURCES})
set_target_properties(sodium_obj PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(sodium_obj PUBLIC ${SODIUM_INC} ${SODIUM_INC}/sodium)
# We build libsodium from source without autotools (portable C only, since the
# HAVE_* feature macros are absent). CONFIGURED=1 silences its "compiled by an
# undocumented method" warning; it gates only that warning, not code selection.
target_compile_definitions(sodium_obj PRIVATE CONFIGURED=1)

# ---- split the library sources ---------------------------------------------
# RUNTIME ships in libwbcrypto.{a,so}; PROVISION (keygen surface) stays host-side.
set(RUNTIME_SOURCES
  ${CMAKE_SOURCE_DIR}/src/vm/vm.cpp
  ${CMAKE_SOURCE_DIR}/src/vm/handlers.cpp
  ${CMAKE_SOURCE_DIR}/src/storage/trusted_storage.cpp
  ${CMAKE_SOURCE_DIR}/src/sdk/wbcrypto.cpp)
set(PROVISION_SOURCES
  ${CMAKE_SOURCE_DIR}/src/wbaes/gf256.cpp
  ${CMAKE_SOURCE_DIR}/src/wbaes/aes_ref.cpp
  ${CMAKE_SOURCE_DIR}/src/wbaes/aes_tables.cpp
  ${CMAKE_SOURCE_DIR}/src/wbaes/encodings.cpp
  ${CMAKE_SOURCE_DIR}/src/wbaes/wb_generator.cpp
  ${CMAKE_SOURCE_DIR}/src/wbaes/wb_interp.cpp
  ${CMAKE_SOURCE_DIR}/src/vm/assembler.cpp
  ${CMAKE_SOURCE_DIR}/src/fw/fwcrypt.cpp
  ${CMAKE_SOURCE_DIR}/src/obf/blinding.cpp
  ${CMAKE_SOURCE_DIR}/src/sdk/wbcrypto_provision.cpp)

set(WBVM_INCLUDES
  ${CMAKE_SOURCE_DIR}/src
  ${CMAKE_SOURCE_DIR}/include
  ${SODIUM_INC})

add_library(wbvm_runtime_obj OBJECT ${RUNTIME_SOURCES})
add_library(wbvm_provision_obj OBJECT ${PROVISION_SOURCES})
foreach(o wbvm_runtime_obj wbvm_provision_obj)
  set_target_properties(${o} PROPERTIES POSITION_INDEPENDENT_CODE ON)
  target_include_directories(${o} PUBLIC ${WBVM_INCLUDES})
endforeach()

# Convenience interface for internal linkers (tools/tests): full source set.
add_library(wbvm STATIC
  $<TARGET_OBJECTS:wbvm_runtime_obj>
  $<TARGET_OBJECTS:wbvm_provision_obj>
  $<TARGET_OBJECTS:sodium_obj>)
target_include_directories(wbvm PUBLIC ${WBVM_INCLUDES})
set_target_properties(wbvm PROPERTIES LINKER_LANGUAGE CXX)

# Runtime SDK static + shared libraries (public C ABI). Runtime objects only.
add_library(wbcrypto_static STATIC
  $<TARGET_OBJECTS:wbvm_runtime_obj> $<TARGET_OBJECTS:sodium_obj>)
add_library(wbcrypto_shared SHARED
  $<TARGET_OBJECTS:wbvm_runtime_obj> $<TARGET_OBJECTS:sodium_obj>)
set_target_properties(wbcrypto_static PROPERTIES OUTPUT_NAME wbcrypto)
set_target_properties(wbcrypto_shared PROPERTIES OUTPUT_NAME wbcrypto)
foreach(sdk wbcrypto_static wbcrypto_shared)
  target_include_directories(${sdk} PUBLIC ${CMAKE_SOURCE_DIR}/include)
  set_target_properties(${sdk} PROPERTIES LINKER_LANGUAGE CXX)
endforeach()

# Export only wbc_* from the shared library, gc dead code, and strip.
target_link_options(wbcrypto_shared PRIVATE
  -Wl,--version-script=${CMAKE_SOURCE_DIR}/src/sdk/wbcrypto.map
  -Wl,--gc-sections
  -Wl,--build-id=none)
if(CMAKE_BUILD_TYPE STREQUAL "Release")
  target_link_options(wbcrypto_shared PRIVATE -Wl,--strip-all)
endif()
# Belt-and-suspenders strip that also removes .comment/producer strings. On the
# NDK path CMAKE_STRIP is llvm-strip; this is the step that reaches the SHIPPED
# artifact (the source of the previous DWARF regression).
if(CMAKE_STRIP)
  add_custom_command(TARGET wbcrypto_shared POST_BUILD
    COMMAND ${CMAKE_STRIP} --strip-all --remove-section=.comment
            $<TARGET_FILE:wbcrypto_shared>
    COMMENT "strip libwbcrypto.so (symbols, debug, .comment)")
endif()

# Host-only provisioning library (adds the keygen surface). Never shipped.
add_library(wbprovision STATIC
  $<TARGET_OBJECTS:wbvm_runtime_obj>
  $<TARGET_OBJECTS:wbvm_provision_obj>
  $<TARGET_OBJECTS:sodium_obj>)
target_include_directories(wbprovision PUBLIC ${CMAKE_SOURCE_DIR}/include)
set_target_properties(wbprovision PROPERTIES LINKER_LANGUAGE CXX)

# Tools: wb_keygen needs the provisioning surface; wb_encrypt is runtime-only.
# Both include internal headers under src/, so give them the internal include
# roots (wbcrypto_static only exposes the public include/ dir).
add_executable(wb_keygen ${CMAKE_SOURCE_DIR}/src/tools/wb_keygen.cpp)
target_link_libraries(wb_keygen PRIVATE wbvm)
add_executable(wb_encrypt ${CMAKE_SOURCE_DIR}/src/tools/wb_encrypt.cpp)
target_link_libraries(wb_encrypt PRIVATE wbcrypto_static)
target_include_directories(wb_encrypt PRIVATE ${WBVM_INCLUDES})

# Benchmark. Links the RUNTIME library only (same shape as wb_encrypt above), so
# it measures what actually ships and can never time the provisioning surface.
# Deliberately NOT registered with add_test(): it asserts nothing, so it has no
# business in ctest. Drive the O-MVLL on/off comparison with
# scripts/bench_android.sh; see docs/BUILD.md ("Benchmarks").
add_executable(wb_bench ${CMAKE_SOURCE_DIR}/bench/wb_bench.cpp)
target_link_libraries(wb_bench PRIVATE wbcrypto_static)
target_include_directories(wb_bench PRIVATE ${WBVM_INCLUDES})

# C integration examples (full lifecycle -> link the provisioning library).
#   example  — the basic open/encrypt lifecycle
#   keywrap  — the pattern to use for real payloads: the white-box wraps a
#              session key, a conventional AEAD moves the data
file(GLOB WBVM_EXAMPLES ${CMAKE_SOURCE_DIR}/examples/*.c)
foreach(ex ${WBVM_EXAMPLES})
    get_filename_component(exname ${ex} NAME_WE)
    add_executable(${exname} ${ex})
    target_link_libraries(${exname} PRIVATE wbprovision)
    set_target_properties(${exname} PROPERTIES LINKER_LANGUAGE CXX)
endforeach()

# Tests (link the full source set).
enable_testing()
file(GLOB TEST_SOURCES ${CMAKE_SOURCE_DIR}/tests/test_*.cpp)
foreach(test_src ${TEST_SOURCES})
  get_filename_component(test_name ${test_src} NAME_WE)
  add_executable(${test_name} ${test_src})
  target_include_directories(${test_name} PRIVATE ${CMAKE_SOURCE_DIR}/tests)
  target_link_libraries(${test_name} PRIVATE wbvm)
  add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()
