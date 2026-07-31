# Portable build for standard toolchains. Mirrors build.sh (the tested path in
# the dev environment, which has no system cmake). Usage:
#   ./scripts/fetch_libsodium.sh          # vendor the crypto dependency once
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

# Opt-in native-code obfuscation (see docs/OBFUSCATION.md and docs/BUILD.md).
# Point OMVLL_PLUGIN at an LLVM pass-plugin (e.g. O-MVLL) built for THIS clang's
# version; empty by default so normal builds are unaffected. The fully tested
# path is an Android NDK cross-compile — the plugin shipped in this repo,
# obfuscation/omvll_ndk_r29.dylib, is a Mach-O arm64 dylib paired with NDK r29:
#   cmake -GNinja -B build \
#     -DCMAKE_TOOLCHAIN_FILE=$NDK/build/cmake/android.toolchain.cmake \
#     -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-24 \
#     -DOMVLL_PLUGIN=$PWD/obfuscation/omvll_ndk_r29.dylib
# Do NOT also pass -fpass-plugin via CMAKE_CXX_FLAGS — that double-applies it.
set(OMVLL_PLUGIN "" CACHE STRING "Path to an LLVM pass-plugin to load (e.g. O-MVLL)")
if(OMVLL_PLUGIN)
  message(STATUS "==> O-MVLL obfuscation: ON  (-fpass-plugin=${OMVLL_PLUGIN})")
  add_compile_options(-fpass-plugin=${OMVLL_PLUGIN})
  add_link_options(-Wl,-z,muldefs)
else()
  message(STATUS "==> O-MVLL obfuscation: OFF (pass -DOMVLL_PLUGIN=/path/to/plugin to enable)")
endif()

# ---- vendored libsodium (seal KDF + AEAD) ----------------------------------
set(SODIUM_ROOT ${CMAKE_SOURCE_DIR}/third_party/libsodium/libsodium-1.0.20)
set(SODIUM_INC ${SODIUM_ROOT}/src/libsodium/include)
if(NOT EXISTS ${SODIUM_INC}/sodium.h)
  message(FATAL_ERROR "libsodium not vendored. Run: ./scripts/fetch_libsodium.sh")
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
  ${CMAKE_SOURCE_DIR}/src/wbaes/wb_export.cpp
  ${CMAKE_SOURCE_DIR}/src/vm/assembler.cpp
  ${CMAKE_SOURCE_DIR}/src/fw/fwcrypt.cpp
  ${CMAKE_SOURCE_DIR}/src/obf/blinding.cpp
  ${CMAKE_SOURCE_DIR}/src/sdk/wbcrypto_provision.cpp)

set(WBVM_INCLUDES
  ${CMAKE_SOURCE_DIR}/src
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/freestanding
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

# C integration example (full lifecycle -> links the provisioning library).
add_executable(example ${CMAKE_SOURCE_DIR}/examples/example.c)
target_link_libraries(example PRIVATE wbprovision)
set_target_properties(example PROPERTIES LINKER_LANGUAGE CXX)

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
