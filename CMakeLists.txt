# Portable build for standard toolchains. Mirrors build.sh (the tested path in
# the dev environment, which has no system cmake). Usage:
#   cmake -S . -B build && cmake --build build && ctest --test-dir build
cmake_minimum_required(VERSION 3.16)
# C is enabled because the SDK integration example (examples/example.c) is C;
# without it CMake can't pick a linker language for that target.
project(whitebox_crypto_vm C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

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
  message(STATUS "native-code obfuscation: -fpass-plugin=${OMVLL_PLUGIN}")
  add_compile_options(-fpass-plugin=${OMVLL_PLUGIN})
  # O-MVLL clones functions with numeric suffixes; a cloned EH/runtime helper can
  # leak as a strong global and collide (duplicate symbol __clang_call_terminate.N).
  # Excluding those helpers in omvll_config.py is the real fix; this is a
  # belt-and-suspenders fallback (lld/GNU ld only — the NDK path uses lld).
  add_link_options(-Wl,-z,muldefs)
endif()

file(GLOB_RECURSE LIB_SOURCES CONFIGURE_DEPENDS
  ${CMAKE_SOURCE_DIR}/src/wbaes/*.cpp
  ${CMAKE_SOURCE_DIR}/src/vm/*.cpp
  ${CMAKE_SOURCE_DIR}/src/fw/*.cpp
  ${CMAKE_SOURCE_DIR}/src/obf/*.cpp
  ${CMAKE_SOURCE_DIR}/src/storage/*.cpp
  ${CMAKE_SOURCE_DIR}/src/sdk/*.cpp)

# Core objects, compiled once with -fPIC so both the archive and the shared
# library can reuse them.
# Include roots: src (library headers), include (public SDK header), and
# freestanding (wb_table_layout.h / wb_stub.h, used by wb_export.cpp and tests).
set(WBVM_INCLUDES
  ${CMAKE_SOURCE_DIR}/src
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/freestanding)

add_library(wbvm_obj OBJECT ${LIB_SOURCES})
set_target_properties(wbvm_obj PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(wbvm_obj PUBLIC ${WBVM_INCLUDES})

# Convenience interface for internal linkers (tools/tests).
add_library(wbvm STATIC $<TARGET_OBJECTS:wbvm_obj>)
target_include_directories(wbvm PUBLIC ${WBVM_INCLUDES})

# SDK static + shared libraries (public C ABI).
add_library(wbcrypto_static STATIC $<TARGET_OBJECTS:wbvm_obj>)
add_library(wbcrypto_shared SHARED $<TARGET_OBJECTS:wbvm_obj>)
set_target_properties(wbcrypto_static PROPERTIES OUTPUT_NAME wbcrypto)
set_target_properties(wbcrypto_shared PROPERTIES OUTPUT_NAME wbcrypto)
foreach(sdk wbcrypto_static wbcrypto_shared)
  target_include_directories(${sdk} PUBLIC ${CMAKE_SOURCE_DIR}/include)
  # These libraries are assembled purely from wbvm_obj's object files, so give
  # CMake an explicit linker language (they contain C++).
  set_target_properties(${sdk} PROPERTIES LINKER_LANGUAGE CXX)
endforeach()

# Tools
foreach(tool wb_keygen wb_encrypt)
  add_executable(${tool} ${CMAKE_SOURCE_DIR}/src/tools/${tool}.cpp)
  target_link_libraries(${tool} PRIVATE wbvm)
endforeach()

# C integration example (links the shared SDK library). Link with the C++
# driver so the C++ runtime the library needs is pulled in.
add_executable(example ${CMAKE_SOURCE_DIR}/examples/example.c)
target_link_libraries(example PRIVATE wbcrypto_shared)
set_target_properties(example PROPERTIES LINKER_LANGUAGE CXX)

# Tests
enable_testing()
file(GLOB TEST_SOURCES ${CMAKE_SOURCE_DIR}/tests/test_*.cpp)
foreach(test_src ${TEST_SOURCES})
  get_filename_component(test_name ${test_src} NAME_WE)
  add_executable(${test_name} ${test_src})
  target_include_directories(${test_name} PRIVATE ${CMAKE_SOURCE_DIR}/tests)
  target_link_libraries(${test_name} PRIVATE wbvm)
  add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()
