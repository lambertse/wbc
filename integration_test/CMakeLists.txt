# CMakeLists.txt — standalone third-party integration of the White-box Crypto VM SDK.
#
# It links ONLY the runtime library (libwbcrypto) and the public header (wbcrypto.h),
# exactly as a shipped field app would. It does NOT build the SDK itself.
#
# Quick start (from this directory):
#     cmake -S . -B build
#     cmake --build build
#     ./build/field_app                 # opens the bundled sealed.blob with pass "demo"
#
# By default it discovers the header in ../include and the library in ../build
# (where this repo's top-level build places libwbcrypto.{so,a,dylib}). Override:
#     cmake -S . -B build -DWBC_ROOT=/path/to/sdk
#     cmake -S . -B build -DWBC_INCLUDE_DIR=/inc -DWBC_LIB_DIR=/libdir
#
# NOTE: use a libwbcrypto built for YOUR run target. The libwbcrypto.so committed at
# ../build is an Android/aarch64 (bionic) build and will not load on a desktop glibc
# host; rebuild the SDK for your platform (./build.sh) or point WBC_LIB_DIR at a native
# build. Android: consume via the NDK toolchain / Gradle externalNativeBuild instead.

cmake_minimum_required(VERSION 3.16)
project(wbc_integration_test LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# --- Locate the SDK header + runtime library --------------------------------
set(WBC_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/.." CACHE PATH "SDK root")
set(WBC_INCLUDE_DIR "${WBC_ROOT}/include" CACHE PATH "dir containing wbcrypto.h")
set(WBC_LIB_DIR     "${WBC_ROOT}/build"   CACHE PATH "dir containing libwbcrypto")

# Static linking bakes libwbcrypto.a (which already bundles libsodium) into
# field_app, so there is no runtime .so/.dylib to locate — no rpath, no install
# name, no loader lookup. Prefer the static archive so find_library resolves
# libwbcrypto.a instead of the shared lib (which it prefers by default).
option(WBC_STATIC "Link libwbcrypto statically (.a) — self-contained binary" ON)
if(WBC_STATIC)
  set(CMAKE_FIND_LIBRARY_SUFFIXES .a)
endif()

find_path(WBC_HEADER wbcrypto.h HINTS "${WBC_INCLUDE_DIR}" REQUIRED)
find_library(WBC_LIB NAMES wbcrypto libwbcrypto HINTS "${WBC_LIB_DIR}" REQUIRED)

message(STATUS "wbcrypto.h : ${WBC_HEADER}/wbcrypto.h")
if(WBC_STATIC)
  message(STATUS "libwbcrypto: ${WBC_LIB}  (static)")
else()
  message(STATUS "libwbcrypto: ${WBC_LIB}  (shared)")
endif()

# --- The field app ----------------------------------------------------------
add_executable(field_app field_app.cpp)
target_include_directories(field_app PRIVATE "${WBC_HEADER}")
target_link_libraries(field_app PRIVATE "${WBC_LIB}")

# Passphrase compiled into the binary (matches the bundled sealed.blob).
target_compile_definitions(field_app PRIVATE WBC_APP_PASSPHRASE="demo")

if(WBC_STATIC)
  # libsodium (vendored into the archive) uses pthreads on some platforms; the
  # static link must pull them in itself (a shared .so would list them as NEEDED).
  # Threads::Threads is a no-op where the C library already provides them (macOS).
  find_package(Threads REQUIRED)
  target_link_libraries(field_app PRIVATE Threads::Threads)
else()
  # Shared lib only: give the loader a runtime search path (no LD_LIBRARY_PATH).
  set_target_properties(field_app PROPERTIES
      BUILD_RPATH   "${WBC_LIB_DIR}"
      INSTALL_RPATH "${WBC_LIB_DIR}")
endif()

# Put the sealed blob next to the executable so `./build/field_app` just works.
add_custom_command(TARGET field_app POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_CURRENT_SOURCE_DIR}/sealed.blob"
            "$<TARGET_FILE_DIR:field_app>/sealed.blob"
    COMMENT "Staging sealed.blob next to field_app")
