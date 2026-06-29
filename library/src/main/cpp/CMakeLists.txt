cmake_minimum_required(VERSION 3.22.1)
project(andlify_chroot LANGUAGES C CXX)

if(NOT ANDROID)
    message(FATAL_ERROR "This project is intended for Android NDK builds.")
endif()

if(NOT ANDROID_ABI STREQUAL "arm64-v8a")
    message(FATAL_ERROR "Only arm64-v8a (AArch64) is supported.")
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

include(FetchContent)

set(ZSTD_BUILD_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ZSTD_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(ZSTD_BUILD_STATIC ON CACHE BOOL "" FORCE)
FetchContent_Declare(
    zstd
    URL https://github.com/facebook/zstd/archive/refs/tags/v1.5.7.tar.gz
    SOURCE_SUBDIR build/cmake
)
FetchContent_MakeAvailable(zstd)

set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(ENABLE_TEST OFF CACHE BOOL "" FORCE)
set(ENABLE_TAR OFF CACHE BOOL "" FORCE)
set(ENABLE_CPIO OFF CACHE BOOL "" FORCE)
set(ENABLE_CAT OFF CACHE BOOL "" FORCE)
set(ENABLE_ACL OFF CACHE BOOL "" FORCE)
set(ENABLE_XATTR OFF CACHE BOOL "" FORCE)
set(ENABLE_BZip2 OFF CACHE BOOL "" FORCE)
set(ENABLE_LZ4 OFF CACHE BOOL "" FORCE)
set(ENABLE_LZMA OFF CACHE BOOL "" FORCE)
set(ENABLE_ZLIB OFF CACHE BOOL "" FORCE)
set(ENABLE_EXPAT OFF CACHE BOOL "" FORCE)
set(ENABLE_ICONV OFF CACHE BOOL "" FORCE)
set(ENABLE_OPENSSL OFF CACHE BOOL "" FORCE)
set(ENABLE_NETTLE OFF CACHE BOOL "" FORCE)
set(ENABLE_ZSTD OFF CACHE BOOL "" FORCE)

set(ENABLE_WERROR OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
    libarchive
    URL https://github.com/libarchive/libarchive/releases/download/v3.8.8/libarchive-3.8.8.tar.xz
)
FetchContent_MakeAvailable(libarchive)

add_library(andlify_core STATIC
    path_rewrite.cpp
    ptrace_memory.cpp
    ptrace_engine.cpp
    rootfs_extractor.cpp
)
target_compile_definitions(andlify_core PRIVATE _GNU_SOURCE)
target_include_directories(andlify_core PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")

add_library(andlify_chroot SHARED
    chroot_jni.cpp
)
target_compile_definitions(andlify_chroot PRIVATE _GNU_SOURCE)
target_include_directories(andlify_chroot PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")

if(TARGET archive_static)
    set(LIBARCHIVE_TARGET archive_static)
elseif(TARGET archive)
    set(LIBARCHIVE_TARGET archive)
else()
    message(FATAL_ERROR "libarchive target not found.")
endif()

if(TARGET libzstd_static)
    set(LIBZSTD_TARGET libzstd_static)
elseif(TARGET zstd::libzstd_static)
    set(LIBZSTD_TARGET zstd::libzstd_static)
elseif(TARGET zstd_static)
    set(LIBZSTD_TARGET zstd_static)
elseif(TARGET libzstd)
    set(LIBZSTD_TARGET libzstd)
else()
    message(FATAL_ERROR "libzstd static target not found.")
endif()

target_link_libraries(
    andlify_core
    PUBLIC
    ${LIBARCHIVE_TARGET}
    ${LIBZSTD_TARGET}
    log
)

target_link_libraries(
    andlify_chroot
    PRIVATE
    andlify_core
)
