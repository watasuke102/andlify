# Andlify

A library that provides a **non-root, ptrace-based chroot-like execution environment**

It enables the extraction of a Linux rootfs (supports `tar` and `tar.zst`) and allows dynamic ELF binaries to run directly on Android without requiring a rooted device.

The ptrace engine intercepts syscalls (such as `openat`, `chdir`, `execve`, etc.) and rewrites paths to seamlessly map interactions into the extracted rootfs, creating an isolated, native-like Linux environment.

Currently, Andlify is optimized for **arm64-v8a** architectures with `minSdk` and `targetSdk` set to **28**.

## Usage

### 1. Using from another Android Project (Gradle)

1. Add the JitPack repository to your root `settings.gradle.kts` or `build.gradle.kts`:
   ```kotlin
   dependencyResolutionManagement {
       repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
       repositories {
           google()
           mavenCentral()
           maven("https://jitpack.io")
       }
   }
   ```
2. Add the dependency to your app's `build.gradle.kts`:
   ```kotlin
   dependencies {
       implementation("com.github.watasuke102:andlify:TagOrCommitHash")
   }
   ```
3. Put `.tar.zst` formatted file to `src/main/assets/`

See `example/`.

### 2. Using from a C++ Project (CMake)

1. Add this repository as a Git submodule to your C++ project:
   ```bash
   git submodule add https://github.com/watasuke102/andlify.git 3rdparty/andlify
   ```
2. In your top-level `CMakeLists.txt`, include the repository directory:

   ```cmake
   add_subdirectory(3rdparty/andlify)
   add_executable(example main.cpp)
   target_link_libraries(example PRIVATE andlify_core)
   ```

3. Include the necessary headers (like `ptrace_engine.h` and `rootfs_extractor.h`) directly from `3rdparty/andlify/library/src/main/cpp` in your C++ code to invoke the engine natively.

---

## Architecture

- **`andlify_core`** (Static C++ Library): The heart of the ptrace interception, memory management, syscall rewriting, and rootfs extraction (`libarchive`, `libzstd`).
- **`andlify_chroot`** (Shared C++ Library): An Android-specific wrapper that exposes the `andlify_core` functions via JNI to Kotlin.
- **`example`**: An Android app demonstrating the rootfs extraction and a functioning chat-like shell UI.

## License

Dual-licensed; MIT (`LICENSE-MIT` or [The MIT License – Open Source Initiative](https://opensource.org/license/mit/)) or MIT SUSHI-WARE LICENSE (`LICENSE-MIT_SUSHI.md`)
