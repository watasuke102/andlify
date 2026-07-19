#include <android/log.h>
#include <jni.h>

#include <string>

#include "ptrace_engine.h"
#include "rootfs_extractor.h"

namespace {

constexpr const char* kLogTag = "andlify-rootfs";

std::string JStringToUtf8(JNIEnv* env, jstring value) {
  if (value == nullptr) {
    return {};
  }

  const char* utf8 = env->GetStringUTFChars(value, nullptr);
  if (utf8 == nullptr) {
    return {};
  }

  std::string result(utf8);
  env->ReleaseStringUTFChars(value, utf8);
  return result;
}

jboolean JniIsRootfsExtracted(
    JNIEnv* env, jobject /*thiz*/, jstring extract_dst_path) {
  const std::string path = JStringToUtf8(env, extract_dst_path);
  return IsRootfsExtracted(path) ? JNI_TRUE : JNI_FALSE;
}

jboolean JniExtractRootfs(JNIEnv* env, jobject /*thiz*/, jstring archive_path,
    jstring extract_dst_path) {
  const std::string archive     = JStringToUtf8(env, archive_path);
  const std::string destination = JStringToUtf8(env, extract_dst_path);
  const bool        ok          = ExtractRootfs(archive, destination);
  if (!ok) {
    __android_log_print(ANDROID_LOG_ERROR, kLogTag,
        "JNI extract_rootfs failed, archive=%s dst=%s", archive.c_str(),
        destination.c_str());
  }
  return ok ? JNI_TRUE : JNI_FALSE;
}

jint JniStartChroot(JNIEnv* env, jobject /*thiz*/, jstring extract_dst_path,
    jstring command_path_in_rootfs, jint stdin_fd, jint stdout_fd,
    jint stderr_fd) {
  const std::string rootfs_path = JStringToUtf8(env, extract_dst_path);
  const std::string command     = JStringToUtf8(env, command_path_in_rootfs);
  return static_cast<jint>(
      StartChroot(rootfs_path, command, static_cast<int>(stdin_fd),
          static_cast<int>(stdout_fd), static_cast<int>(stderr_fd)));
}

void JniStopChroot(JNIEnv* /*env*/, jobject /*thiz*/, jint pid) {
  StopChroot(static_cast<pid_t>(pid));
}

jint JniStartChrootFunc(JNIEnv* env, jobject /*thiz*/, jstring extract_dst_path,
    jobject runnable, jint stdin_fd, jint stdout_fd, jint stderr_fd) {
  const std::string rootfs_path = JStringToUtf8(env, extract_dst_path);

  auto child_func = [env, runnable]() -> int {
    jclass runnable_class = env->GetObjectClass(runnable);
    if (!runnable_class)
      return 1;
    jmethodID run_method = env->GetMethodID(runnable_class, "run", "()V");
    if (!run_method)
      return 1;

    env->CallVoidMethod(runnable, run_method);

    if (env->ExceptionCheck()) {
      env->ExceptionDescribe();
      env->ExceptionClear();
      return 1;
    }
    return 0;
  };

  return static_cast<jint>(
      StartChrootFunc(rootfs_path, child_func, static_cast<int>(stdin_fd),
          static_cast<int>(stdout_fd), static_cast<int>(stderr_fd)));
}

}  // namespace

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* /*reserved*/) {
  JNIEnv* env = nullptr;
  if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK ||
      env == nullptr) {
    return JNI_ERR;
  }

  jclass clazz = env->FindClass("com/andlify/library/ChrootNative");
  if (clazz == nullptr) {
    return JNI_ERR;
  }

  static const JNINativeMethod methods[] = {
      {"is_rootfs_extracted", "(Ljava/lang/String;)Z",
       reinterpret_cast<void*>(JniIsRootfsExtracted)                                                                },
      {"extract_rootfs",      "(Ljava/lang/String;Ljava/lang/String;)Z",
       reinterpret_cast<void*>(JniExtractRootfs)                                                                    },
      {"start_chroot",        "(Ljava/lang/String;Ljava/lang/String;III)I",
       reinterpret_cast<void*>(JniStartChroot)                                                                      },
      {"start_chroot_func",   "(Ljava/lang/String;Ljava/lang/Runnable;III)I",
       reinterpret_cast<void*>(JniStartChrootFunc)                                                                  },
      {"stop_chroot",         "(I)V",                                         reinterpret_cast<void*>(JniStopChroot)},
  };

  if (env->RegisterNatives(
          clazz, methods, sizeof(methods) / sizeof(methods[0])) != JNI_OK) {
    return JNI_ERR;
  }

  return JNI_VERSION_1_6;
}
