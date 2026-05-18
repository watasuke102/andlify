#include "ptrace_engine.h"
#include "rootfs_extractor.h"

#include <jni.h>

#include <string>

namespace {

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

jboolean JniIsRootfsExtracted(JNIEnv* env, jobject /*thiz*/, jstring extract_dst_path) {
    const std::string path = JStringToUtf8(env, extract_dst_path);
    return IsRootfsExtracted(path) ? JNI_TRUE : JNI_FALSE;
}

jboolean JniExtractRootfs(JNIEnv* env, jobject /*thiz*/, jstring archive_path, jstring extract_dst_path) {
    const std::string archive = JStringToUtf8(env, archive_path);
    const std::string destination = JStringToUtf8(env, extract_dst_path);
    return ExtractRootfs(archive, destination) ? JNI_TRUE : JNI_FALSE;
}

jint JniStartChroot(
    JNIEnv* env,
    jobject /*thiz*/,
    jstring extract_dst_path,
    jstring command_path_in_rootfs,
    jint stdin_fd,
    jint stdout_fd,
    jint stderr_fd) {
    const std::string rootfs_path = JStringToUtf8(env, extract_dst_path);
    const std::string command = JStringToUtf8(env, command_path_in_rootfs);
    return static_cast<jint>(StartChroot(
        rootfs_path,
        command,
        static_cast<int>(stdin_fd),
        static_cast<int>(stdout_fd),
        static_cast<int>(stderr_fd)));
}

void JniStopChroot(JNIEnv* /*env*/, jobject /*thiz*/, jint pid) {
    StopChroot(static_cast<pid_t>(pid));
}

}  // namespace

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* /*reserved*/) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK || env == nullptr) {
        return JNI_ERR;
    }

    jclass clazz = env->FindClass("com/andlify/library/ChrootNative");
    if (clazz == nullptr) {
        return JNI_ERR;
    }

    static const JNINativeMethod methods[] = {
        {"is_rootfs_extracted", "(Ljava/lang/String;)Z", reinterpret_cast<void*>(JniIsRootfsExtracted)},
        {"extract_rootfs", "(Ljava/lang/String;Ljava/lang/String;)Z", reinterpret_cast<void*>(JniExtractRootfs)},
        {"start_chroot", "(Ljava/lang/String;Ljava/lang/String;III)I", reinterpret_cast<void*>(JniStartChroot)},
        {"stop_chroot", "(I)V", reinterpret_cast<void*>(JniStopChroot)},
    };

    if (env->RegisterNatives(clazz, methods, sizeof(methods) / sizeof(methods[0])) != JNI_OK) {
        return JNI_ERR;
    }

    return JNI_VERSION_1_6;
}
