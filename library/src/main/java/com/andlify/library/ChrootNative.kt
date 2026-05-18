package com.andlify.library

object ChrootNative {
    init {
        System.loadLibrary("andlify_chroot")
    }

    external fun is_rootfs_extracted(extractDstPath: String): Boolean

    external fun extract_rootfs(archivePath: String, extractDstPath: String): Boolean

    external fun start_chroot(
        extractDstPath: String,
        commandPathInRootfs: String,
        stdinFd: Int,
        stdoutFd: Int,
        stderrFd: Int,
    ): Int

    external fun stop_chroot(pid: Int)
}
