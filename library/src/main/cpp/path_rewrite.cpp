#include "path_rewrite.h"

std::string NormalizeRootfsPrefix(const std::string& rootfs_path) {
    if (rootfs_path.empty()) {
        return "/";
    }

    std::string normalized = rootfs_path;
    while (normalized.size() > 1 && normalized.back() == '/') {
        normalized.pop_back();
    }
    return normalized;
}

bool IsAbsoluteUnixPath(const std::string& path) {
    return !path.empty() && path[0] == '/';
}

std::string RewritePathToRootfs(const std::string& normalized_rootfs, const std::string& original_path) {
    if (!IsAbsoluteUnixPath(original_path)) {
        return original_path;
    }

    if (normalized_rootfs == "/") {
        return original_path;
    }

    if (original_path == "/") {
        return normalized_rootfs;
    }

    if (original_path.rfind(normalized_rootfs, 0) == 0) {
        return original_path;
    }

    if (original_path == "/dev" || original_path == "/dev/") {
        // Fall through to rewrite to rootfs to avoid Permission Denied on ls /dev
    } else if (original_path.rfind("/dev/", 0) == 0 ||
               original_path == "/proc" || original_path.rfind("/proc/", 0) == 0 ||
               original_path == "/sys" || original_path.rfind("/sys/", 0) == 0) {
        return original_path;
    }

    return normalized_rootfs + original_path;
}

std::string BuildRealPathInRootfs(const std::string& rootfs_path, const std::string& command_path_in_rootfs) {
    const std::string normalized_rootfs = NormalizeRootfsPrefix(rootfs_path);
    if (command_path_in_rootfs.empty()) {
        return normalized_rootfs;
    }

    if (IsAbsoluteUnixPath(command_path_in_rootfs)) {
        return RewritePathToRootfs(normalized_rootfs, command_path_in_rootfs);
    }

    if (normalized_rootfs == "/") {
        return "/" + command_path_in_rootfs;
    }
    return normalized_rootfs + "/" + command_path_in_rootfs;
}
