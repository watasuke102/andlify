#pragma once

#include <string>

inline constexpr char kInotifyMaxUserWatchesPath[] =
    "/proc/sys/fs/inotify/max_user_watches";
inline constexpr char kInotifyMaxUserWatchesBackingPath[] =
    "/tmp/.andlify-inotify-max-user-watches";

std::string NormalizeRootfsPrefix(const std::string& rootfs_path);
bool        IsAbsoluteUnixPath(const std::string& path);
bool        IsPassthroughUnixPath(const std::string& path);
std::string RewritePathToRootfs(
    const std::string& normalized_rootfs, const std::string& original_path);
std::string BuildRealPathInRootfs(
    const std::string& rootfs_path, const std::string& command_path_in_rootfs);
