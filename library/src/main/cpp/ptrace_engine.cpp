#include "ptrace_engine.h"

#include <android/log.h>
#include <asm/ptrace.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/memfd.h>
#include <linux/netlink.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/stat.h>
#include <net/if.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <charconv>
#include <deque>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "elf_exec.h"
#include "path_rewrite.h"
#include "ptrace_memory.h"

namespace {

constexpr const char* kLogTag                 = "andlify-ptrace";
constexpr uint64_t    kSysSetxattr            = 5;
constexpr uint64_t    kSysLsetxattr           = 6;
constexpr uint64_t    kSysGetxattr            = 8;
constexpr uint64_t    kSysLgetxattr           = 9;
constexpr uint64_t    kSysListxattr           = 11;
constexpr uint64_t    kSysLlistxattr          = 12;
constexpr uint64_t    kSysRemovexattr         = 14;
constexpr uint64_t    kSysLremovexattr        = 15;
constexpr uint64_t    kSysMknodat             = 33;
constexpr uint64_t    kSysEventfd2            = 19;
constexpr uint64_t    kSysClose               = 57;
constexpr uint64_t    kSysUmount2             = 39;
constexpr uint64_t    kSysMount               = 40;
constexpr uint64_t    kSysPivotRoot           = 41;
constexpr uint64_t    kSysMkdirat             = 34;
constexpr uint64_t    kSysUnlinkat            = 35;
constexpr uint64_t    kSysSymlinkat           = 36;
constexpr uint64_t    kSysLinkat              = 37;
constexpr uint64_t    kSysRenameat            = 38;
constexpr uint64_t    kSysStatfs              = 43;
constexpr uint64_t    kSysFaccessat           = 48;
constexpr uint64_t    kSysChdir               = 49;
constexpr uint64_t    kSysFchmodat            = 53;
constexpr uint64_t    kSysFchownat            = 54;
constexpr uint64_t    kSysFchown              = 55;
constexpr uint64_t    kSysOpenat              = 56;
constexpr uint64_t    kSysReadlinkat          = 78;
constexpr uint64_t    kSysNewfstatat          = 79;
constexpr uint64_t    kSysFstat               = 80;
constexpr uint64_t    kSysUtimensat           = 88;
constexpr uint64_t    kSysRenameat2           = 276;
constexpr uint64_t    kSysStatx               = 291;
constexpr uint64_t    kSysOpenat2             = 437;
constexpr uint64_t    kSysFaccessat2          = 439;
constexpr uint64_t    kSysExecve              = 221;
constexpr uint64_t    kSysExecveat            = 281;
constexpr uint64_t    kSysCapset              = 91;
constexpr uint64_t    kSysSocket              = 198;
constexpr uint64_t    kSysBind                = 200;
constexpr uint64_t    kSysAccept              = 202;
constexpr uint64_t    kSysConnect             = 203;
constexpr uint64_t    kSysSendto              = 206;
constexpr uint64_t    kSysRecvfrom            = 207;
constexpr uint64_t    kSysGetsockopt          = 209;
constexpr uint64_t    kSysSendmsg             = 211;
constexpr uint64_t    kSysRecvmsg             = 212;
constexpr uint64_t    kSysAccept4             = 242;
constexpr uint64_t    kSysPrlimit64           = 261;
constexpr uint64_t    kSysSetregid            = 143;
constexpr uint64_t    kSysSetgid              = 144;
constexpr uint64_t    kSysSetreuid            = 145;
constexpr uint64_t    kSysSetuid              = 146;
constexpr uint64_t    kSysSetresuid           = 147;
constexpr uint64_t    kSysGetresuid           = 148;
constexpr uint64_t    kSysSetresgid           = 149;
constexpr uint64_t    kSysGetresgid           = 150;
constexpr uint64_t    kSysSetfsuid            = 151;
constexpr uint64_t    kSysSetfsgid            = 152;
constexpr uint64_t    kSysGetgroups           = 158;
constexpr uint64_t    kSysSetgroups           = 159;
constexpr uint64_t    kSysGetrlimit           = 163;
constexpr uint64_t    kSysSetrlimit           = 164;
constexpr uint64_t    kSysPrctl               = 167;
constexpr uint64_t    kSysClone               = 220;
constexpr uint64_t    kSysUnshare             = 97;
constexpr uint64_t    kSysClone3              = 435;
constexpr uint64_t    kSysGetpid              = 172;
constexpr uint64_t    kSysGetuid              = 174;
constexpr uint64_t    kSysGeteuid             = 175;
constexpr uint64_t    kSysGetgid              = 176;
constexpr uint64_t    kSysGetegid             = 177;
constexpr uint64_t    kSysIoctl               = 29;
constexpr uint64_t    kSysGetcwd              = 17;
constexpr uint64_t    kTcgets                 = 0x5401;
constexpr uint64_t    kTcsets                 = 0x5402;
constexpr uint64_t    kTcsetsw                = 0x5403;
constexpr uint64_t    kTcsetsf                = 0x5404;
constexpr uint64_t    kTcgets2                = 0x802c542A;
constexpr uint64_t    kTcsets2                = 0x402c542B;
constexpr uint64_t    kTcsetsw2               = 0x402c542C;
constexpr uint64_t    kTcsetsf2               = 0x402c542D;
constexpr uint64_t    kTiocgpgrp              = 0x540F;
constexpr uint64_t    kTiocspgrp              = 0x5410;
constexpr uint64_t    kTiocgwinsz             = 0x5413;
constexpr uint64_t    kSiocgifindex           = 0x8933;
constexpr size_t      kPathReadLimit          = 4096;
constexpr uint64_t    kStackScratchOffset     = 0x800;
constexpr uint64_t    kExecScratchSize        = 0x2000;
constexpr size_t      kMaxSymlinkDepth        = 40;
constexpr uint64_t    kRootUid                = 0;
constexpr uint64_t    kRootGid                = 0;
constexpr uint64_t    kAfUnix                 = 1;
constexpr uint64_t    kAfInet                 = 2;
constexpr uint64_t    kAfInet6                = 10;
constexpr uint64_t    kAfNetlink              = 16;
constexpr uint64_t    kSockDgram              = 2;
constexpr uint64_t    kSockRaw                = 3;
constexpr uint64_t    kSockTypeMask           = 0xf;
constexpr uint64_t    kIpProtoIcmp            = 1;
constexpr uint64_t    kIpProtoIcmpv6          = 58;
constexpr uint64_t    kNetlinkAudit           = 9;
constexpr uint64_t    kNetlinkRoute           = 0;
constexpr uint32_t    kUnchangedId            = UINT32_MAX;
constexpr uint64_t    kResolveNoMagiclinks    = 0x02;
constexpr uint64_t    kResolveInRoot          = 0x10;
constexpr uint64_t    kMaxSupplementaryGroups = 65536;
constexpr size_t      kMaxControlMessageSize  = 65536;
constexpr uint64_t    kNamespaceCloneFlags =
    CLONE_NEWCGROUP | CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWNS | CLONE_NEWPID |
    CLONE_NEWUSER | CLONE_NEWUTS;
constexpr const char* kDefaultEnvironment[][2] = {
    {"PATH",    "/usr/bin:/bin:/usr/sbin:/sbin"},
    {"HOME",    "/root"                        },
    {"USER",    "root"                         },
    {"LOGNAME", "root"                         },
    {"PWD",     "/"                            },
    {"TERM",    "xterm-256color"               },
    {"TMPDIR",  "/tmp"                         },
};

constexpr char kInotifyMaxUserWatchesValue[] = "8192\n";
constexpr char kOverflowIdValue[]            = "65534\n";

struct ProcessExecutable {
  std::shared_ptr<ElfExecutable> image;
  std::shared_ptr<ElfExecutable> interpreter;
  std::string                    execfn;
  std::string                    comm;
  int                            auxv_fd = -1;

  ~ProcessExecutable() {
    if (auxv_fd >= 0)
      close(auxv_fd);
  }
};

struct TraceeState {
  bool                               expect_entry               = true;
  bool                               options_applied            = false;
  bool                               has_emulated_return        = false;
  bool                               emulated_mount_namespace   = false;
  bool                               emulated_network_namespace = false;
  bool                               emulated_user_namespace    = false;
  bool                               pending_netlink_route_fd   = false;
  bool                               pending_openat2_retry      = false;
  uint64_t                           emulated_return            = 0;
  uint64_t                           pending_openat_dirfd       = 0;
  uint64_t                           pending_openat_path        = 0;
  uint64_t                           pending_openat_flags       = 0;
  uint64_t                           pending_openat_mode        = 0;
  std::shared_ptr<ProcessExecutable> executable;
  std::shared_ptr<ProcessExecutable> pending_executable;
  std::string                        pending_open_permission_path;
  std::string                        emulated_new_root;
  std::string                        emulated_old_root;
  std::string                        emulated_mountinfo_path;
  mode_t                             pending_open_permission_mode = 0;
  uint32_t                           real_uid                     = kRootUid;
  uint32_t                           effective_uid                = kRootUid;
  uint32_t                           saved_uid                    = kRootUid;
  uint32_t                           fs_uid                       = kRootUid;
  uint32_t                           real_gid                     = kRootGid;
  uint32_t                           effective_gid                = kRootGid;
  uint32_t                           saved_gid                    = kRootGid;
  uint32_t                           fs_gid                       = kRootGid;
  std::vector<uint32_t>              supplementary_groups{kRootGid};
  std::unordered_set<std::string>    copied_lock_sources;
  std::unordered_set<std::string>    emulated_mount_nodes;
  std::unordered_set<std::string>    emulated_mount_points{"/"};
  std::unordered_map<std::string, std::string> emulated_bind_mounts;
  std::unordered_map<int, uint32_t>            emulated_netlink_route_fds;
  rlimit                                       file_descriptor_limit{};
};

std::string ResolveEmulatedBindMounts(
    const TraceeState& state, const std::string& path) {
  std::string resolved_path = path;
  for (size_t depth = 0; depth <= state.emulated_bind_mounts.size(); ++depth) {
    const std::pair<const std::string, std::string>* best_match = nullptr;
    for (const auto& mount : state.emulated_bind_mounts) {
      if (resolved_path != mount.first &&
          resolved_path.rfind(mount.first + "/", 0) != 0) {
        continue;
      }
      if (best_match == nullptr ||
          mount.first.size() > best_match->first.size()) {
        best_match = &mount;
      }
    }
    if (best_match == nullptr) {
      return resolved_path;
    }

    const std::string suffix = resolved_path.substr(best_match->first.size());
    const std::string next_path = best_match->second == "/" ?
                                      (suffix.empty() ? "/" : suffix) :
                                      best_match->second + suffix;
    if (next_path == resolved_path) {
      return resolved_path;
    }
    resolved_path = next_path;
  }
  return resolved_path;
}

struct UnixCredentials {
  int32_t  pid;
  uint32_t uid;
  uint32_t gid;
};

struct OpenHow {
  uint64_t flags;
  uint64_t mode;
  uint64_t resolve;
};

bool ResetEnvironment() {
  if (clearenv() != 0) {
    return false;
  }

  for (const auto& variable : kDefaultEnvironment) {
    if (setenv(variable[0], variable[1], 1) != 0) {
      return false;
    }
  }
  return true;
}

bool GetRegs(pid_t pid, user_pt_regs* regs) {
  iovec io{regs, sizeof(*regs)};
  return ptrace(PTRACE_GETREGSET, pid, reinterpret_cast<void*>(NT_PRSTATUS),
             &io) == 0;
}

bool SetRegs(pid_t pid, const user_pt_regs& regs) {
  iovec io{const_cast<user_pt_regs*>(&regs), sizeof(regs)};
  return ptrace(PTRACE_SETREGSET, pid, reinterpret_cast<void*>(NT_PRSTATUS),
             &io) == 0;
}

bool ResolveVirtualPathBase(pid_t pid, int dir_fd,
    const std::string& normalized_rootfs, std::string* virtual_path) {
  if (virtual_path == nullptr) {
    return false;
  }

  char source_path[64];
  if (dir_fd == AT_FDCWD) {
    snprintf(source_path, sizeof(source_path), "/proc/%d/cwd", pid);
  } else {
    snprintf(source_path, sizeof(source_path), "/proc/%d/fd/%d", pid, dir_fd);
  }

  char          resolved_path[kPathReadLimit];
  const ssize_t resolved_size =
      readlink(source_path, resolved_path, sizeof(resolved_path) - 1);
  if (resolved_size <= 0) {
    return false;
  }
  resolved_path[resolved_size] = '\0';

  const std::string real_path(resolved_path);
  if (real_path == normalized_rootfs) {
    *virtual_path = "/";
    return true;
  }

  const std::string rootfs_prefix = normalized_rootfs + "/";
  if (real_path.rfind(rootfs_prefix, 0) == 0) {
    *virtual_path = real_path.substr(normalized_rootfs.size());
    return true;
  }
  if (IsPassthroughUnixPath(real_path)) {
    *virtual_path = real_path;
    return true;
  }
  return false;
}

std::string ResolveVirtualRelativePath(
    const std::string& base_path, const std::string& relative_path) {
  std::vector<std::string> components;
  const std::string        combined_path = base_path + "/" + relative_path;
  size_t                   start         = 0;
  while (start <= combined_path.size()) {
    const size_t slash = combined_path.find('/', start);
    const size_t end =
        slash == std::string::npos ? combined_path.size() : slash;
    const std::string component = combined_path.substr(start, end - start);
    if (component == "..") {
      if (!components.empty()) {
        components.pop_back();
      }
    } else if (!component.empty() && component != ".") {
      components.push_back(component);
    }
    if (slash == std::string::npos) {
      break;
    }
    start = slash + 1;
  }

  std::string result = "/";
  for (size_t i = 0; i < components.size(); ++i) {
    if (i != 0) {
      result.push_back('/');
    }
    result.append(components[i]);
  }
  return result;
}

std::string TranslateProcPath(pid_t               pid,
    const std::unordered_map<pid_t, TraceeState>& states, std::string path,
    bool follow_final, bool* root_reference = nullptr) {
  if (root_reference != nullptr)
    *root_reference = false;
  if (path.rfind("/proc/self/", 0) == 0) {
    path.replace(6, 4, std::to_string(pid));
  } else if (path.rfind("/proc/thread-self/", 0) == 0) {
    path.replace(6, 11, std::to_string(pid));
  }
  if (path.rfind("/proc/", 0) != 0) {
    return path;
  }
  size_t separator = path.find('/', 6);
  if (separator == std::string::npos)
    return path;
  pid_t target = 0;
  auto  parsed =
      std::from_chars(path.data() + 6, path.data() + separator, target);
  if (parsed.ec != std::errc{} || parsed.ptr != path.data() + separator ||
      target <= 0) {
    return path;
  }
  if (path.compare(separator, 6, "/task/") == 0) {
    const size_t start = separator + 6;
    separator          = path.find('/', start);
    if (separator == std::string::npos)
      return path;
    parsed =
        std::from_chars(path.data() + start, path.data() + separator, target);
    struct stat task_stat{};
    if (parsed.ec != std::errc{} || parsed.ptr != path.data() + separator ||
        stat(path.substr(0, separator).c_str(), &task_stat) != 0) {
      return path;
    }
  }
  const auto found = states.find(target);
  if (found == states.end())
    return path;
  const std::string suffix = path.substr(separator);
  if (suffix == "/root" || suffix.rfind("/root/", 0) == 0) {
    const bool final_root = suffix == "/root";
    if (root_reference != nullptr)
      *root_reference = final_root;
    if (final_root && !follow_final)
      return path;
    const std::string root = found->second.emulated_new_root.empty() ?
                                 "/" :
                                 found->second.emulated_new_root;
    return final_root ?
               root :
               (root == "/" ? suffix.substr(5) : root + suffix.substr(5));
  }
  if (!follow_final || !found->second.executable)
    return path;
  const auto& executable = *found->second.executable;
  int         fd         = -1;
  if (path.compare(separator, std::string::npos, "/exe") == 0) {
    fd = executable.image->fd;
  } else if (path.compare(separator, std::string::npos, "/auxv") == 0) {
    fd = executable.auxv_fd;
  }
  if (fd < 0)
    return path;
  return "/proc/" + std::to_string(getpid()) + "/fd/" + std::to_string(fd);
}

std::string ResolveVirtualSymlinks(const std::string& normalized_rootfs,
    const std::string& path, bool follow_final_symlink,
    bool                                          allow_passthrough = true,
    const std::unordered_map<pid_t, TraceeState>* states            = nullptr,
    pid_t pid = 0, size_t symlink_depth = 0) {
  if (symlink_depth > kMaxSymlinkDepth)
    return path;
  if (allow_passthrough && IsPassthroughUnixPath(path)) {
    if (states == nullptr)
      return path;
    const std::string translated =
        TranslateProcPath(pid, *states, path, follow_final_symlink);
    if (translated == path)
      return path;
    return ResolveVirtualSymlinks(normalized_rootfs, translated,
        follow_final_symlink, true, states, pid, symlink_depth + 1);
  }

  bool requires_directory = path.size() > 1 && path.back() == '/';
  std::deque<std::string> pending_components;
  size_t                  start = 0;
  while (start <= path.size()) {
    const size_t slash = path.find('/', start);
    const size_t end   = slash == std::string::npos ? path.size() : slash;
    if (end != start) {
      pending_components.emplace_back(path.substr(start, end - start));
    }
    if (slash == std::string::npos) {
      break;
    }
    start = slash + 1;
  }

  std::vector<std::string> resolved_components;
  while (!pending_components.empty()) {
    std::string component = std::move(pending_components.front());
    pending_components.pop_front();
    if (component == ".") {
      continue;
    }
    if (component == "..") {
      if (!resolved_components.empty()) {
        resolved_components.pop_back();
      }
      continue;
    }

    std::string candidate_path;
    for (const std::string& resolved_component : resolved_components) {
      candidate_path.push_back('/');
      candidate_path.append(resolved_component);
    }
    candidate_path.push_back('/');
    candidate_path.append(component);

    if (states != nullptr && candidate_path == "/proc" &&
        !pending_components.empty()) {
      for (const auto& remaining : pending_components) {
        candidate_path += "/" + remaining;
      }
      return ResolveVirtualSymlinks(normalized_rootfs, candidate_path,
          follow_final_symlink, true, states, pid, symlink_depth);
    }

    if (pending_components.empty() && !follow_final_symlink &&
        !requires_directory) {
      resolved_components.emplace_back(std::move(component));
      continue;
    }

    const std::string real_path =
        allow_passthrough ?
            RewritePathToRootfs(normalized_rootfs, candidate_path) :
            normalized_rootfs + candidate_path;
    char          target[kPathReadLimit];
    const ssize_t target_size =
        readlink(real_path.c_str(), target, sizeof(target) - 1);
    if (target_size < 0) {
      resolved_components.emplace_back(std::move(component));
      continue;
    }
    if (++symlink_depth > kMaxSymlinkDepth) {
      return path;
    }
    target[target_size] = '\0';
    if (target_size > 0 && target[target_size - 1] == '/') {
      requires_directory = true;
    }
    if (IsAbsoluteUnixPath(target)) {
      resolved_components.clear();
    }

    std::vector<std::string> target_components;
    start = 0;
    while (start <= static_cast<size_t>(target_size)) {
      const size_t slash =
          std::string_view(target, target_size).find('/', start);
      const size_t end = slash == std::string::npos ? target_size : slash;
      if (end != start) {
        target_components.emplace_back(target + start, end - start);
      }
      if (slash == std::string::npos) {
        break;
      }
      start = slash + 1;
    }
    for (auto it = target_components.rbegin(); it != target_components.rend();
        ++it) {
      pending_components.emplace_front(std::move(*it));
    }
  }

  if (resolved_components.empty()) {
    return "/";
  }
  std::string result;
  for (const std::string& component : resolved_components) {
    result.push_back('/');
    result.append(component);
  }
  if (requires_directory) {
    result.push_back('/');
  }
  return result;
}

bool ShouldFollowFinalSymlink(
    pid_t pid, const user_pt_regs& regs, int arg_index) {
  switch (regs.regs[8]) {
    case kSysLsetxattr:
    case kSysLgetxattr:
    case kSysLlistxattr:
    case kSysLremovexattr:
    case kSysMknodat:
    case kSysMkdirat:
    case kSysUnlinkat:
    case kSysReadlinkat:
    case kSysSymlinkat:
    case kSysRenameat:
    case kSysRenameat2:
      return false;
    case kSysOpenat:
      return (regs.regs[2] & O_NOFOLLOW) == 0;
    case kSysOpenat2: {
      uint64_t flags = 0;
      return !ReadTraceeMemory(pid, regs.regs[2], &flags, sizeof(flags)) ||
             (flags & O_NOFOLLOW) == 0;
    }
    case kSysNewfstatat:
    case kSysUtimensat:
    case kSysFaccessat2:
      return (regs.regs[3] & AT_SYMLINK_NOFOLLOW) == 0;
    case kSysFchownat:
      return (regs.regs[4] & AT_SYMLINK_NOFOLLOW) == 0;
    case kSysStatx:
      return (regs.regs[2] & AT_SYMLINK_NOFOLLOW) == 0;
    case kSysLinkat:
      return arg_index == 1 && (regs.regs[4] & AT_SYMLINK_FOLLOW) != 0;
    default:
      return true;
  }
}

bool ApplyTraceOptions(pid_t pid) {
  const long options = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK |
                       PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE |
                       PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL;
  return ptrace(PTRACE_SETOPTIONS, pid, nullptr, options) == 0;
}

bool ReadShebangInterpreter(const std::string& executable_path,
    std::string* interpreter_path, std::string* interpreter_argument) {
  if (interpreter_path == nullptr || interpreter_argument == nullptr) {
    return false;
  }
  interpreter_path->clear();
  interpreter_argument->clear();

  const int fd = open(executable_path.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return false;
  }

  char          buffer[256]{};
  const ssize_t size = read(fd, buffer, sizeof(buffer) - 1);
  close(fd);
  if (size < 3 || buffer[0] != '#' || buffer[1] != '!') {
    return false;
  }

  size_t end = 2;
  while (end < static_cast<size_t>(size) && buffer[end] != '\n' &&
         buffer[end] != '\0') {
    ++end;
  }
  while (end > 2 && (buffer[end - 1] == ' ' || buffer[end - 1] == '\t' ||
                        buffer[end - 1] == '\r')) {
    --end;
  }

  size_t interpreter_start = 2;
  while (interpreter_start < end && (buffer[interpreter_start] == ' ' ||
                                        buffer[interpreter_start] == '\t')) {
    ++interpreter_start;
  }
  size_t interpreter_end = interpreter_start;
  while (interpreter_end < end && buffer[interpreter_end] != ' ' &&
         buffer[interpreter_end] != '\t') {
    ++interpreter_end;
  }
  if (interpreter_start == interpreter_end) {
    return false;
  }

  interpreter_path->assign(
      buffer + interpreter_start, interpreter_end - interpreter_start);
  size_t argument_start = interpreter_end;
  while (argument_start < end &&
         (buffer[argument_start] == ' ' || buffer[argument_start] == '\t')) {
    ++argument_start;
  }
  if (argument_start < end) {
    interpreter_argument->assign(buffer + argument_start, end - argument_start);
  }
  return !interpreter_path->empty();
}

bool ReadTraceeArgv(pid_t pid, uint64_t argv_address, size_t max_arg_count,
    std::vector<uint64_t>* argv_out) {
  if (argv_out == nullptr || argv_address == 0 || max_arg_count == 0) {
    return false;
  }

  argv_out->clear();
  for (size_t i = 0; i <= max_arg_count; ++i) {
    uint64_t arg_ptr = 0;
    if (!ReadTraceeMemory(pid, argv_address + (i * sizeof(uint64_t)), &arg_ptr,
            sizeof(arg_ptr))) {
      return false;
    }
    if (arg_ptr == 0) {
      return true;
    }
    if (i == max_arg_count) {
      return false;
    }
    argv_out->push_back(arg_ptr);
  }
  return false;
}

bool SetSyscallNumber(pid_t pid, user_pt_regs* regs, uint64_t syscall_number) {
  if (regs == nullptr) {
    return false;
  }

  regs->regs[8] = syscall_number;
  if (!SetRegs(pid, *regs)) {
    __android_log_print(
        ANDROID_LOG_WARN, kLogTag, "Failed to set syscall for pid=%d", pid);
    return false;
  }

#if defined(__aarch64__)
  int   syscall_no = static_cast<int>(syscall_number);
  iovec io_syscall{&syscall_no, sizeof(syscall_no)};
  if (ptrace(PTRACE_SETREGSET, pid,
          reinterpret_cast<void*>(0x404 /* NT_ARM_SYSTEM_CALL */),
          &io_syscall) != 0) {
    __android_log_print(ANDROID_LOG_WARN, kLogTag,
        "Failed to set NT_ARM_SYSTEM_CALL for pid=%d", pid);
    return false;
  }
#endif

  return true;
}

void SetEmulatedSyscallReturn(
    pid_t pid, TraceeState* state, user_pt_regs* regs, int64_t return_value) {
  if (state == nullptr || !SetSyscallNumber(pid, regs, kSysGetpid)) {
    return;
  }

  state->has_emulated_return = true;
  state->emulated_return     = static_cast<uint64_t>(return_value);
}

bool RewriteExecveIfNeeded(pid_t pid, const std::string& normalized_rootfs,
    const std::unordered_map<pid_t, TraceeState>& states, TraceeState* state,
    user_pt_regs* regs) {
  const bool at = regs->regs[8] == kSysExecveat;
  if (!at && regs->regs[8] != kSysExecve)
    return false;
  state->pending_executable.reset();
  const uint64_t argv_address = regs->regs[at ? 2 : 1];
  const uint64_t env_address  = regs->regs[at ? 3 : 2];
  const int      dirfd        = at ? static_cast<int>(regs->regs[0]) : AT_FDCWD;
  const uint64_t flags        = at ? regs->regs[4] : 0;
  auto           fail         = [&](int error) {
    state->pending_executable.reset();
    SetEmulatedSyscallReturn(pid, state, regs, -error);
    return true;
  };
  if (flags & ~(AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW))
    return fail(EINVAL);
  std::string original;
  if (!ReadTraceeCString(
          pid, regs->regs[at ? 1 : 0], kPathReadLimit, &original)) {
    return fail(EFAULT);
  }
  if (original.empty() && !(flags & AT_EMPTY_PATH))
    return fail(ENOENT);
  if (original.rfind(normalized_rootfs + "/", 0) == 0) {
    original.erase(0, normalized_rootfs.size());
  }
  std::string path = original;
  if (path.empty()) {
    path = "/proc/" + std::to_string(pid) + "/fd/" + std::to_string(dirfd);
  } else if (!IsAbsoluteUnixPath(path)) {
    std::string base;
    if (!ResolveVirtualPathBase(pid, dirfd, normalized_rootfs, &base)) {
      return fail(EBADF);
    }
    path = base + "/" + path;
  }
  path = ResolveEmulatedBindMounts(*state, path);
  const std::string virtual_execfn =
      original.empty() ? "/dev/fd/" + std::to_string(dirfd) : original;
  auto pending    = std::make_shared<ProcessExecutable>();
  pending->execfn = virtual_execfn;
  pending->comm   = virtual_execfn;
  std::vector<std::string> prefix;
  for (size_t depth = 0;; ++depth) {
    const bool follow = depth != 0 || !(flags & AT_SYMLINK_NOFOLLOW);
    path              = ResolveVirtualSymlinks(
        normalized_rootfs, path, follow, true, &states, pid);
    const std::string real_path = RewritePathToRootfs(normalized_rootfs, path);
    if (!follow) {
      struct stat link_stat{};
      if (lstat(real_path.c_str(), &link_stat) != 0)
        return fail(errno);
      if (S_ISLNK(link_stat.st_mode))
        return fail(ELOOP);
    }
    pending->image = OpenElfExecutable(real_path);
    if (pending->image)
      break;
    const int elf_error = errno;
    if (elf_error != ENOEXEC)
      return fail(elf_error);
    std::string interpreter;
    std::string argument;
    if (!ReadShebangInterpreter(real_path, &interpreter, &argument))
      return fail(ENOEXEC);
    if (depth >= 5)
      return fail(ELOOP);
    if (at && depth == 0 &&
        (original.empty() || !IsAbsoluteUnixPath(original))) {
      const std::string fdinfo =
          "/proc/" + std::to_string(pid) + "/fdinfo/" + std::to_string(dirfd);
      FILE* file = fopen(fdinfo.c_str(), "re");
      if (file != nullptr) {
        char         line[128];
        unsigned int fd_flags = 0;
        while (fgets(line, sizeof(line), file)) {
          if (sscanf(line, "flags:\t%o", &fd_flags) == 1)
            break;
        }
        fclose(file);
        if (fd_flags & O_CLOEXEC)
          return fail(ENOENT);
      }
    }
    const std::string script =
        depth == 0 ? (at && !IsAbsoluteUnixPath(original) && dirfd != AT_FDCWD ?
                             "/dev/fd/" + std::to_string(dirfd) +
                                 (original.empty() ? "" : "/" + original) :
                             virtual_execfn) :
                     path;
    if (!prefix.empty())
      prefix.erase(prefix.begin());
    prefix.insert(prefix.begin(), script);
    if (!argument.empty())
      prefix.insert(prefix.begin(), argument);
    prefix.insert(prefix.begin(), interpreter);
    path = interpreter;
    if (!IsAbsoluteUnixPath(path)) {
      std::string base;
      if (!ResolveVirtualPathBase(pid, AT_FDCWD, normalized_rootfs, &base))
        return fail(ENOENT);
      path = base + "/" + path;
    }
  }
  auto kernel_image = pending->image;
  if (!pending->image->interpreter.empty()) {
    const std::string interpreter = ResolveVirtualSymlinks(normalized_rootfs,
        pending->image->interpreter, true, true, &states, pid);
    pending->interpreter =
        OpenElfExecutable(RewritePathToRootfs(normalized_rootfs, interpreter));
    if (!pending->interpreter)
      return fail(errno);
    if (!pending->interpreter->interpreter.empty())
      return fail(ELIBBAD);
    kernel_image = pending->interpreter;
  }
  const std::string kernel_path = "/proc/" + std::to_string(getpid()) + "/fd/" +
                                  std::to_string(kernel_image->fd);
  if (regs->sp < kExecScratchSize + kStackScratchOffset)
    return fail(E2BIG);
  const uint64_t scratch      = regs->sp - kExecScratchSize;
  const uint64_t path_address = scratch;
  if (!WriteTraceeMemory(
          pid, path_address, kernel_path.c_str(), kernel_path.size() + 1))
    return fail(EFAULT);
  uint64_t cursor         = (scratch + kernel_path.size() + 8) & ~7ULL;
  uint64_t rewritten_argv = argv_address;
  if (!prefix.empty()) {
    std::vector<uint64_t> original_argv;
    if (argv_address != 0 && !ReadTraceeArgv(pid, argv_address,
                                 kExecScratchSize / 8, &original_argv))
      return fail(E2BIG);
    std::vector<uint64_t> pointers;
    for (const auto& argument : prefix) {
      if (cursor + argument.size() + 1 > scratch + kExecScratchSize)
        return fail(E2BIG);
      pointers.push_back(cursor);
      if (!WriteTraceeMemory(
              pid, cursor, argument.c_str(), argument.size() + 1))
        return fail(EFAULT);
      cursor = (cursor + argument.size() + 8) & ~7ULL;
    }
    for (size_t i = 1; i < original_argv.size(); ++i)
      pointers.push_back(original_argv[i]);
    pointers.push_back(0);
    if (cursor + pointers.size() * 8 > scratch + kExecScratchSize)
      return fail(E2BIG);
    if (!WriteTraceeMemory(pid, cursor, pointers.data(), pointers.size() * 8))
      return fail(EFAULT);
    rewritten_argv = cursor;
  }
  regs->regs[0] = path_address;
  regs->regs[1] = rewritten_argv;
  regs->regs[2] = env_address;
  if (!SetSyscallNumber(pid, regs, kSysExecve))
    return fail(EFAULT);
  state->pending_executable = std::move(pending);
  return true;
}

bool MaybeEmulateProcReadlink(pid_t pid, const std::string& normalized_rootfs,
    const std::unordered_map<pid_t, TraceeState>& states, TraceeState* state,
    user_pt_regs* regs) {
  if (regs->regs[8] != kSysReadlinkat)
    return false;
  std::string path;
  if (!ReadTraceeCString(pid, regs->regs[1], kPathReadLimit, &path))
    return false;
  if (!IsAbsoluteUnixPath(path)) {
    std::string base;
    if (!ResolveVirtualPathBase(
            pid, static_cast<int>(regs->regs[0]), normalized_rootfs, &base))
      return false;
    path = path.empty() ? base : base + "/" + path;
  }
  path = ResolveVirtualSymlinks(
      normalized_rootfs, path, false, true, &states, pid);
  if (path.rfind("/proc/", 0) != 0 || path == "/proc/self" ||
      path == "/proc/thread-self")
    return false;
  bool              root_reference = false;
  const std::string target =
      TranslateProcPath(pid, states, path, true, &root_reference);
  std::string result;
  if (root_reference) {
    // Android's proc root link exposes the host root and may deny readlink
    // entirely.
    result = target;
  } else {
    struct stat info{};
    if (lstat(path.c_str(), &info) != 0 || !S_ISLNK(info.st_mode))
      return false;
    char          buffer[kPathReadLimit];
    const ssize_t length = readlink(target.c_str(), buffer, sizeof(buffer));
    if (length < 0) {
      SetEmulatedSyscallReturn(pid, state, regs, -errno);
      return true;
    }
    result.assign(buffer, length);
    if (result == normalized_rootfs) {
      result = "/";
    } else if (result.rfind(normalized_rootfs + "/", 0) == 0) {
      result.erase(0, normalized_rootfs.size());
    }
  }
  if (regs->regs[3] == 0) {
    SetEmulatedSyscallReturn(pid, state, regs, -EINVAL);
    return true;
  }
  const size_t size =
      std::min(result.size(), static_cast<size_t>(regs->regs[3]));
  if (!WriteTraceeMemory(pid, regs->regs[2], result.data(), size)) {
    SetEmulatedSyscallReturn(pid, state, regs, -EFAULT);
    return true;
  }
  SetEmulatedSyscallReturn(pid, state, regs, size);
  return true;
}

bool MaybeEmulateNamespaceSyscall(
    pid_t pid, TraceeState* state, user_pt_regs* regs) {
  if (state == nullptr || regs == nullptr) {
    return false;
  }

  if (regs->regs[8] == kSysUnshare) {
    const uint64_t namespace_flags = regs->regs[0] & kNamespaceCloneFlags;
    if (namespace_flags == 0) {
      return false;
    }

    state->emulated_mount_namespace |= (namespace_flags & CLONE_NEWNS) != 0;
    state->emulated_network_namespace |= (namespace_flags & CLONE_NEWNET) != 0;
    state->emulated_user_namespace |= (namespace_flags & CLONE_NEWUSER) != 0;
    regs->regs[0] &= ~kNamespaceCloneFlags;
    if (regs->regs[0] == 0) {
      SetEmulatedSyscallReturn(pid, state, regs, 0);
      return true;
    }
    SetRegs(pid, *regs);
    return false;
  }

  if (regs->regs[8] == kSysClone) {
    const uint64_t namespace_flags = regs->regs[0] & kNamespaceCloneFlags;
    if (namespace_flags == 0) {
      return false;
    }

    state->emulated_mount_namespace |= (namespace_flags & CLONE_NEWNS) != 0;
    state->emulated_network_namespace |= (namespace_flags & CLONE_NEWNET) != 0;
    state->emulated_user_namespace |= (namespace_flags & CLONE_NEWUSER) != 0;
    regs->regs[0] &= ~kNamespaceCloneFlags;
    SetRegs(pid, *regs);
    return false;
  }

  if (regs->regs[8] != kSysClone3 || regs->regs[0] == 0 ||
      regs->regs[1] < sizeof(uint64_t)) {
    return false;
  }

  uint64_t flags = 0;
  if (!ReadTraceeMemory(pid, regs->regs[0], &flags, sizeof(flags))) {
    return false;
  }
  const uint64_t namespace_flags = flags & kNamespaceCloneFlags;
  if (namespace_flags == 0) {
    return false;
  }

  state->emulated_mount_namespace |= (namespace_flags & CLONE_NEWNS) != 0;
  state->emulated_network_namespace |= (namespace_flags & CLONE_NEWNET) != 0;
  state->emulated_user_namespace |= (namespace_flags & CLONE_NEWUSER) != 0;
  flags &= ~kNamespaceCloneFlags;
  WriteTraceeMemory(pid, regs->regs[0], &flags, sizeof(flags));
  return false;
}

bool MaybeEmulateMountNamespaceOperation(pid_t pid,
    const std::string& normalized_rootfs, TraceeState* state,
    user_pt_regs* regs) {
  if (state == nullptr || regs == nullptr || !state->emulated_mount_namespace) {
    return false;
  }

  const auto resolve_path = [&](int dir_fd, uint64_t address,
                                std::string* virtual_path,
                                std::string* real_path) {
    if (!ReadTraceeCString(pid, address, kPathReadLimit, virtual_path) ||
        virtual_path->empty()) {
      return false;
    }
    if (!IsAbsoluteUnixPath(*virtual_path)) {
      std::string base_path;
      if (!ResolveVirtualPathBase(pid, dir_fd, normalized_rootfs, &base_path)) {
        return false;
      }
      *virtual_path = ResolveVirtualRelativePath(base_path, *virtual_path);
    }
    if (!state->emulated_old_root.empty() &&
        (*virtual_path == state->emulated_old_root ||
            virtual_path->rfind(state->emulated_old_root + "/", 0) == 0)) {
      *virtual_path = virtual_path->substr(state->emulated_old_root.size());
      if (virtual_path->empty()) {
        *virtual_path = "/";
      }
    }
    *real_path = RewritePathToRootfs(normalized_rootfs,
        ResolveVirtualSymlinks(normalized_rootfs, *virtual_path, false));
    return true;
  };
  const auto is_in_emulated_mount = [&](const std::string& path) {
    return std::any_of(state->emulated_mount_points.begin(),
        state->emulated_mount_points.end(),
        [&](const std::string& mount_point) {
          return mount_point != "/" &&
                 (path == mount_point || path.rfind(mount_point + "/", 0) == 0);
        });
  };

  switch (regs->regs[8]) {
    case kSysMkdirat: {
      std::string path;
      std::string real_path;
      if (!resolve_path(static_cast<int>(regs->regs[0]), regs->regs[1], &path,
              &real_path) ||
          !is_in_emulated_mount(path)) {
        return false;
      }

      struct stat existing_stat{};
      if (lstat(real_path.c_str(), &existing_stat) != 0) {
        if (errno == ENOENT) {
          state->emulated_mount_nodes.insert(path);
        }
        return false;
      }
      if (!S_ISDIR(existing_stat.st_mode) ||
          state->emulated_mount_nodes.count(path) != 0) {
        return false;
      }
      state->emulated_mount_nodes.insert(path);
      SetEmulatedSyscallReturn(pid, state, regs, 0);
      return true;
    }
    case kSysSymlinkat: {
      std::string path;
      std::string real_path;
      if (!resolve_path(static_cast<int>(regs->regs[1]), regs->regs[2], &path,
              &real_path) ||
          !is_in_emulated_mount(path)) {
        return false;
      }

      struct stat existing_stat{};
      if (lstat(real_path.c_str(), &existing_stat) != 0) {
        if (errno == ENOENT) {
          state->emulated_mount_nodes.insert(path);
        }
        return false;
      }
      if (!S_ISLNK(existing_stat.st_mode) ||
          state->emulated_mount_nodes.count(path) != 0) {
        return false;
      }

      std::string   target;
      char          existing_target[kPathReadLimit];
      const ssize_t existing_target_size =
          readlink(real_path.c_str(), existing_target, sizeof(existing_target));
      if (!ReadTraceeCString(pid, regs->regs[0], kPathReadLimit, &target) ||
          existing_target_size < 0 ||
          static_cast<size_t>(existing_target_size) != target.size() ||
          memcmp(existing_target, target.data(), target.size()) != 0) {
        return false;
      }
      state->emulated_mount_nodes.insert(path);
      SetEmulatedSyscallReturn(pid, state, regs, 0);
      return true;
    }
    case kSysOpenat:
    case kSysOpenat2: {
      uint64_t flags = regs->regs[2];
      if (regs->regs[8] == kSysOpenat2 &&
          !ReadTraceeMemory(pid, regs->regs[2], &flags, sizeof(flags))) {
        return false;
      }
      if ((flags & O_CREAT) == 0) {
        return false;
      }

      std::string path;
      std::string real_path;
      if (!resolve_path(static_cast<int>(regs->regs[0]), regs->regs[1], &path,
              &real_path)) {
        return false;
      }
      struct stat existing_stat{};
      if (lstat(real_path.c_str(), &existing_stat) != 0) {
        return false;
      }
      if ((flags & O_EXCL) != 0) {
        SetEmulatedSyscallReturn(pid, state, regs, -EEXIST);
        return true;
      }
      if ((flags & O_ACCMODE) == O_RDONLY || state->fs_uid != kRootUid ||
          !S_ISREG(existing_stat.st_mode) ||
          (existing_stat.st_mode & S_IWUSR) != 0) {
        return false;
      }
      if (chmod(real_path.c_str(), existing_stat.st_mode | S_IWUSR) != 0) {
        return false;
      }
      state->pending_open_permission_path = real_path;
      state->pending_open_permission_mode = existing_stat.st_mode & 07777;
      return false;
    }
    case kSysMount: {
      constexpr std::string_view self_fd_prefix   = "/proc/self/fd/";
      constexpr std::string_view thread_fd_prefix = "/proc/thread-self/fd/";
      const auto resolve_mount_path = [&](uint64_t address, std::string* path) {
        if (address == 0 || path == nullptr ||
            !ReadTraceeCString(pid, address, kPathReadLimit, path) ||
            path->empty()) {
          return false;
        }

        std::string_view fd_text;
        if (path->rfind(self_fd_prefix, 0) == 0) {
          fd_text = std::string_view(*path).substr(self_fd_prefix.size());
        } else if (path->rfind(thread_fd_prefix, 0) == 0) {
          fd_text = std::string_view(*path).substr(thread_fd_prefix.size());
        }
        char*      end = nullptr;
        const long fd = fd_text.empty() ? -1 : strtol(fd_text.data(), &end, 10);
        if (!fd_text.empty() && end == fd_text.data() + fd_text.size() &&
            fd >= 0 && fd <= INT_MAX) {
          return ResolveVirtualPathBase(
              pid, static_cast<int>(fd), normalized_rootfs, path);
        }

        if (!IsAbsoluteUnixPath(*path)) {
          std::string cwd;
          if (!ResolveVirtualPathBase(pid, AT_FDCWD, normalized_rootfs, &cwd)) {
            return false;
          }
          *path = ResolveVirtualRelativePath(cwd, *path);
        }
        if (!state->emulated_old_root.empty() &&
            (*path == state->emulated_old_root ||
                path->rfind(state->emulated_old_root + "/", 0) == 0)) {
          *path = path->substr(state->emulated_old_root.size());
          if (path->empty()) {
            *path = "/";
          }
        } else if (!state->emulated_new_root.empty() &&
                   !IsPassthroughUnixPath(*path)) {
          *path = state->emulated_new_root + *path;
        }
        return true;
      };

      std::string destination;
      if (resolve_mount_path(regs->regs[1], &destination)) {
        state->emulated_mount_points.insert(destination);
        state->emulated_mount_points.insert(
            RewritePathToRootfs(normalized_rootfs, destination));

        std::string source;
        if (resolve_mount_path(regs->regs[0], &source)) {
          source = ResolveEmulatedBindMounts(*state, source);
          if ((regs->regs[3] & MS_BIND) != 0) {
            state->emulated_bind_mounts[destination] = source;
          } else {
            state->emulated_bind_mounts.erase(destination);
          }
        }
        __android_log_print(ANDROID_LOG_VERBOSE, kLogTag,
            "Recorded emulated mount pid=%d source=%s destination=%s "
            "mounts=%zu",
            pid, source.c_str(), destination.c_str(),
            state->emulated_mount_points.size());
      }
      SetEmulatedSyscallReturn(pid, state, regs, 0);
      return true;
    }
    case kSysUmount2:
      SetEmulatedSyscallReturn(pid, state, regs, 0);
      return true;
    case kSysPivotRoot: {
      std::string new_root;
      std::string old_root;
      if (!ReadTraceeCString(pid, regs->regs[0], kPathReadLimit, &new_root) ||
          !ReadTraceeCString(pid, regs->regs[1], kPathReadLimit, &old_root)) {
        SetEmulatedSyscallReturn(pid, state, regs, -EFAULT);
        return true;
      }

      std::string cwd;
      if ((!IsAbsoluteUnixPath(new_root) || !IsAbsoluteUnixPath(old_root)) &&
          !ResolveVirtualPathBase(pid, AT_FDCWD, normalized_rootfs, &cwd)) {
        SetEmulatedSyscallReturn(pid, state, regs, -ENOENT);
        return true;
      }
      if (!IsAbsoluteUnixPath(new_root)) {
        new_root = ResolveVirtualRelativePath(cwd, new_root);
      }
      if (!IsAbsoluteUnixPath(old_root)) {
        old_root = ResolveVirtualRelativePath(cwd, old_root);
      }
      if (old_root.rfind(new_root, 0) != 0 ||
          (old_root.size() > new_root.size() &&
              old_root[new_root.size()] != '/')) {
        SetEmulatedSyscallReturn(pid, state, regs, -EINVAL);
        return true;
      }

      state->emulated_old_root = old_root.substr(new_root.size());
      state->emulated_new_root = new_root;
      SetEmulatedSyscallReturn(pid, state, regs, 0);
      return true;
    }
    default:
      return false;
  }
}

void RestoreOpenPermission(TraceeState* state) {
  if (state == nullptr || state->pending_open_permission_path.empty()) {
    return;
  }

  if (chmod(state->pending_open_permission_path.c_str(),
          state->pending_open_permission_mode) != 0) {
    __android_log_print(ANDROID_LOG_WARN, kLogTag,
        "Failed to restore file permissions path=%s: %s",
        state->pending_open_permission_path.c_str(), strerror(errno));
  }
  state->pending_open_permission_path.clear();
  state->pending_open_permission_mode = 0;
}

void RedirectEmulatedMountInfo(pid_t pid, const std::string& normalized_rootfs,
    TraceeState* state, user_pt_regs* regs) {
  if (state == nullptr || regs == nullptr || !state->emulated_mount_namespace ||
      (regs->regs[8] != kSysOpenat && regs->regs[8] != kSysOpenat2) ||
      regs->regs[1] == 0) {
    return;
  }

  std::string path;
  if (!ReadTraceeCString(pid, regs->regs[1], kPathReadLimit, &path) ||
      path.empty()) {
    return;
  }
  if (!IsAbsoluteUnixPath(path)) {
    std::string base_path;
    if (!ResolveVirtualPathBase(pid, static_cast<int>(regs->regs[0]),
            normalized_rootfs, &base_path)) {
      return;
    }
    path = ResolveVirtualRelativePath(base_path, path);
  }
  if (!state->emulated_old_root.empty() &&
      (path == state->emulated_old_root ||
          path.rfind(state->emulated_old_root + "/", 0) == 0)) {
    path = path.substr(state->emulated_old_root.size());
    if (path.empty()) {
      path = "/";
    }
  }

  const std::string process_mountinfo =
      "/proc/" + std::to_string(pid) + "/mountinfo";
  if (path != "/proc/self/mountinfo" && path != "/proc/thread-self/mountinfo" &&
      path != process_mountinfo) {
    return;
  }

  state->emulated_mountinfo_path =
      normalized_rootfs + "/tmp/.andlify-mountinfo-" + std::to_string(pid);
  const int fd = open(state->emulated_mountinfo_path.c_str(),
      O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (fd < 0) {
    __android_log_print(ANDROID_LOG_WARN, kLogTag,
        "Failed to create emulated mountinfo pid=%d path=%s: %s", pid,
        state->emulated_mountinfo_path.c_str(), strerror(errno));
    return;
  }

  std::string content  = "1 0 0:1 / / rw,nosuid,nodev - tmpfs andlify rw\n";
  int         mount_id = 2;
  for (const std::string& mount_point : state->emulated_mount_points) {
    if (mount_point == "/") {
      continue;
    }
    std::string escaped_path;
    for (const char value : mount_point) {
      switch (value) {
        case ' ':
          escaped_path.append("\\040");
          break;
        case '\t':
          escaped_path.append("\\011");
          break;
        case '\n':
          escaped_path.append("\\012");
          break;
        case '\\':
          escaped_path.append("\\134");
          break;
        default:
          escaped_path.push_back(value);
          break;
      }
    }
    content.append(std::to_string(mount_id));
    content.append(" 1 0:1 / ");
    content.append(escaped_path);
    content.append(" rw,nosuid,nodev - tmpfs andlify rw\n");
    ++mount_id;
  }

  size_t written = 0;
  while (written < content.size()) {
    const ssize_t result =
        write(fd, content.data() + written, content.size() - written);
    if (result < 0 && errno == EINTR) {
      continue;
    }
    if (result <= 0) {
      close(fd);
      return;
    }
    written += static_cast<size_t>(result);
  }
  close(fd);

  __android_log_print(ANDROID_LOG_VERBOSE, kLogTag,
      "Redirecting mountinfo pid=%d mounts=%zu path=%s", pid,
      state->emulated_mount_points.size(),
      state->emulated_mountinfo_path.c_str());

  if (regs->sp <= kStackScratchOffset ||
      !WriteTraceeMemory(pid, regs->sp - kStackScratchOffset,
          state->emulated_mountinfo_path.c_str(),
          state->emulated_mountinfo_path.size() + 1)) {
    return;
  }
  regs->regs[1] = regs->sp - kStackScratchOffset;
  SetRegs(pid, *regs);
}

bool MaybeEmulateNetworkNamespaceOperation(
    pid_t pid, TraceeState* state, user_pt_regs* regs) {
  if (state == nullptr || regs == nullptr ||
      !state->emulated_network_namespace) {
    return false;
  }

  if (regs->regs[8] == kSysSocket && regs->regs[0] == kAfNetlink &&
      regs->regs[2] == kNetlinkRoute) {
    regs->regs[0] = 1;
    regs->regs[1] = O_CLOEXEC | O_NONBLOCK;
    if (!SetSyscallNumber(pid, regs, kSysEventfd2)) {
      return false;
    }
    state->pending_netlink_route_fd = true;
    return true;
  }

  const int fd       = static_cast<int>(regs->regs[0]);
  auto      route_fd = state->emulated_netlink_route_fds.find(fd);
  if (route_fd == state->emulated_netlink_route_fds.end()) {
    return false;
  }

  switch (regs->regs[8]) {
    case kSysBind:
      SetEmulatedSyscallReturn(pid, state, regs, 0);
      return true;
    case kSysSendto: {
      nlmsghdr     header{};
      const size_t length = static_cast<size_t>(regs->regs[2]);
      if (length < sizeof(header) ||
          !ReadTraceeMemory(pid, regs->regs[1], &header, sizeof(header))) {
        SetEmulatedSyscallReturn(pid, state, regs, -EFAULT);
        return true;
      }
      route_fd->second = header.nlmsg_seq;
      SetEmulatedSyscallReturn(pid, state, regs, length);
      return true;
    }
    case kSysRecvfrom: {
      struct {
        nlmsghdr header;
        int32_t  error;
      } response{};
      response.header.nlmsg_len  = sizeof(response);
      response.header.nlmsg_type = NLMSG_ERROR;
      response.header.nlmsg_seq  = route_fd->second;
      response.header.nlmsg_pid  = pid;
      const size_t length =
          std::min(static_cast<size_t>(regs->regs[2]), sizeof(response));
      if (regs->regs[1] == 0 ||
          !WriteTraceeMemory(pid, regs->regs[1], &response, length)) {
        SetEmulatedSyscallReturn(pid, state, regs, -EFAULT);
        return true;
      }
      SetEmulatedSyscallReturn(pid, state, regs, length);
      return true;
    }
    case kSysClose:
      state->emulated_netlink_route_fds.erase(route_fd);
      return false;
    default:
      return false;
  }
}

void TrackEmulatedNetworkNamespaceFd(
    TraceeState* state, const user_pt_regs& regs) {
  if (state == nullptr || !state->pending_netlink_route_fd) {
    return;
  }

  state->pending_netlink_route_fd = false;
  const int64_t fd                = static_cast<int64_t>(regs.regs[0]);
  if (fd >= 0 && fd <= INT_MAX) {
    state->emulated_netlink_route_fds.emplace(static_cast<int>(fd), 0);
  }
}

void RedirectUserNamespaceControlFile(pid_t pid,
    const std::string& normalized_rootfs, const TraceeState& state,
    user_pt_regs* regs) {
  if (regs == nullptr || !state.emulated_user_namespace ||
      regs->regs[8] != kSysOpenat || regs->regs[1] == 0) {
    return;
  }

  std::string path;
  if (!ReadTraceeCString(pid, regs->regs[1], kPathReadLimit, &path) ||
      path.empty()) {
    return;
  }
  if (!IsAbsoluteUnixPath(path)) {
    std::string base_path;
    if (!ResolveVirtualPathBase(pid, static_cast<int>(regs->regs[0]),
            normalized_rootfs, &base_path)) {
      return;
    }
    path = ResolveVirtualRelativePath(base_path, path);
  }

  constexpr std::string_view proc_prefix = "/proc/";
  if (path.rfind(proc_prefix, 0) != 0) {
    return;
  }
  const size_t separator = path.find('/', proc_prefix.size());
  if (separator == std::string::npos) {
    return;
  }
  const std::string_view process = std::string_view(path).substr(
      proc_prefix.size(), separator - proc_prefix.size());
  if (process.empty() ||
      (process != "self" && process != "thread-self" &&
          !std::all_of(process.begin(), process.end(), [](char value) {
            return value >= '0' && value <= '9';
          }))) {
    return;
  }
  const std::string_view file = std::string_view(path).substr(separator + 1);
  if (file != "uid_map" && file != "gid_map" && file != "setgroups") {
    return;
  }

  constexpr char target[] = "/dev/null";
  if (regs->sp <= kStackScratchOffset ||
      !WriteTraceeMemory(
          pid, regs->sp - kStackScratchOffset, target, sizeof(target))) {
    return;
  }
  regs->regs[1] = regs->sp - kStackScratchOffset;
  SetRegs(pid, *regs);
}

bool MaybeEmulateGetcwd(pid_t pid, const std::string& normalized_rootfs,
    TraceeState* state, user_pt_regs* regs) {
  if (state == nullptr || regs == nullptr || regs->regs[8] != kSysGetcwd) {
    return false;
  }

  const uint64_t buffer_address = regs->regs[0];
  const size_t   buffer_size    = static_cast<size_t>(regs->regs[1]);
  if (buffer_size == 0) {
    SetEmulatedSyscallReturn(pid, state, regs, -EINVAL);
    return true;
  }

  std::string virtual_path;
  if (!ResolveVirtualPathBase(
          pid, AT_FDCWD, normalized_rootfs, &virtual_path)) {
    return false;
  }
  if (!state->emulated_new_root.empty() &&
      (virtual_path == state->emulated_new_root ||
          virtual_path.rfind(state->emulated_new_root + "/", 0) == 0)) {
    virtual_path = virtual_path.substr(state->emulated_new_root.size());
    if (virtual_path.empty()) {
      virtual_path = "/";
    }
  }

  const size_t result_size = virtual_path.size() + 1;
  if (result_size > buffer_size) {
    SetEmulatedSyscallReturn(pid, state, regs, -ERANGE);
    return true;
  }
  if (buffer_address == 0 || !WriteTraceeMemory(pid, buffer_address,
                                 virtual_path.c_str(), result_size)) {
    SetEmulatedSyscallReturn(pid, state, regs, -EFAULT);
    return true;
  }

  SetEmulatedSyscallReturn(pid, state, regs, result_size);
  return true;
}

void MaybeRewriteAcceptSyscall(pid_t pid, user_pt_regs* regs) {
  if (regs == nullptr || regs->regs[8] != kSysAccept) {
    return;
  }

  regs->regs[3] = 0;
  if (!SetSyscallNumber(pid, regs, kSysAccept4)) {
    return;
  }

  __android_log_print(
      ANDROID_LOG_INFO, kLogTag, "Rewrote accept to accept4 for pid=%d", pid);
}

bool MaybeEmulateUidGidSyscall(
    pid_t pid, TraceeState* state, user_pt_regs* regs) {
  if (state == nullptr || regs == nullptr) {
    return false;
  }

  switch (regs->regs[8]) {
    case kSysGetuid:
      SetEmulatedSyscallReturn(pid, state, regs, state->real_uid);
      return true;
    case kSysGeteuid:
      SetEmulatedSyscallReturn(pid, state, regs, state->effective_uid);
      return true;
    case kSysGetgid:
      SetEmulatedSyscallReturn(pid, state, regs, state->real_gid);
      return true;
    case kSysGetegid:
      SetEmulatedSyscallReturn(pid, state, regs, state->effective_gid);
      return true;
    case kSysSetuid: {
      const uint32_t uid = regs->regs[0];
      if (state->effective_uid == kRootUid) {
        state->real_uid = state->effective_uid = state->saved_uid =
            state->fs_uid                      = uid;
        SetEmulatedSyscallReturn(pid, state, regs, 0);
        return true;
      }
      if (uid != state->real_uid && uid != state->saved_uid) {
        SetEmulatedSyscallReturn(pid, state, regs, -EPERM);
        return true;
      }
      state->effective_uid = state->fs_uid = uid;
      SetEmulatedSyscallReturn(pid, state, regs, 0);
      return true;
    }
    case kSysSetgid: {
      const uint32_t gid = regs->regs[0];
      if (state->effective_uid == kRootUid) {
        state->real_gid = state->effective_gid = state->saved_gid =
            state->fs_gid                      = gid;
        SetEmulatedSyscallReturn(pid, state, regs, 0);
        return true;
      }
      if (gid != state->real_gid && gid != state->saved_gid) {
        SetEmulatedSyscallReturn(pid, state, regs, -EPERM);
        return true;
      }
      state->effective_gid = state->fs_gid = gid;
      SetEmulatedSyscallReturn(pid, state, regs, 0);
      return true;
    }
    case kSysSetreuid:
    case kSysSetresuid: {
      const uint32_t real      = regs->regs[0];
      const uint32_t effective = regs->regs[1];
      const uint32_t saved =
          regs->regs[8] == kSysSetresuid ? regs->regs[2] : kUnchangedId;
      const bool privileged = state->effective_uid == kRootUid;
      const auto allowed    = [&](uint32_t uid) {
        return uid == kUnchangedId || privileged || uid == state->real_uid ||
               uid == state->effective_uid || uid == state->saved_uid;
      };
      if (!allowed(real) || !allowed(effective) || !allowed(saved)) {
        SetEmulatedSyscallReturn(pid, state, regs, -EPERM);
        return true;
      }
      if (real != kUnchangedId) {
        state->real_uid = real;
      }
      if (effective != kUnchangedId) {
        state->effective_uid = state->fs_uid = effective;
      }
      if (saved != kUnchangedId) {
        state->saved_uid = saved;
      } else if (regs->regs[8] == kSysSetreuid &&
                 (real != kUnchangedId || effective != kUnchangedId)) {
        state->saved_uid = state->effective_uid;
      }
      SetEmulatedSyscallReturn(pid, state, regs, 0);
      return true;
    }
    case kSysSetregid:
    case kSysSetresgid: {
      const uint32_t real      = regs->regs[0];
      const uint32_t effective = regs->regs[1];
      const uint32_t saved =
          regs->regs[8] == kSysSetresgid ? regs->regs[2] : kUnchangedId;
      const bool privileged = state->effective_uid == kRootUid;
      const auto allowed    = [&](uint32_t gid) {
        return gid == kUnchangedId || privileged || gid == state->real_gid ||
               gid == state->effective_gid || gid == state->saved_gid;
      };
      if (!allowed(real) || !allowed(effective) || !allowed(saved)) {
        SetEmulatedSyscallReturn(pid, state, regs, -EPERM);
        return true;
      }
      if (real != kUnchangedId) {
        state->real_gid = real;
      }
      if (effective != kUnchangedId) {
        state->effective_gid = state->fs_gid = effective;
      }
      if (saved != kUnchangedId) {
        state->saved_gid = saved;
      } else if (regs->regs[8] == kSysSetregid &&
                 (real != kUnchangedId || effective != kUnchangedId)) {
        state->saved_gid = state->effective_gid;
      }
      SetEmulatedSyscallReturn(pid, state, regs, 0);
      return true;
    }
    case kSysSetfsuid: {
      const uint32_t previous = state->fs_uid;
      const uint32_t uid      = regs->regs[0];
      if (state->effective_uid == kRootUid || uid == state->real_uid ||
          uid == state->effective_uid || uid == state->saved_uid ||
          uid == state->fs_uid) {
        state->fs_uid = uid;
      }
      SetEmulatedSyscallReturn(pid, state, regs, previous);
      return true;
    }
    case kSysSetfsgid: {
      const uint32_t previous = state->fs_gid;
      const uint32_t gid      = regs->regs[0];
      if (state->effective_uid == kRootUid || gid == state->real_gid ||
          gid == state->effective_gid || gid == state->saved_gid ||
          gid == state->fs_gid) {
        state->fs_gid = gid;
      }
      SetEmulatedSyscallReturn(pid, state, regs, previous);
      return true;
    }
    case kSysSetgroups: {
      if (state->effective_uid != kRootUid) {
        SetEmulatedSyscallReturn(pid, state, regs, -EPERM);
        return true;
      }
      const uint64_t size = regs->regs[0];
      const uint64_t list = regs->regs[1];
      if (size > kMaxSupplementaryGroups) {
        SetEmulatedSyscallReturn(pid, state, regs, -EINVAL);
        return true;
      }
      std::vector<uint32_t> groups(size);
      if (size != 0 && (list == 0 || !ReadTraceeMemory(pid, list, groups.data(),
                                         size * sizeof(uint32_t)))) {
        SetEmulatedSyscallReturn(pid, state, regs, -EFAULT);
        return true;
      }
      state->supplementary_groups = std::move(groups);
      SetEmulatedSyscallReturn(pid, state, regs, 0);
      return true;
    }
    case kSysCapset:
    case kSysFchownat:
    case kSysFchown:
      SetEmulatedSyscallReturn(pid, state, regs, 0);
      return true;
    case kSysGetresuid: {
      const bool success =
          WriteTraceeMemory(
              pid, regs->regs[0], &state->real_uid, sizeof(state->real_uid)) &&
          WriteTraceeMemory(pid, regs->regs[1], &state->effective_uid,
              sizeof(state->effective_uid)) &&
          WriteTraceeMemory(
              pid, regs->regs[2], &state->saved_uid, sizeof(state->saved_uid));
      if (!success) {
        SetEmulatedSyscallReturn(pid, state, regs, -EFAULT);
        return true;
      }
      SetEmulatedSyscallReturn(pid, state, regs, 0);
      return true;
    }
    case kSysGetresgid: {
      const bool success =
          WriteTraceeMemory(
              pid, regs->regs[0], &state->real_gid, sizeof(state->real_gid)) &&
          WriteTraceeMemory(pid, regs->regs[1], &state->effective_gid,
              sizeof(state->effective_gid)) &&
          WriteTraceeMemory(
              pid, regs->regs[2], &state->saved_gid, sizeof(state->saved_gid));
      if (!success) {
        SetEmulatedSyscallReturn(pid, state, regs, -EFAULT);
        return true;
      }
      SetEmulatedSyscallReturn(pid, state, regs, 0);
      return true;
    }
    case kSysGetgroups: {
      const uint64_t size = regs->regs[0];
      const uint64_t list = regs->regs[1];
      if (size == 0) {
        SetEmulatedSyscallReturn(
            pid, state, regs, state->supplementary_groups.size());
        return true;
      }
      if (size < state->supplementary_groups.size()) {
        SetEmulatedSyscallReturn(pid, state, regs, -EINVAL);
        return true;
      }
      if (state->supplementary_groups.empty()) {
        SetEmulatedSyscallReturn(pid, state, regs, 0);
        return true;
      }
      if (list == 0 ||
          !WriteTraceeMemory(pid, list, state->supplementary_groups.data(),
              state->supplementary_groups.size() * sizeof(uint32_t))) {
        SetEmulatedSyscallReturn(pid, state, regs, -EFAULT);
        return true;
      }
      SetEmulatedSyscallReturn(
          pid, state, regs, state->supplementary_groups.size());
      return true;
    }
    default:
      return false;
  }
}

bool MaybeEmulateFileDescriptorLimit(
    pid_t pid, TraceeState* state, user_pt_regs* regs) {
  if (state == nullptr || regs == nullptr) {
    return false;
  }

  uint64_t new_limit_address = 0;
  uint64_t old_limit_address = 0;
  switch (regs->regs[8]) {
    case kSysGetrlimit:
      if (regs->regs[0] != RLIMIT_NOFILE) {
        return false;
      }
      old_limit_address = regs->regs[1];
      break;
    case kSysSetrlimit:
      if (regs->regs[0] != RLIMIT_NOFILE) {
        return false;
      }
      new_limit_address = regs->regs[1];
      break;
    case kSysPrlimit64:
      if ((regs->regs[0] != 0 && regs->regs[0] != static_cast<uint64_t>(pid)) ||
          regs->regs[1] != RLIMIT_NOFILE) {
        return false;
      }
      new_limit_address = regs->regs[2];
      old_limit_address = regs->regs[3];
      break;
    default:
      return false;
  }

  const rlimit old_limit = state->file_descriptor_limit;
  if (new_limit_address != 0) {
    rlimit new_limit{};
    if (!ReadTraceeMemory(
            pid, new_limit_address, &new_limit, sizeof(new_limit))) {
      SetEmulatedSyscallReturn(pid, state, regs, -EFAULT);
      return true;
    }
    if (new_limit.rlim_cur > new_limit.rlim_max) {
      SetEmulatedSyscallReturn(pid, state, regs, -EINVAL);
      return true;
    }
    if (state->effective_uid != kRootUid &&
        new_limit.rlim_max > old_limit.rlim_max) {
      SetEmulatedSyscallReturn(pid, state, regs, -EPERM);
      return true;
    }
    state->file_descriptor_limit = new_limit;
  }

  if (old_limit_address != 0 && !WriteTraceeMemory(pid, old_limit_address,
                                    &old_limit, sizeof(old_limit))) {
    state->file_descriptor_limit = old_limit;
    SetEmulatedSyscallReturn(pid, state, regs, -EFAULT);
    return true;
  }

  SetEmulatedSyscallReturn(pid, state, regs, 0);
  return true;
}

void RewriteUnixCredentials(pid_t pid, uint64_t message_address, uid_t app_uid,
    gid_t app_gid, const std::unordered_map<pid_t, TraceeState>& states,
    bool to_kernel) {
  msghdr message{};
  if (message_address == 0 ||
      !ReadTraceeMemory(pid, message_address, &message, sizeof(message)) ||
      message.msg_control == nullptr || message.msg_controllen == 0 ||
      message.msg_controllen > kMaxControlMessageSize) {
    return;
  }

  const uint64_t control_address =
      reinterpret_cast<uint64_t>(message.msg_control);
  std::vector<uint8_t> control(message.msg_controllen);
  if (!ReadTraceeMemory(pid, control_address, control.data(), control.size())) {
    return;
  }

  bool   changed = false;
  size_t offset  = 0;
  while (offset + sizeof(cmsghdr) <= control.size()) {
    cmsghdr header{};
    memcpy(&header, control.data() + offset, sizeof(header));
    if (header.cmsg_len < sizeof(cmsghdr) ||
        header.cmsg_len > control.size() - offset) {
      break;
    }

    if (header.cmsg_level == SOL_SOCKET &&
        header.cmsg_type == SCM_CREDENTIALS &&
        header.cmsg_len >= sizeof(cmsghdr) + sizeof(UnixCredentials)) {
      UnixCredentials credentials{};
      memcpy(&credentials, control.data() + offset + sizeof(cmsghdr),
          sizeof(credentials));
      if (to_kernel) {
        credentials.uid = app_uid;
        credentials.gid = app_gid;
      } else {
        const auto sender = states.find(credentials.pid);
        if (sender != states.end()) {
          credentials.uid = sender->second.effective_uid;
          credentials.gid = sender->second.effective_gid;
        } else {
          if (credentials.uid == app_uid) {
            credentials.uid = kRootUid;
          }
          if (credentials.gid == app_gid) {
            credentials.gid = kRootGid;
          }
        }
      }
      memcpy(control.data() + offset + sizeof(cmsghdr), &credentials,
          sizeof(credentials));
      changed = true;
    }

    const size_t next =
        (header.cmsg_len + sizeof(size_t) - 1U) & ~(sizeof(size_t) - 1U);
    if (next == 0 || next > control.size() - offset) {
      break;
    }
    offset += next;
  }

  if (changed) {
    WriteTraceeMemory(pid, control_address, control.data(), control.size());
  }
}

void RewritePeerCredentials(pid_t pid, uid_t app_uid, gid_t app_gid,
    const std::unordered_map<pid_t, TraceeState>& states,
    const user_pt_regs&                           regs) {
  if (regs.regs[8] != kSysGetsockopt ||
      static_cast<int64_t>(regs.regs[0]) < 0 || regs.regs[1] != SOL_SOCKET ||
      regs.regs[2] != SO_PEERCRED || regs.regs[3] == 0 || regs.regs[4] == 0) {
    return;
  }

  socklen_t length = 0;
  if (!ReadTraceeMemory(pid, regs.regs[4], &length, sizeof(length)) ||
      length < sizeof(UnixCredentials)) {
    return;
  }

  UnixCredentials credentials{};
  if (!ReadTraceeMemory(pid, regs.regs[3], &credentials, sizeof(credentials))) {
    return;
  }

  const auto peer = states.find(credentials.pid);
  if (peer != states.end()) {
    credentials.uid = peer->second.effective_uid;
    credentials.gid = peer->second.effective_gid;
  } else {
    if (credentials.uid == app_uid) {
      credentials.uid = kRootUid;
    }
    if (credentials.gid == app_gid) {
      credentials.gid = kRootGid;
    }
  }
  WriteTraceeMemory(pid, regs.regs[3], &credentials, sizeof(credentials));
}

void ReplaceAppOwnership(struct stat* file_stat, uid_t app_uid, gid_t app_gid) {
  if (file_stat == nullptr) {
    return;
  }
  if (file_stat->st_uid == app_uid) {
    file_stat->st_uid = kRootUid;
  }
  if (file_stat->st_gid == app_gid) {
    file_stat->st_gid = kRootGid;
  }
}

void ReplaceAppOwnership(
    struct statx* file_stat, uid_t app_uid, gid_t app_gid) {
  if (file_stat == nullptr) {
    return;
  }
  if (file_stat->stx_uid == app_uid) {
    file_stat->stx_uid = kRootUid;
  }
  if (file_stat->stx_gid == app_gid) {
    file_stat->stx_gid = kRootGid;
  }
}

void RewriteStatOwnershipIfNeeded(
    pid_t pid, uid_t app_uid, gid_t app_gid, const user_pt_regs& regs) {
  if (static_cast<int64_t>(regs.regs[0]) != 0) {
    return;
  }

  uint64_t stat_address = 0;
  switch (regs.regs[8]) {
    case kSysNewfstatat:
      stat_address = regs.regs[2];
      break;
    case kSysFstat:
      stat_address = regs.regs[1];
      break;
    case kSysStatx: {
      struct statx file_stat{};
      stat_address = regs.regs[4];
      if (stat_address == 0 ||
          !ReadTraceeMemory(pid, stat_address, &file_stat, sizeof(file_stat))) {
        return;
      }
      ReplaceAppOwnership(&file_stat, app_uid, app_gid);
      WriteTraceeMemory(pid, stat_address, &file_stat, sizeof(file_stat));
      return;
    }
    default:
      return;
  }

  struct stat file_stat{};
  if (stat_address == 0 ||
      !ReadTraceeMemory(pid, stat_address, &file_stat, sizeof(file_stat))) {
    return;
  }
  ReplaceAppOwnership(&file_stat, app_uid, app_gid);
  WriteTraceeMemory(pid, stat_address, &file_stat, sizeof(file_stat));
}

bool MaybeEmulateUnavailableAuditSocket(
    pid_t pid, TraceeState* state, user_pt_regs* regs) {
  if (state == nullptr || regs == nullptr || regs->regs[8] != kSysSocket ||
      regs->regs[0] != kAfNetlink || regs->regs[2] != kNetlinkAudit) {
    return false;
  }

  SetEmulatedSyscallReturn(pid, state, regs, -EPROTONOSUPPORT);
  return true;
}

bool MaybeEmulateShadowLockSyscall(pid_t pid,
    const std::string& normalized_rootfs, uid_t app_uid, gid_t app_gid,
    TraceeState* state, user_pt_regs* regs) {
  if (state == nullptr || regs == nullptr) {
    return false;
  }

  if (regs->regs[8] == kSysNewfstatat) {
    std::string path;
    if (!ReadTraceeCString(pid, regs->regs[1], kPathReadLimit, &path) ||
        state->copied_lock_sources.erase(path) == 0) {
      return false;
    }

    struct stat file_stat{};
    if (stat(RewritePathToRootfs(normalized_rootfs, path).c_str(),
            &file_stat) != 0) {
      SetEmulatedSyscallReturn(pid, state, regs, -errno);
      return true;
    }
    ReplaceAppOwnership(&file_stat, app_uid, app_gid);
    file_stat.st_nlink = 2;
    const int64_t result =
        WriteTraceeMemory(pid, regs->regs[2], &file_stat, sizeof(file_stat)) ?
            0 :
            -EFAULT;
    SetEmulatedSyscallReturn(pid, state, regs, result);
    return true;
  }

  if (regs->regs[8] != kSysLinkat) {
    return false;
  }

  std::string source_path;
  std::string lock_path;
  if (!ReadTraceeCString(pid, regs->regs[1], kPathReadLimit, &source_path) ||
      !ReadTraceeCString(pid, regs->regs[3], kPathReadLimit, &lock_path) ||
      source_path.rfind("/etc/", 0) != 0 || lock_path.rfind("/etc/", 0) != 0 ||
      lock_path.size() <= 5 ||
      lock_path.compare(lock_path.size() - 5, 5, ".lock") != 0) {
    return false;
  }

  const std::string lock_base     = lock_path.substr(0, lock_path.size() - 5);
  const std::string source_prefix = lock_base + ".";
  if (source_path.rfind(source_prefix, 0) != 0 ||
      source_path.size() == source_prefix.size() ||
      !std::all_of(source_path.begin() + source_prefix.size(),
          source_path.end(), [](char value) {
            return value >= '0' && value <= '9';
          })) {
    return false;
  }

  const std::string real_source =
      RewritePathToRootfs(normalized_rootfs, source_path);
  const std::string real_lock =
      RewritePathToRootfs(normalized_rootfs, lock_path);
  const int flags = static_cast<int>(regs->regs[4]);
  if (linkat(AT_FDCWD, real_source.c_str(), AT_FDCWD, real_lock.c_str(),
          flags) == 0) {
    SetEmulatedSyscallReturn(pid, state, regs, 0);
    return true;
  }

  const int link_errno = errno;
  if (link_errno != EPERM && link_errno != EACCES && link_errno != ENOSYS &&
      link_errno != EOPNOTSUPP) {
    SetEmulatedSyscallReturn(pid, state, regs, -link_errno);
    return true;
  }

  const int source_fd = open(real_source.c_str(), O_RDONLY | O_CLOEXEC);
  if (source_fd < 0) {
    SetEmulatedSyscallReturn(pid, state, regs, -errno);
    return true;
  }
  const int lock_fd =
      open(real_lock.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  if (lock_fd < 0) {
    const int open_errno = errno;
    close(source_fd);
    SetEmulatedSyscallReturn(pid, state, regs, -open_errno);
    return true;
  }

  bool copy_succeeded = true;
  char buffer[256];
  while (copy_succeeded) {
    const ssize_t read_size = read(source_fd, buffer, sizeof(buffer));
    if (read_size == 0) {
      break;
    }
    if (read_size < 0) {
      if (errno == EINTR) {
        continue;
      }
      copy_succeeded = false;
      break;
    }
    size_t written = 0;
    while (written < static_cast<size_t>(read_size)) {
      const ssize_t write_size =
          write(lock_fd, buffer + written, read_size - written);
      if (write_size < 0 && errno == EINTR) {
        continue;
      }
      if (write_size <= 0) {
        copy_succeeded = false;
        break;
      }
      written += static_cast<size_t>(write_size);
    }
  }
  close(source_fd);
  if (close(lock_fd) != 0) {
    copy_succeeded = false;
  }
  if (!copy_succeeded) {
    const int copy_errno = errno == 0 ? EIO : errno;
    unlink(real_lock.c_str());
    SetEmulatedSyscallReturn(pid, state, regs, -copy_errno);
    return true;
  }

  state->copied_lock_sources.insert(source_path);
  SetEmulatedSyscallReturn(pid, state, regs, 0);
  return true;
}

void ApplyExecCredentialTransition(TraceeState* state) {
  if (state == nullptr || !state->pending_executable) {
    return;
  }

  struct stat executable_stat{};
  if (fstat(state->pending_executable->image->fd, &executable_stat) != 0) {
    return;
  }
  if ((executable_stat.st_mode & S_ISUID) != 0) {
    state->effective_uid = state->saved_uid = state->fs_uid = kRootUid;
  }
  if ((executable_stat.st_mode & S_ISGID) != 0) {
    state->effective_gid = state->saved_gid = state->fs_gid = kRootGid;
  }
}

bool MaybeEmulatePrctlSyscall(
    pid_t pid, TraceeState* state, user_pt_regs* regs) {
  if (regs == nullptr || regs->regs[8] != kSysPrctl ||
      regs->regs[0] != PR_SET_DUMPABLE || regs->regs[1] != 0) {
    return false;
  }

  SetEmulatedSyscallReturn(pid, state, regs, 0);
  __android_log_print(ANDROID_LOG_INFO, kLogTag,
      "Preserved dumpable state for traced pid=%d", pid);
  return true;
}

bool MaybeHandleIoctlSyscall(
    pid_t pid, TraceeState* state, user_pt_regs* regs) {
  if (regs == nullptr || regs->regs[8] != kSysIoctl) {
    return false;
  }

  const uint64_t request = regs->regs[1];
  const uint64_t fd      = regs->regs[0];

  if (state != nullptr && request == kSiocgifindex) {
    ifreq interface_request{};
    if (regs->regs[2] == 0 ||
        !ReadTraceeMemory(pid, regs->regs[2], &interface_request,
            sizeof(interface_request))) {
      SetEmulatedSyscallReturn(pid, state, regs, -EFAULT);
      return true;
    }

    interface_request.ifr_name[IFNAMSIZ - 1] = '\0';
    const bool is_loopback = strcmp(interface_request.ifr_name, "lo") == 0;
    if (!is_loopback && !state->emulated_network_namespace) {
      return false;
    }
    if (!is_loopback) {
      SetEmulatedSyscallReturn(pid, state, regs, -ENODEV);
      return true;
    }

    interface_request.ifr_ifindex = 1;
    if (!WriteTraceeMemory(pid, regs->regs[2], &interface_request,
            sizeof(interface_request))) {
      SetEmulatedSyscallReturn(pid, state, regs, -EFAULT);
      return true;
    }
    SetEmulatedSyscallReturn(pid, state, regs, 0);
    return true;
  }

  char path[256];
  snprintf(path, sizeof(path), "/proc/%d/fd/%llu", pid,
      static_cast<unsigned long long>(fd));
  char    target[256];
  ssize_t len = readlink(path, target, sizeof(target) - 1);
  if (len > 0) {
    target[len] = '\0';
  } else {
    target[0] = '\0';
  }

  __android_log_print(ANDROID_LOG_INFO, kLogTag,
      "ioctl pid=%d fd=%llu request=0x%llx target=%s", pid,
      static_cast<unsigned long long>(fd),
      static_cast<unsigned long long>(request), target);

  uint64_t rewritten_request = 0;
  if (strncmp(target, "/dev/pts/", 9) == 0) {
    switch (request) {
      case kTcgets2:
        rewritten_request = kTcgets;
        break;
      case kTcsets2:
        rewritten_request = kTcsets;
        break;
      case kTcsetsw2:
        rewritten_request = kTcsetsw;
        break;
      case kTcsetsf2:
        rewritten_request = kTcsetsf;
        break;
      default:
        break;
    }
  }
  if (rewritten_request != 0) {
    regs->regs[1] = rewritten_request;
    if (!SetRegs(pid, *regs)) {
      return false;
    }
    __android_log_print(ANDROID_LOG_INFO, kLogTag,
        "rewrote devpts ioctl pid=%d request=0x%llx to 0x%llx", pid,
        static_cast<unsigned long long>(request),
        static_cast<unsigned long long>(rewritten_request));
    return true;
  }

  if (request == kTiocgwinsz || request == kTcgets || request == kTiocgpgrp ||
      request == kTiocspgrp) {
    if (len > 0) {
      if (strncmp(target, "pipe:", 5) == 0 ||
          strncmp(target, "socket:", 7) == 0 ||
          strncmp(target, "anon_inode:", 11) == 0) {
        __android_log_print(
            ANDROID_LOG_INFO, kLogTag, "emulating ioctl for target=%s", target);
        SetEmulatedSyscallReturn(pid, state, regs, -ENOTTY);
        return true;
      }
    }
  }
  return false;
}

bool MaybeRewritePingSocket(pid_t pid, user_pt_regs* regs) {
  if (regs == nullptr || regs->regs[8] != kSysSocket) {
    return false;
  }

  const uint64_t domain     = regs->regs[0];
  const uint64_t type       = regs->regs[1];
  const uint64_t protocol   = regs->regs[2];
  const uint64_t base_type  = type & kSockTypeMask;
  const bool     is_icmp_v4 = domain == kAfInet && protocol == kIpProtoIcmp;
  const bool     is_icmp_v6 = domain == kAfInet6 && protocol == kIpProtoIcmpv6;
  if (base_type != kSockRaw || (!is_icmp_v4 && !is_icmp_v6)) {
    return false;
  }

  regs->regs[1] = (type & ~kSockTypeMask) | kSockDgram;
  if (!SetRegs(pid, *regs)) {
    __android_log_print(ANDROID_LOG_WARN, kLogTag,
        "Failed to rewrite ping socket for pid=%d", pid);
    return false;
  }

  __android_log_print(ANDROID_LOG_INFO, kLogTag,
      "rewrote ICMP raw socket to datagram ping socket pid=%d domain=%llu "
      "protocol=%llu",
      pid, static_cast<unsigned long long>(domain),
      static_cast<unsigned long long>(protocol));
  return true;
}

bool ApplyEmulatedSyscallReturn(pid_t pid, TraceeState* state) {
  if (state == nullptr || !state->has_emulated_return) {
    return false;
  }

  const uint64_t return_value = state->emulated_return;
  state->has_emulated_return  = false;
  state->emulated_return      = 0;

  user_pt_regs regs{};
  if (!GetRegs(pid, &regs)) {
    __android_log_print(ANDROID_LOG_WARN, kLogTag,
        "Failed to read regs for emulated syscall pid=%d", pid);
    return false;
  }

  regs.regs[0] = return_value;
  if (!SetRegs(pid, regs)) {
    __android_log_print(ANDROID_LOG_WARN, kLogTag,
        "Failed to set emulated syscall result pid=%d", pid);
    return false;
  }

  return true;
}

void RewritePathArgument(pid_t pid, const std::string& normalized_rootfs,
    const TraceeState&                            state,
    const std::unordered_map<pid_t, TraceeState>& states, user_pt_regs* regs,
    int arg_index, int dir_fd_arg_index, uint64_t scratch_offset) {
  const uint64_t source_path_address = regs->regs[arg_index];
  if (source_path_address == 0) {
    return;
  }

  std::string original_path;
  if (!ReadTraceeCString(
          pid, source_path_address, kPathReadLimit, &original_path) ||
      original_path.empty()) {
    return;
  }
  std::string virtual_path = original_path;
  if (!IsAbsoluteUnixPath(virtual_path)) {
    const int   dir_fd = dir_fd_arg_index < 0 ?
                             AT_FDCWD :
                             static_cast<int>(regs->regs[dir_fd_arg_index]);
    std::string base_path;
    if (!ResolveVirtualPathBase(pid, dir_fd, normalized_rootfs, &base_path)) {
      return;
    }
    if (base_path.back() != '/') {
      base_path.push_back('/');
    }
    virtual_path = base_path + virtual_path;
  }

  if (!state.emulated_old_root.empty() &&
      (virtual_path == state.emulated_old_root ||
          virtual_path.rfind(state.emulated_old_root + "/", 0) == 0)) {
    virtual_path = virtual_path.substr(state.emulated_old_root.size());
    if (virtual_path.empty()) {
      virtual_path = "/";
    }
  } else if (IsAbsoluteUnixPath(original_path) &&
             !state.emulated_new_root.empty() &&
             original_path != normalized_rootfs &&
             original_path.rfind(normalized_rootfs + "/", 0) != 0 &&
             !IsPassthroughUnixPath(original_path)) {
    virtual_path = state.emulated_new_root + virtual_path;
  }

  virtual_path = ResolveEmulatedBindMounts(state, virtual_path);
  virtual_path = ResolveVirtualSymlinks(normalized_rootfs, virtual_path,
      ShouldFollowFinalSymlink(pid, *regs, arg_index), true, &states, pid);
  const std::string rewritten_path =
      RewritePathToRootfs(normalized_rootfs, virtual_path);
  if (rewritten_path == original_path) {
    return;
  }

  __android_log_print(ANDROID_LOG_VERBOSE, kLogTag,
      "rewrite pid=%d syscall=%llu %s -> %s", pid,
      static_cast<unsigned long long>(regs->regs[8]), original_path.c_str(),
      rewritten_path.c_str());

  const uint64_t scratch_address =
      regs->sp > scratch_offset ? regs->sp - scratch_offset : 0;
  if (scratch_address != 0 &&
      WriteTraceeMemory(pid, scratch_address, rewritten_path.c_str(),
          rewritten_path.size() + 1)) {
    regs->regs[arg_index] = scratch_address;
    if (!SetRegs(pid, *regs)) {
      __android_log_print(
          ANDROID_LOG_WARN, kLogTag, "Failed to set regs for pid=%d", pid);
    }
    return;
  }

  if (rewritten_path.size() <= original_path.size() &&
      WriteTraceeMemory(pid, source_path_address, rewritten_path.c_str(),
          rewritten_path.size() + 1)) {
    return;
  }
}

void RewriteOpenat2IfNeeded(pid_t pid, const std::string& normalized_rootfs,
    TraceeState* state, user_pt_regs* regs) {
  if (state == nullptr || regs == nullptr || regs->regs[8] != kSysOpenat2 ||
      regs->regs[3] != sizeof(OpenHow)) {
    return;
  }

  OpenHow how{};
  if (!ReadTraceeMemory(pid, regs->regs[2], &how, sizeof(how)) ||
      (how.resolve & kResolveInRoot) == 0 ||
      (how.resolve & ~(kResolveNoMagiclinks | kResolveInRoot)) != 0 ||
      how.flags > UINT32_MAX || how.mode > UINT32_MAX) {
    return;
  }

  std::string path;
  std::string virtual_root;
  if (!ReadTraceeCString(pid, regs->regs[1], kPathReadLimit, &path) ||
      path.empty() ||
      !ResolveVirtualPathBase(pid, static_cast<int>(regs->regs[0]),
          normalized_rootfs, &virtual_root)) {
    return;
  }

  if (!IsAbsoluteUnixPath(path)) {
    path.insert(path.begin(), '/');
  }
  std::string rewritten_path;
  if (virtual_root == "/") {
    rewritten_path = RewritePathToRootfs(
        normalized_rootfs, ResolveVirtualSymlinks(normalized_rootfs, path,
                               (how.flags & O_NOFOLLOW) == 0));
  } else {
    const std::string resolution_root =
        RewritePathToRootfs(normalized_rootfs, virtual_root);
    const std::string resolved_path = ResolveVirtualSymlinks(
        resolution_root, path, (how.flags & O_NOFOLLOW) == 0, false);
    rewritten_path = resolved_path == "/" ? resolution_root :
                                            resolution_root + resolved_path;
  }
  const uint64_t scratch_address =
      regs->sp > kStackScratchOffset ? regs->sp - kStackScratchOffset : 0;
  if (scratch_address == 0 ||
      !WriteTraceeMemory(pid, scratch_address, rewritten_path.c_str(),
          rewritten_path.size() + 1)) {
    return;
  }

  regs->regs[1] = scratch_address;
  regs->regs[2] = how.flags;
  regs->regs[3] = how.mode;
  regs->regs[8] = kSysOpenat;
  if (!SetRegs(pid, *regs)) {
    __android_log_print(
        ANDROID_LOG_WARN, kLogTag, "Failed to rewrite openat2 for pid=%d", pid);
    return;
  }
  state->pending_openat2_retry = true;
  state->pending_openat_dirfd  = regs->regs[0];
  state->pending_openat_path   = regs->regs[1];
  state->pending_openat_flags  = regs->regs[2];
  state->pending_openat_mode   = regs->regs[3];
  __android_log_print(ANDROID_LOG_VERBOSE, kLogTag,
      "rewrote openat2 to openat pid=%d path=%s", pid, rewritten_path.c_str());
}

void RewritePathArgumentsIfNeeded(pid_t pid,
    const std::string& normalized_rootfs, TraceeState& state,
    const std::unordered_map<pid_t, TraceeState>& states, user_pt_regs* regs) {
  const uint64_t syscall_number = regs->regs[8];
  switch (syscall_number) {
    case kSysSetxattr:
    case kSysLsetxattr:
    case kSysGetxattr:
    case kSysLgetxattr:
    case kSysListxattr:
    case kSysLlistxattr:
    case kSysRemovexattr:
    case kSysLremovexattr:
    case kSysChdir:
    case kSysExecve:
    case kSysStatfs:
      RewritePathArgument(pid, normalized_rootfs, state, states, regs, 0, -1,
          kStackScratchOffset);
      return;
    case kSysMknodat:
    case kSysMkdirat:
    case kSysUnlinkat:
    case kSysFaccessat:
    case kSysFchmodat:
    case kSysFchownat:
    case kSysOpenat:
    case kSysReadlinkat:
    case kSysNewfstatat:
    case kSysUtimensat:
    case kSysStatx:
    case kSysFaccessat2:
      RewritePathArgument(pid, normalized_rootfs, state, states, regs, 1, 0,
          kStackScratchOffset);
      return;
    case kSysOpenat2:
      RewriteOpenat2IfNeeded(pid, normalized_rootfs, &state, regs);
      return;
    case kSysSymlinkat:
      RewritePathArgument(pid, normalized_rootfs, state, states, regs, 2, 1,
          kStackScratchOffset);
      return;
    case kSysLinkat:
    case kSysRenameat:
    case kSysRenameat2:
      RewritePathArgument(pid, normalized_rootfs, state, states, regs, 1, 0,
          kStackScratchOffset);
      RewritePathArgument(pid, normalized_rootfs, state, states, regs, 3, 2,
          kStackScratchOffset * 2);
      return;
    default:
      return;
  }
}

void RewriteSockaddrIfNeeded(
    pid_t pid, const std::string& normalized_rootfs, user_pt_regs* regs) {
  const uint64_t syscall_number     = regs->regs[8];
  int            sockaddr_arg_index = -1;
  int            addrlen_arg_index  = -1;

  if (syscall_number == kSysBind || syscall_number == kSysConnect) {
    sockaddr_arg_index = 1;
    addrlen_arg_index  = 2;
  } else if (syscall_number == kSysSendto) {
    sockaddr_arg_index = 4;
    addrlen_arg_index  = 5;
  } else {
    return;
  }

  const uint64_t sockaddr_address = regs->regs[sockaddr_arg_index];
  const uint64_t addrlen          = regs->regs[addrlen_arg_index];

  if (sockaddr_address == 0 || addrlen < sizeof(sa_family_t)) {
    return;
  }

  sa_family_t family = 0;
  if (!ReadTraceeMemory(pid, sockaddr_address, &family, sizeof(family))) {
    return;
  }

  if (family != kAfUnix) {
    return;
  }

  const size_t path_offset = offsetof(sockaddr_un, sun_path);
  if (addrlen <= path_offset) {
    return;
  }

  char first_byte = 0;
  if (!ReadTraceeMemory(pid, sockaddr_address + path_offset, &first_byte, 1)) {
    return;
  }
  if (first_byte == '\0') {
    return;
  }

  size_t path_size = static_cast<size_t>(addrlen) - path_offset;
  if (path_size > sizeof(sockaddr_un{}.sun_path)) {
    path_size = sizeof(sockaddr_un{}.sun_path);
  }
  std::vector<char> path_buffer(path_size);
  if (!ReadTraceeMemory(pid, sockaddr_address + path_offset, path_buffer.data(),
          path_buffer.size())) {
    return;
  }

  const char* terminator = static_cast<const char*>(
      memchr(path_buffer.data(), '\0', path_buffer.size()));
  const size_t original_path_size =
      terminator == nullptr ?
          path_buffer.size() :
          static_cast<size_t>(terminator - path_buffer.data());
  const std::string original_path(path_buffer.data(), original_path_size);
  if (!IsAbsoluteUnixPath(original_path)) {
    return;
  }

  const bool        follow_final_symlink = syscall_number != kSysBind;
  const std::string rewritten_path       = RewritePathToRootfs(
      normalized_rootfs, ResolveVirtualSymlinks(normalized_rootfs,
                             original_path, follow_final_symlink));
  if (rewritten_path == original_path) {
    return;
  }

  __android_log_print(ANDROID_LOG_VERBOSE, kLogTag,
      "rewrite_sockaddr pid=%d syscall=%llu %s -> %s", pid,
      static_cast<unsigned long long>(syscall_number), original_path.c_str(),
      rewritten_path.c_str());

  const size_t new_addrlen = path_offset + rewritten_path.size() + 1;
  if (new_addrlen > sizeof(sockaddr_un)) {
    __android_log_print(
        ANDROID_LOG_WARN, kLogTag, "rewritten unix socket path too long");
    return;
  }

  const uint64_t scratch_address =
      regs->sp > kStackScratchOffset ? regs->sp - kStackScratchOffset : 0;
  if (scratch_address == 0) {
    return;
  }

  sockaddr_un rewritten_address{};
  rewritten_address.sun_family = family;
  memcpy(rewritten_address.sun_path, rewritten_path.c_str(),
      rewritten_path.size() + 1);
  if (!WriteTraceeMemory(
          pid, scratch_address, &rewritten_address, new_addrlen)) {
    return;
  }

  regs->regs[sockaddr_arg_index] = scratch_address;
  regs->regs[addrlen_arg_index]  = new_addrlen;
  if (!SetRegs(pid, *regs)) {
    __android_log_print(ANDROID_LOG_WARN, kLogTag,
        "Failed to set regs for pid=%d sockaddr", pid);
  }
}

int ChildTraceeMain(const std::string& extract_dst_path,
    const std::string& command_path_in_rootfs, int stdin_fd, int stdout_fd,
    int stderr_fd) {
  if (dup2(stdin_fd, STDIN_FILENO) < 0) {
    return 127;
  }
  if (dup2(stdout_fd, STDOUT_FILENO) < 0) {
    return 127;
  }
  if (dup2(stderr_fd, STDERR_FILENO) < 0) {
    return 127;
  }

  if (chdir(extract_dst_path.c_str()) != 0) {
    return 127;
  }

  if (!ResetEnvironment()) {
    return 127;
  }

  if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) != 0) {
    return 127;
  }
  raise(SIGSTOP);

  const char* argv[] = {command_path_in_rootfs.c_str(), nullptr};
  execv(command_path_in_rootfs.c_str(), const_cast<char* const *>(argv));
  __android_log_print(ANDROID_LOG_ERROR, kLogTag,
      "execve failed: executable=%s errno=%d (%s)",
      command_path_in_rootfs.c_str(), errno, strerror(errno));
  return 126;
}

void ResumeSyscall(pid_t pid, int signal_number) {
  if (ptrace(PTRACE_SYSCALL, pid, nullptr, signal_number) != 0) {
    __android_log_print(ANDROID_LOG_WARN, kLogTag,
        "PTRACE_SYSCALL failed for pid=%d (%d)", pid, errno);
  }
}

bool SuppressBlockedSyscall(pid_t pid, TraceeState* state) {
  user_pt_regs regs{};
  if (!GetRegs(pid, &regs)) {
    __android_log_print(ANDROID_LOG_WARN, kLogTag,
        "Failed to read regs for SIGSYS pid=%d", pid);
    return false;
  }

  siginfo_t  siginfo{};
  const bool has_siginfo =
      ptrace(PTRACE_GETSIGINFO, pid, nullptr, &siginfo) == 0;
  if (has_siginfo) {
    __android_log_print(ANDROID_LOG_WARN, kLogTag,
        "pid=%d blocked syscall=%d arch=0x%x code=%d", pid, siginfo.si_syscall,
        siginfo.si_arch, siginfo.si_code);
  } else {
    __android_log_print(ANDROID_LOG_WARN, kLogTag,
        "pid=%d blocked syscall=%llu", pid,
        static_cast<unsigned long long>(regs.regs[8]));
  }

  const int blocked_syscall =
      has_siginfo ? siginfo.si_syscall : static_cast<int>(regs.regs[8]);
  if (static_cast<uint64_t>(blocked_syscall) == kSysOpenat2 &&
      state != nullptr && state->pending_openat2_retry && has_siginfo &&
      siginfo.si_call_addr != nullptr) {
    regs.regs[0] = state->pending_openat_dirfd;
    regs.regs[1] = state->pending_openat_path;
    regs.regs[2] = state->pending_openat_flags;
    regs.regs[3] = state->pending_openat_mode;
    regs.regs[8] = kSysOpenat;
    regs.pc =
        reinterpret_cast<uintptr_t>(siginfo.si_call_addr) - sizeof(uint32_t);
    if (!SetRegs(pid, regs)) {
      __android_log_print(
          ANDROID_LOG_WARN, kLogTag, "Failed to retry openat for pid=%d", pid);
      return false;
    }
    state->expect_entry          = true;
    state->has_emulated_return   = false;
    state->emulated_return       = 0;
    state->pending_openat2_retry = false;
    __android_log_print(ANDROID_LOG_VERBOSE, kLogTag,
        "retrying blocked openat2 as openat pid=%d", pid);
    return true;
  }
  const bool is_emulated_syscall =
      static_cast<uint64_t>(blocked_syscall) == kSysGetpid &&
      state != nullptr && state->has_emulated_return;
  const uint64_t return_value = is_emulated_syscall ?
                                    state->emulated_return :
                                    static_cast<uint64_t>(-ENOSYS);

  regs.regs[0] = return_value;
  if (!SetRegs(pid, regs)) {
    __android_log_print(ANDROID_LOG_WARN, kLogTag,
        "Failed to set SIGSYS result for pid=%d", pid);
    return false;
  }
  if (state != nullptr) {
    state->expect_entry        = true;
    state->has_emulated_return = false;
    state->emulated_return     = 0;
  }
  return true;
}

bool PrepareSharedMemoryDirectory(const std::string& normalized_rootfs) {
  const std::string dev_path = normalized_rootfs + "/dev";
  const int         dev_fd =
      open(dev_path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (dev_fd < 0) {
    __android_log_print(ANDROID_LOG_ERROR, kLogTag,
        "Failed to open rootfs device directory: %s (%s)", dev_path.c_str(),
        strerror(errno));
    return false;
  }

  if (flock(dev_fd, LOCK_EX) != 0) {
    __android_log_print(ANDROID_LOG_ERROR, kLogTag,
        "Failed to lock rootfs device directory: %s (%s)", dev_path.c_str(),
        strerror(errno));
    close(dev_fd);
    return false;
  }

  struct stat dev_stat{};
  if (fstat(dev_fd, &dev_stat) != 0) {
    __android_log_print(ANDROID_LOG_ERROR, kLogTag,
        "Failed to inspect rootfs device directory: %s (%s)", dev_path.c_str(),
        strerror(errno));
    close(dev_fd);
    return false;
  }

  const mode_t required_dev_mode = S_IWUSR | S_IXUSR;
  const bool   restore_dev_mode =
      (dev_stat.st_mode & required_dev_mode) != required_dev_mode;
  if (restore_dev_mode &&
      fchmod(dev_fd, dev_stat.st_mode | required_dev_mode) != 0) {
    __android_log_print(ANDROID_LOG_ERROR, kLogTag,
        "Failed to make rootfs device directory writable: %s (%s)",
        dev_path.c_str(), strerror(errno));
    close(dev_fd);
    return false;
  }

  const int mkdir_result = mkdirat(dev_fd, "shm", 01777);
  const int mkdir_errno  = errno;
  if (restore_dev_mode && fchmod(dev_fd, dev_stat.st_mode) != 0) {
    __android_log_print(ANDROID_LOG_ERROR, kLogTag,
        "Failed to restore rootfs device directory permissions: %s (%s)",
        dev_path.c_str(), strerror(errno));
    close(dev_fd);
    return false;
  }
  if (mkdir_result != 0 && mkdir_errno != EEXIST) {
    __android_log_print(ANDROID_LOG_ERROR, kLogTag,
        "Failed to create rootfs shared-memory directory: %s/shm (%s)",
        dev_path.c_str(), strerror(mkdir_errno));
    close(dev_fd);
    return false;
  }

  const int shm_fd =
      openat(dev_fd, "shm", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (shm_fd < 0) {
    __android_log_print(ANDROID_LOG_ERROR, kLogTag,
        "Failed to open rootfs shared-memory directory: %s/shm (%s)",
        dev_path.c_str(), strerror(errno));
    close(dev_fd);
    return false;
  }
  if (fchmod(shm_fd, 01777) != 0) {
    __android_log_print(ANDROID_LOG_ERROR, kLogTag,
        "Failed to set rootfs shared-memory permissions: %s/shm (%s)",
        dev_path.c_str(), strerror(errno));
    close(shm_fd);
    close(dev_fd);
    return false;
  }

  close(shm_fd);
  close(dev_fd);
  return true;
}

bool PrepareEmulatedProcFiles(const std::string& normalized_rootfs) {
  struct utsname identity{};
  if (uname(&identity) != 0) {
    __android_log_print(ANDROID_LOG_ERROR, kLogTag,
        "Failed to read kernel hostname: %s", strerror(errno));
    return false;
  }
  // The hostname sysctl may be unreadable even though uname exposes the same
  // UTS name.
  const std::string hostname = std::string(identity.nodename) + "\n";
  struct File {
    const char* backing_path;
    const char* value;
    size_t      value_size;
  };
  const File files[] = {
      {kHostnameBackingPath,              hostname.c_str(),            hostname.size()             },
      {kInotifyMaxUserWatchesBackingPath, kInotifyMaxUserWatchesValue,
       sizeof(kInotifyMaxUserWatchesValue) - 1                                                     },
      {kOverflowUidBackingPath,           kOverflowIdValue,            sizeof(kOverflowIdValue) - 1},
      {kOverflowGidBackingPath,           kOverflowIdValue,            sizeof(kOverflowIdValue) - 1},
  };

  for (const File& file : files) {
    const std::string backing_path = normalized_rootfs + file.backing_path;
    const std::string temporary_template = backing_path + ".XXXXXX";
    std::vector<char> temporary_path_buffer(
        temporary_template.begin(), temporary_template.end());
    temporary_path_buffer.push_back('\0');

    const int fd = mkostemp(temporary_path_buffer.data(), O_CLOEXEC);
    if (fd < 0) {
      __android_log_print(ANDROID_LOG_ERROR, kLogTag,
          "Failed to create temporary proc file: %s (%s)",
          temporary_template.c_str(), strerror(errno));
      return false;
    }
    const std::string temporary_path(temporary_path_buffer.data());

    size_t written = 0;
    while (written < file.value_size) {
      const ssize_t result =
          write(fd, file.value + written, file.value_size - written);
      if (result < 0 && errno == EINTR) {
        continue;
      }
      if (result <= 0) {
        __android_log_print(ANDROID_LOG_ERROR, kLogTag,
            "Failed to write proc file: %s (%s)", temporary_path.c_str(),
            strerror(errno));
        close(fd);
        unlink(temporary_path.c_str());
        return false;
      }
      written += static_cast<size_t>(result);
    }

    if (fchmod(fd, 0444) != 0) {
      __android_log_print(ANDROID_LOG_ERROR, kLogTag,
          "Failed to set proc file permissions: %s (%s)",
          temporary_path.c_str(), strerror(errno));
      close(fd);
      unlink(temporary_path.c_str());
      return false;
    }
    close(fd);

    if (rename(temporary_path.c_str(), backing_path.c_str()) != 0) {
      __android_log_print(ANDROID_LOG_ERROR, kLogTag,
          "Failed to publish proc file: %s (%s)", backing_path.c_str(),
          strerror(errno));
      unlink(temporary_path.c_str());
      return false;
    }
  }
  return true;
}

int TracerMain(const std::string& extract_dst_path,
    const std::function<int()>&   child_spawn_func) {
  prctl(PR_SET_PDEATHSIG, SIGKILL);

  const std::string normalized_rootfs = NormalizeRootfsPrefix(extract_dst_path);
  const uid_t       app_uid           = getuid();
  const gid_t       app_gid           = getgid();
  if (!PrepareSharedMemoryDirectory(normalized_rootfs)) {
    return 1;
  }
  if (!PrepareEmulatedProcFiles(normalized_rootfs)) {
    return 1;
  }

  const pid_t tracee_pid = fork();
  if (tracee_pid < 0) {
    return 1;
  }
  if (tracee_pid == 0) {
    _exit(child_spawn_func());
  }

  int status = 0;
  if (waitpid(tracee_pid, &status, 0) != tracee_pid || !WIFSTOPPED(status)) {
    return 1;
  }

  std::unordered_map<pid_t, TraceeState> states;
  std::unordered_set<pid_t>              tracked_pids;

  TraceeState initial_state;
  if (getrlimit(RLIMIT_NOFILE, &initial_state.file_descriptor_limit) != 0) {
    initial_state.file_descriptor_limit = {
        .rlim_cur = 1024,
        .rlim_max = 1024,
    };
  }
  states.emplace(tracee_pid, std::move(initial_state));
  tracked_pids.emplace(tracee_pid);
  if (!ApplyTraceOptions(tracee_pid)) {
    return 1;
  }
  states[tracee_pid].options_applied = true;
  ResumeSyscall(tracee_pid, 0);

  while (!tracked_pids.empty()) {
    int         wait_status = 0;
    const pid_t pid         = waitpid(-1, &wait_status, __WALL);
    if (pid < 0) {
      if (errno == EINTR) {
        continue;
      }
      break;
    }

    if (WIFEXITED(wait_status)) {
      __android_log_print(ANDROID_LOG_INFO, kLogTag, "pid=%d exited status=%d",
          pid, WEXITSTATUS(wait_status));
      tracked_pids.erase(pid);
      if (!states[pid].emulated_mountinfo_path.empty()) {
        unlink(states[pid].emulated_mountinfo_path.c_str());
      }
      states.erase(pid);
      continue;
    }
    if (WIFSIGNALED(wait_status)) {
      __android_log_print(ANDROID_LOG_WARN, kLogTag, "pid=%d killed signal=%d",
          pid, WTERMSIG(wait_status));
      tracked_pids.erase(pid);
      if (!states[pid].emulated_mountinfo_path.empty()) {
        unlink(states[pid].emulated_mountinfo_path.c_str());
      }
      states.erase(pid);
      continue;
    }
    if (!WIFSTOPPED(wait_status)) {
      continue;
    }

    auto& state = states[pid];
    if (!state.options_applied) {
      state.options_applied = ApplyTraceOptions(pid);
    }

    const int      signal_number = WSTOPSIG(wait_status);
    const unsigned event         = static_cast<unsigned>(wait_status) >> 16U;
    if (signal_number == (SIGTRAP | 0x80)) {
      bool                is_syscall_entry        = state.expect_entry;
      bool                syscall_direction_known = false;
      ptrace_syscall_info syscall_info{};
      const long          syscall_info_size = ptrace(
          PTRACE_GET_SYSCALL_INFO, pid, sizeof(syscall_info), &syscall_info);
      if (syscall_info_size > 0 &&
          (syscall_info.op == PTRACE_SYSCALL_INFO_ENTRY ||
              syscall_info.op == PTRACE_SYSCALL_INFO_SECCOMP)) {
        is_syscall_entry        = true;
        syscall_direction_known = true;
      } else if (syscall_info_size > 0 &&
                 syscall_info.op == PTRACE_SYSCALL_INFO_EXIT) {
        is_syscall_entry        = false;
        syscall_direction_known = true;
      }

      if (state.has_emulated_return && !is_syscall_entry) {
        RestoreOpenPermission(&state);
        ApplyEmulatedSyscallReturn(pid, &state);
        state.expect_entry = true;
        ResumeSyscall(pid, 0);
        continue;
      }

      user_pt_regs regs{};
      if (GetRegs(pid, &regs)) {
        if (!is_syscall_entry) {
          RestoreOpenPermission(&state);
          state.pending_executable.reset();
          TrackEmulatedNetworkNamespaceFd(&state, regs);
          if (regs.regs[8] == kSysSendmsg ||
              (regs.regs[8] == kSysRecvmsg &&
                  static_cast<int64_t>(regs.regs[0]) >= 0)) {
            RewriteUnixCredentials(
                pid, regs.regs[1], app_uid, app_gid, states, false);
          }
          RewritePeerCredentials(pid, app_uid, app_gid, states, regs);
        }
        if (is_syscall_entry || !syscall_direction_known) {
          RewriteSockaddrIfNeeded(pid, normalized_rootfs, &regs);
        }
        if (is_syscall_entry) {
          state.pending_openat2_retry = false;
          if (regs.regs[8] == kSysSendmsg) {
            RewriteUnixCredentials(
                pid, regs.regs[1], app_uid, app_gid, states, true);
          }
          RedirectUserNamespaceControlFile(
              pid, normalized_rootfs, state, &regs);
          RedirectEmulatedMountInfo(pid, normalized_rootfs, &state, &regs);
          if (!MaybeEmulateNamespaceSyscall(pid, &state, &regs) &&
              !MaybeEmulateMountNamespaceOperation(
                  pid, normalized_rootfs, &state, &regs) &&
              !MaybeEmulateNetworkNamespaceOperation(pid, &state, &regs) &&
              !MaybeEmulateGetcwd(pid, normalized_rootfs, &state, &regs) &&
              !MaybeEmulateProcReadlink(
                  pid, normalized_rootfs, states, &state, &regs) &&
              !MaybeEmulatePrctlSyscall(pid, &state, &regs) &&
              !MaybeEmulateFileDescriptorLimit(pid, &state, &regs) &&
              !MaybeEmulateUidGidSyscall(pid, &state, &regs) &&
              !MaybeEmulateUnavailableAuditSocket(pid, &state, &regs) &&
              !MaybeEmulateShadowLockSyscall(
                  pid, normalized_rootfs, app_uid, app_gid, &state, &regs) &&
              !MaybeHandleIoctlSyscall(pid, &state, &regs)) {
            MaybeRewriteAcceptSyscall(pid, &regs);
            MaybeRewritePingSocket(pid, &regs);
            if (!RewriteExecveIfNeeded(
                    pid, normalized_rootfs, states, &state, &regs)) {
              RewritePathArgumentsIfNeeded(
                  pid, normalized_rootfs, state, states, &regs);
            }
          }
        } else {
          RewriteStatOwnershipIfNeeded(pid, app_uid, app_gid, regs);
        }
      }
      state.expect_entry = !is_syscall_entry;
      ResumeSyscall(pid, 0);
      continue;
    }

    if (signal_number == SIGTRAP && event != 0U) {
      __android_log_print(
          ANDROID_LOG_VERBOSE, kLogTag, "pid=%d ptrace event=%u", pid, event);
      if (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK ||
          event == PTRACE_EVENT_CLONE) {
        unsigned long new_pid = 0;
        if (ptrace(PTRACE_GETEVENTMSG, pid, nullptr, &new_pid) == 0 &&
            new_pid > 0) {
          tracked_pids.insert(static_cast<pid_t>(new_pid));
          TraceeState child_state           = state;
          child_state.expect_entry          = true;
          child_state.options_applied       = false;
          child_state.has_emulated_return   = false;
          child_state.emulated_return       = 0;
          child_state.pending_openat2_retry = false;
          child_state.emulated_mountinfo_path.clear();
          child_state.pending_open_permission_path.clear();
          child_state.pending_open_permission_mode = 0;
          child_state.pending_executable.reset();
          states.insert_or_assign(
              static_cast<pid_t>(new_pid), std::move(child_state));
        }
      } else if (event == PTRACE_EVENT_EXEC) {
        unsigned long previous_tid = 0;
        if (ptrace(PTRACE_GETEVENTMSG, pid, nullptr, &previous_tid) == 0 &&
            previous_tid != 0 &&
            previous_tid != static_cast<unsigned long>(pid)) {
          auto previous = states.find(static_cast<pid_t>(previous_tid));
          if (previous != states.end()) {
            state = std::move(previous->second);
            states.erase(previous);
          }
          tracked_pids.erase(static_cast<pid_t>(previous_tid));
          tracked_pids.insert(pid);
        }
        if (state.pending_executable) {
          auto&                     executable = *state.pending_executable;
          std::vector<Elf64_auxv_t> auxv;
          const char*               stage = "load executable";
          int error = InitializeElfExecutable(pid, *executable.image,
              executable.interpreter.get(), executable.execfn, executable.comm,
              &auxv);
          if (error == 0) {
            stage              = "create auxv";
            executable.auxv_fd = syscall(SYS_memfd_create, "andlify-auxv",
                MFD_CLOEXEC | MFD_ALLOW_SEALING);
            if (executable.auxv_fd < 0)
              error = -errno;
          }
          if (error == 0) {
            stage             = "write auxv";
            const size_t size = auxv.size() * sizeof(Elf64_auxv_t);
            ssize_t      written;
            do {
              written = write(executable.auxv_fd, auxv.data(), size);
            } while (written < 0 && errno == EINTR);
            if (written != static_cast<ssize_t>(size)) {
              error = written < 0 ? -errno : -EIO;
            }
          }
          if (error == 0) {
            stage = "seal auxv";
            // Android denies setattr on app memfds; seals prevent content
            // changes without chmod.
            if (fcntl(executable.auxv_fd, F_ADD_SEALS,
                    F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) !=
                0) {
              error = -errno;
            }
          }
          if (error != 0) {
            __android_log_print(ANDROID_LOG_ERROR, kLogTag,
                "ELF initialization failed pid=%d executable=%s stage=%s: %s",
                pid, executable.execfn.c_str(), stage, strerror(-error));
            kill(pid, SIGKILL);
            continue;
          }
          ApplyExecCredentialTransition(&state);
          executable.interpreter.reset();
          state.executable   = std::move(state.pending_executable);
          state.expect_entry = true;
        }
      }
      ResumeSyscall(pid, 0);
      continue;
    }

    if (signal_number == SIGSTOP) {
      ResumeSyscall(pid, 0);
      continue;
    }

    if (signal_number == SIGSYS) {
      if (SuppressBlockedSyscall(pid, &state)) {
        ResumeSyscall(pid, 0);
      } else {
        ResumeSyscall(pid, signal_number);
      }
      continue;
    }

    __android_log_print(ANDROID_LOG_VERBOSE, kLogTag, "pid=%d signal stop=%d",
        pid, signal_number);
    ResumeSyscall(pid, signal_number);
  }

  return 0;
}

}  // namespace

int StartChroot(const std::string& extract_dst_path,
    const std::string& command_path_in_rootfs, int stdin_fd, int stdout_fd,
    int stderr_fd) {
  if (extract_dst_path.empty() || command_path_in_rootfs.empty()) {
    return -EINVAL;
  }
  if (stdin_fd < 0 || stdout_fd < 0 || stderr_fd < 0) {
    return -EBADF;
  }

  auto child_spawn_func = [=]() {
    return ChildTraceeMain(extract_dst_path, command_path_in_rootfs, stdin_fd,
        stdout_fd, stderr_fd);
  };

  const pid_t tracer_pid = fork();
  if (tracer_pid < 0) {
    return -errno;
  }

  if (tracer_pid == 0) {
    _exit(TracerMain(extract_dst_path, child_spawn_func));
  }

  return tracer_pid;
}

int StartChrootFunc(const std::string& extract_dst_path,
    const std::function<int()>& child_func, int stdin_fd, int stdout_fd,
    int stderr_fd) {
  if (extract_dst_path.empty() || !child_func) {
    return -EINVAL;
  }
  if (stdin_fd < 0 || stdout_fd < 0 || stderr_fd < 0) {
    return -EBADF;
  }

  auto child_spawn_func = [=]() {
    if (dup2(stdin_fd, STDIN_FILENO) < 0) {
      return 127;
    }
    if (dup2(stdout_fd, STDOUT_FILENO) < 0) {
      return 127;
    }
    if (dup2(stderr_fd, STDERR_FILENO) < 0) {
      return 127;
    }

    if (chdir(extract_dst_path.c_str()) != 0) {
      return 127;
    }

    if (!ResetEnvironment()) {
      return 127;
    }

    if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) != 0) {
      return 127;
    }
    raise(SIGSTOP);

    return child_func();
  };

  const pid_t tracer_pid = fork();
  if (tracer_pid < 0) {
    return -errno;
  }

  if (tracer_pid == 0) {
    _exit(TracerMain(extract_dst_path, child_spawn_func));
  }

  return tracer_pid;
}

void StopChroot(pid_t tracer_pid) {
  if (tracer_pid <= 0) {
    return;
  }

  if (kill(tracer_pid, SIGTERM) != 0 && errno == ESRCH) {
    return;
  }

  for (int i = 0; i < 50; ++i) {
    const pid_t waited = waitpid(tracer_pid, nullptr, WNOHANG);
    if (waited == tracer_pid) {
      return;
    }
    if (waited < 0 && errno == ECHILD) {
      return;
    }
    usleep(20 * 1000);
  }

  if (kill(tracer_pid, SIGKILL) == 0) {
    waitpid(tracer_pid, nullptr, 0);
  }
}
