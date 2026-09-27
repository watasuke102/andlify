#include "virtual_filesystem.h"

#include <fcntl.h>
#include <linux/stat.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <filesystem>

#include "ptrace_memory.h"

namespace andlify {
namespace {
enum : uint64_t {
  kSetxattr     = 5,
  kLsetxattr    = 6,
  kRemovexattr  = 14,
  kLremovexattr = 15,
  kMknodat      = 33,
  kMkdirat      = 34,
  kUnlinkat     = 35,
  kSymlinkat    = 36,
  kLinkat       = 37,
  kRenameat     = 38,
  kTruncate     = 45,
  kFtruncate    = 46,
  kFaccessat    = 48,
  kChdir        = 49,
  kFchdir       = 50,
  kFchmod       = 52,
  kFchmodat     = 53,
  kFchownat     = 54,
  kFchown       = 55,
  kOpenat       = 56,
  kReadlinkat   = 78,
  kNewfstatat   = 79,
  kUtimensat    = 88,
  kBind         = 200,
  kConnect      = 203,
  kExecve       = 221,
  kRenameat2    = 276,
  kExecveat     = 281,
  kStatx        = 291,
  kOpenat2      = 437,
  kFaccessat2   = 439,
  kFchmodat2    = 452,
};
bool Managed(const OwnershipStore& store, const std::string& path) {
  return path == store.root() || path.rfind(store.root() + "/", 0) == 0;
}
bool Owner(OwnershipStore& store, const std::string& path, FileOwner* owner) {
  struct stat st{};
  if (lstat(path.c_str(), &st) != 0)
    return false;
  if (store.Lookup(st.st_dev, st.st_ino, owner))
    return true;
  if (errno != ENOENT || !store.Identify(path, owner))
    return false;
  return store.Set(*owner);
}
bool Group(const FileCredentials& credentials, uint32_t gid) {
  return credentials.gid == gid ||
         std::find(credentials.groups.begin(), credentials.groups.end(), gid) !=
             credentials.groups.end();
}
bool Allowed(const FileOwner& owner, const FileCredentials& c, int mask) {
  if (c.uid == 0)
    return !(mask & X_OK) || S_ISDIR(owner.mode) || (owner.mode & 0111);
  unsigned bits = owner.mode;
  if (c.uid == owner.uid)
    bits >>= 6;
  else if (Group(c, owner.gid))
    bits >>= 3;
  return (bits & mask) == unsigned(mask);
}
int Search(
    OwnershipStore& store, const std::string& path, const FileCredentials& c) {
  if (!Managed(store, path))
    return 0;
  std::string parent = std::filesystem::path(path).parent_path();
  while (Managed(store, parent)) {
    FileOwner owner;
    if (!Owner(store, parent, &owner))
      return errno;
    if (!S_ISDIR(owner.mode))
      return ENOTDIR;
    if (!Allowed(owner, c, X_OK))
      return EACCES;
    if (parent == store.root())
      break;
    parent = std::filesystem::path(parent).parent_path();
  }
  return 0;
}
int Parent(OwnershipStore& store, const std::string& path,
    const FileCredentials& c, FileOwner* parent) {
  const std::string dir = std::filesystem::path(path).parent_path();
  if (!Owner(store, dir, parent))
    return errno;
  if (!Allowed(*parent, c, W_OK | X_OK))
    return EACCES;
  return 0;
}
int Sticky(const FileOwner& parent, const FileOwner& target,
    const FileCredentials& c) {
  if ((parent.mode & S_ISVTX) && c.uid != 0 && c.uid != parent.uid &&
      c.uid != target.uid)
    return EPERM;
  return 0;
}
}  // namespace

int CheckFileAccess(OwnershipStore& store, const std::string& path,
    const FileCredentials& credentials, int mask) {
  if (!Managed(store, path))
    return 0;
  FileOwner owner;
  if (!Owner(store, path, &owner))
    return errno;
  if (!S_ISDIR(owner.mode) && mask == X_OK)
    return ENOTDIR;
  return Allowed(owner, credentials, mask) ? 0 : EACCES;
}

bool PrepareFileOperation(pid_t pid, uint64_t syscall, uint64_t* a,
    const FileCredentials& c, OwnershipStore& store, const ResolveFile& resolve,
    PendingFile* pending, int64_t* result) {
  *pending          = {};
  int      path_arg = -1;
  int      dir_arg  = -1;
  bool     follow   = true;
  bool     fd       = false;
  uint64_t flags    = 0;
  if (syscall == kBind || syscall == kConnect) {
    sockaddr_un address{};
    if (a[2] > sizeof(address) || a[2] <= offsetof(sockaddr_un, sun_path) ||
        !ReadTraceeMemory(pid, a[1], &address, a[2]) ||
        address.sun_family != AF_UNIX || !address.sun_path[0])
      return false;
    std::string socket_path(
        address.sun_path, strnlen(address.sun_path, sizeof(address.sun_path)));
    if (!Managed(store, socket_path))
      return false;
    int       error = Search(store, socket_path, c);
    FileOwner owner;
    if (!error && syscall == kBind)
      error = Parent(store, socket_path, c, &owner);
    if (!error && syscall == kConnect) {
      if (!Owner(store, socket_path, &owner))
        error = errno;
      else if (!Allowed(owner, c, W_OK))
        error = EACCES;
    }
    if (error) {
      *result = -error;
      return true;
    }
    if (syscall == kBind) {
      pending->creation   = true;
      pending->path       = socket_path;
      pending->owner.uid  = c.uid;
      pending->owner.gid  = (owner.mode & S_ISGID) ? owner.gid : c.gid;
      pending->owner.mode = S_IFSOCK | (0777 & ~c.mask);
    }
    return false;
  }
  switch (syscall) {
    case kOpenat:
      flags    = a[2];
      path_arg = 1;
      dir_arg  = 0;
      follow =
          !(flags & O_NOFOLLOW) && !((flags & O_CREAT) && (flags & O_EXCL));
      break;
    case kOpenat2: {
      struct {
        uint64_t flags, mode, resolve;
      } how{};
      if (a[3] < sizeof(how) ||
          !ReadTraceeMemory(pid, a[2], &how, sizeof(how))) {
        *result = -EINVAL;
        return true;
      }
      // Path resolution constraints must not be silently discarded.
      if (how.resolve & ~uint64_t(0x12)) {
        *result = -EOPNOTSUPP;
        return true;
      }
      flags    = how.flags;
      path_arg = 1;
      dir_arg  = 0;
      follow   = !(flags & O_NOFOLLOW);
      break;
    }
    case kMknodat:
    case kMkdirat:
    case kUnlinkat:
    case kRenameat:
    case kRenameat2:
    case kReadlinkat:
      path_arg = 1;
      dir_arg  = 0;
      follow   = false;
      break;
    case kSymlinkat:
      path_arg = 2;
      dir_arg  = 1;
      follow   = false;
      break;
    case kLinkat:
      path_arg = 1;
      dir_arg  = 0;
      follow   = (a[4] & AT_SYMLINK_FOLLOW);
      break;
    case kFaccessat:
    case kFchmodat:
      path_arg = 1;
      dir_arg  = 0;
      break;
    case kFchownat:
      path_arg = 1;
      dir_arg  = 0;
      follow   = !(a[4] & AT_SYMLINK_NOFOLLOW);
      break;
    case kNewfstatat:
      path_arg = 1;
      dir_arg  = 0;
      follow   = !(a[3] & AT_SYMLINK_NOFOLLOW);
      break;
    case kUtimensat:
    case kStatx:
    case kFaccessat2:
    case kFchmodat2:
      path_arg = 1;
      dir_arg  = 0;
      follow   = !((syscall == kStatx ? a[2] : a[3]) & AT_SYMLINK_NOFOLLOW);
      break;
    case kChdir:
    case kExecve:
      path_arg = 0;
      break;
    case kExecveat:
      path_arg = 1;
      dir_arg  = 0;
      follow   = !(a[4] & AT_SYMLINK_NOFOLLOW);
      break;
    case kFchmod:
    case kFchown:
    case kFchdir:
    case kFtruncate:
      fd = true;
      break;
    case kTruncate:
      path_arg = 0;
      break;
    case kSetxattr:
    case kLsetxattr:
    case kRemovexattr:
    case kLremovexattr:
      path_arg = 0;
      follow   = syscall != kLsetxattr && syscall != kLremovexattr;
      break;
    default:
      return false;
  }
  std::string path;
  bool        outside = false;
  if (fd) {
    path = "/proc/" + std::to_string(pid) + "/fd/" + std::to_string(a[0]);
    char          buffer[4096];
    const ssize_t n = readlink(path.c_str(), buffer, sizeof(buffer));
    if (n < 0) {
      *result = -EBADF;
      return true;
    }
    std::string target(buffer, n);
    outside = !Managed(store, target);
  } else if (!resolve(path_arg, dir_arg, follow, &path)) {
    *result = -(errno ? errno : EFAULT);
    return true;
  }
  if (!fd && path.rfind("/proc/" + std::to_string(pid) + "/fd/", 0) == 0) {
    char          target[4096];
    const ssize_t n = readlink(path.c_str(), target, sizeof(target));
    if (n > 0) {
      fd      = true;
      outside = !Managed(store, std::string(target, n));
    }
  }
  FileOwner owner;
  bool      terminal = false;
  if (outside || (!fd && !Managed(store, path))) {
    if (!store.TerminalOwner(path, fd || follow, &owner)) {
      if (errno == ENOTTY)
        return false;
      *result = -errno;
      return true;
    }
    terminal = true;
  }
  auto fail = [&](int error) {
    *result = -error;
    return true;
  };
  int error = fd || terminal ? 0 : Search(store, path, c);
  if (error)
    return fail(error);
  bool exists = terminal;
  if (!terminal && fd) {
    struct stat st{};
    if (stat(path.c_str(), &st) != 0)
      return fail(errno);
    exists = store.Lookup(st.st_dev, st.st_ino, &owner);
  } else if (!terminal)
    exists = Owner(store, path, &owner);
  if (!exists && errno != ENOENT)
    return fail(errno);

  const FileOwner previous = owner;
  if (syscall == kFchownat || syscall == kFchown) {
    if (!exists)
      return fail(ENOENT);
    if (syscall == kFchownat && (a[4] & ~(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH)))
      return fail(EINVAL);
    const uint32_t uid = a[syscall == kFchown ? 1 : 2];
    const uint32_t gid = a[syscall == kFchown ? 2 : 3];
    if (c.uid != 0 &&
        (c.uid != owner.uid || (uid != UINT32_MAX && uid != owner.uid) ||
            (gid != UINT32_MAX && gid != owner.gid && !Group(c, gid))))
      return fail(EPERM);
    if (uid != UINT32_MAX)
      owner.uid = uid;
    if (gid != UINT32_MAX)
      owner.gid = gid;
    if (!S_ISDIR(owner.mode) && (uid != UINT32_MAX || gid != UINT32_MAX))
      owner.mode &= ~(S_ISUID | S_ISGID);
    if (terminal) {
      auto expected = previous;
      if (!store.TerminalOwner(path, fd || follow, &expected, &owner))
        return fail(errno);
    } else if (!store.Set(owner, true, &previous))
      return fail(errno);
    *result = 0;
    return true;
  }
  if (syscall == kFchmod || syscall == kFchmodat || syscall == kFchmodat2) {
    if (!exists)
      return fail(ENOENT);
    if (c.uid != 0 && c.uid != owner.uid)
      return fail(EPERM);
    if (syscall == kFchmodat2 &&
        (a[3] & ~(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH)))
      return fail(EINVAL);
    if (S_ISLNK(owner.mode))
      return fail(EOPNOTSUPP);
    uint32_t mode = a[syscall == kFchmod ? 1 : 2] & 07777;
    if (c.uid != 0 && !Group(c, owner.gid))
      mode &= ~S_ISGID;
    owner.mode = (owner.mode & S_IFMT) | mode;
    if (terminal) {
      auto expected = previous;
      if (!store.TerminalOwner(path, fd || follow, &expected, &owner))
        return fail(errno);
    } else if (!store.Set(owner, true, &previous))
      return fail(errno);
    if (!terminal &&
        chmod(path.c_str(), mode | (S_ISDIR(owner.mode) ? 0700 : 0600)) != 0)
      return fail(errno);
    *result = 0;
    return true;
  }
  if (syscall == kFaccessat || syscall == kFaccessat2) {
    if (!exists)
      return fail(ENOENT);
    if (a[2] & ~7U)
      return fail(EINVAL);
    if (!Allowed(owner, c, a[2]))
      return fail(EACCES);
    *result = 0;
    return true;
  }
  if (syscall == kOpenat || syscall == kOpenat2) {
    if (flags & O_PATH)
      flags &= uint64_t(O_PATH | O_NOFOLLOW | O_DIRECTORY);
    if ((flags & O_CREAT) && (flags & O_DIRECTORY) &&
        (flags & O_TMPFILE) != O_TMPFILE)
      return fail(EINVAL);
    if (!exists && !(flags & O_CREAT))
      return false;
    if (exists && (flags & O_CREAT) && (flags & O_EXCL))
      return fail(EEXIST);
    if (exists && !(flags & O_PATH)) {
      const int mask = (flags & O_ACCMODE) == O_RDONLY ? R_OK :
                       (flags & O_ACCMODE) == O_WRONLY ? W_OK :
                                                         R_OK | W_OK;
      if (!Allowed(owner, c, mask | ((flags & O_TRUNC) ? W_OK : 0)))
        return fail(EACCES);
      if (c.uid != 0 && (mask & W_OK) && (owner.mode & (S_ISUID | S_ISGID))) {
        owner.mode &= ~(S_ISUID | S_ISGID);
        if (!store.Set(owner))
          return fail(errno);
      }
    }
    pending->open = true;
    pending->path = path;
    if (!exists || (flags & O_TMPFILE) == O_TMPFILE) {
      FileOwner parent;
      error = (flags & O_TMPFILE) == O_TMPFILE ?
                  (exists && Allowed(owner, c, W_OK | X_OK) ? 0 : EACCES) :
                  Parent(store, path, c, &parent);
      if (error)
        return fail(error);
      if ((flags & O_TMPFILE) == O_TMPFILE)
        parent = owner;
      uint64_t mode = a[3];
      if (syscall == kOpenat2 &&
          !ReadTraceeMemory(pid, a[2] + 8, &mode, sizeof(mode)))
        return fail(EFAULT);
      pending->creation   = true;
      pending->owner.uid  = c.uid;
      pending->owner.gid  = (parent.mode & S_ISGID) ? parent.gid : c.gid;
      pending->owner.mode = S_IFREG | (mode & 07777 & ~c.mask);
      if (c.uid != 0 && !Group(c, pending->owner.gid))
        pending->owner.mode &= ~S_ISGID;
      if ((flags & O_TMPFILE) != O_TMPFILE) {
        if (!store.Create(path, pending->owner)) {
          if (errno != EEXIST || (flags & O_EXCL))
            return fail(errno);
          if (!Owner(store, path, &owner) ||
              !Allowed(owner, c,
                  ((flags & O_ACCMODE) == O_RDONLY    ? R_OK :
                      (flags & O_ACCMODE) == O_WRONLY ? W_OK :
                                                        R_OK | W_OK)))
            return fail(EACCES);
        }
        pending->creation = false;
        if (syscall == kOpenat)
          a[2] &= ~uint64_t(O_EXCL);
        else {
          pending->open_how_address = a[2];
          pending->open_how_flags   = flags;
          flags &= ~uint64_t(O_EXCL);
          if (!WriteTraceeMemory(pid, a[2], &flags, sizeof(flags)))
            return fail(EFAULT);
        }
      }
    }
    return false;
  }
  if (syscall == kMkdirat || syscall == kMknodat || syscall == kSymlinkat) {
    if (exists)
      return fail(EEXIST);
    FileOwner parent;
    if ((error = Parent(store, path, c, &parent)))
      return fail(error);
    pending->creation  = true;
    pending->path      = path;
    pending->owner.uid = c.uid;
    pending->owner.gid = (parent.mode & S_ISGID) ? parent.gid : c.gid;
    uint32_t mode =
        syscall == kSymlinkat ? (S_IFLNK | 0777) : uint32_t(a[2]) & ~c.mask;
    if (syscall == kMkdirat)
      mode = (mode & 07777) | S_IFDIR | (parent.mode & S_ISGID);
    if (syscall == kMknodat && !(mode & S_IFMT))
      mode |= S_IFREG;
    if (syscall == kMknodat && !S_ISREG(mode) && !S_ISFIFO(mode))
      return fail(EPERM);
    pending->owner.mode = mode;
    std::string target;
    if (syscall == kSymlinkat && !ReadTraceeCString(pid, a[0], 4096, &target))
      return fail(EFAULT);
    if (!store.Create(path, pending->owner, target))
      return fail(errno);
    *pending = {};
    *result  = 0;
    return true;
  }
  if (syscall == kUnlinkat || syscall == kRenameat || syscall == kRenameat2 ||
      syscall == kLinkat) {
    if (!exists)
      return fail(ENOENT);
    FileOwner parent;
    if (syscall != kLinkat) {
      if ((error = Parent(store, path, c, &parent)))
        return fail(error);
      if ((error = Sticky(parent, owner, c)))
        return fail(error);
    } else if (c.uid != 0 && c.uid != owner.uid &&
               (!S_ISREG(owner.mode) || (owner.mode & (S_ISUID | S_ISGID)) ||
                   !Allowed(owner, c, R_OK | W_OK)))
      return fail(EPERM);
    if (syscall != kUnlinkat) {
      std::string target;
      if (!resolve(3, 2, false, &target))
        return fail(EFAULT);
      if (!Managed(store, target))
        return fail(EXDEV);
      if ((error = Search(store, target, c)) ||
          (error = Parent(store, target, c, &parent)))
        return fail(error);
      FileOwner replaced;
      if (Owner(store, target, &replaced) &&
          (error = Sticky(parent, replaced, c)))
        return fail(error);
    }
    return false;
  }
  if (!exists)
    return false;
  int mask = 0;
  if (syscall == kChdir || syscall == kFchdir || syscall == kExecve ||
      syscall == kExecveat)
    mask = X_OK;
  if (syscall == kTruncate || syscall == kFtruncate || syscall == kSetxattr ||
      syscall == kLsetxattr || syscall == kRemovexattr ||
      syscall == kLremovexattr)
    mask = W_OK;
  if (syscall == kUtimensat && c.uid != 0 && c.uid != owner.uid) {
    if (a[2])
      return fail(EPERM);
    mask = W_OK;
  }
  if (mask && !Allowed(owner, c, mask))
    return fail(EACCES);
  return false;
}
bool FinishFileOperation(pid_t pid, int64_t result, OwnershipStore& store,
    const FileCredentials& /*credentials*/, PendingFile* pending) {
  if (pending->open_how_address &&
      !WriteTraceeMemory(pid, pending->open_how_address,
          &pending->open_how_flags, sizeof(pending->open_how_flags)))
    return false;
  if (result < 0 || !pending->creation) {
    *pending = {};
    return true;
  }
  std::string path = pending->path;
  if (pending->open)
    path = "/proc/" + std::to_string(pid) + "/fd/" + std::to_string(result);
  FileOwner owner;
  if (pending->open) {
    if (!store.Identify(path, &owner, true))
      return false;
    owner.uid  = pending->owner.uid;
    owner.gid  = pending->owner.gid;
    owner.mode = pending->owner.mode;
    if (!store.Set(owner) ||
        chmod(path.c_str(), (owner.mode & 07777) | 0600) != 0)
      return false;
  } else if (!store.SetPath(path, pending->owner.uid, pending->owner.gid,
                 pending->owner.mode))
    return false;
  *pending = {};
  return true;
}

}  // namespace andlify
