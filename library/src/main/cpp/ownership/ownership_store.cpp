#include "ownership_store.h"

#include <dirent.h>
#include <fcntl.h>
#include <linux/stat.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <new>
#include <sstream>

#include "ownership_store_internal.h"
#include "user_setup.h"

namespace andlify {
using namespace ownership_detail;
namespace ownership_detail {
uint64_t ProcessStart(pid_t pid) {
  std::ifstream input("/proc/" + std::to_string(pid) + "/stat");
  std::string   line;
  if (!std::getline(input, line))
    return 0;
  const auto end = line.rfind(')');
  if (end == std::string::npos)
    return 0;
  std::istringstream fields(line.substr(end + 1));
  std::string        field;
  for (int number = 3; number < 22; ++number)
    if (!(fields >> field))
      return 0;
  uint64_t start = 0;
  fields >> start;
  return start;
}
}  // namespace ownership_detail

OwnershipStore::~OwnershipStore() {
  for (const auto& pin : terminal_pins_) close(pin.second);
  if (journal_fd_ >= 0)
    close(journal_fd_);
  if (shared_)
    munmap(shared_, sizeof(Shared));
  if (lock_fd_ >= 0)
    close(lock_fd_);
  if (memory_fd_ >= 0)
    close(memory_fd_);
  if (directory_fd_ >= 0)
    close(directory_fd_);
  if (lease_fd_ >= 0)
    close(lease_fd_);
}

bool OwnershipStore::Open(const std::string& root, bool prepare_user) {
  char* canonical = realpath(root.c_str(), nullptr);
  if (!canonical)
    return false;
  root_ = canonical;
  free(canonical);
  directory_ = root_ + ".andlify-owners";
  if (mkdir(directory_.c_str(), 0700) != 0 && errno != EEXIST)
    return false;
  directory_fd_ =
      open(directory_.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (directory_fd_ < 0)
    return false;
  int init_fd = openat(directory_fd_, "init.lock",
      O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (init_fd < 0)
    return false;
  if (flock(init_fd, LOCK_EX) != 0) {
    close(init_fd);
    return false;
  }
  lease_fd_ = openat(
      directory_fd_, "lease", O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
  lock_fd_         = openat(directory_fd_, "writer.lock",
      O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
  bool       ok    = lease_fd_ >= 0 && lock_fd_ >= 0;
  const bool first = ok && flock(lease_fd_, LOCK_EX | LOCK_NB) == 0;
  if (ok && !first)
    ok = flock(lease_fd_, LOCK_SH) == 0;
  memory_fd_ = openat(
      directory_fd_, "table", O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
  ok = ok && memory_fd_ >= 0;
  if (ok && first)
    ok = ftruncate(memory_fd_, sizeof(Shared)) == 0;
  struct stat st{};
  if (ok)
    ok = fstat(memory_fd_, &st) == 0 && st.st_size == sizeof(Shared);
  if (ok) {
    void* memory = mmap(nullptr, sizeof(Shared), PROT_READ | PROT_WRITE,
        MAP_SHARED, memory_fd_, 0);
    ok           = memory != MAP_FAILED;
    if (ok)
      shared_ = static_cast<Shared*>(memory);
  }
  if (ok && first) {
    std::error_code error;
    for (const auto& entry :
        std::filesystem::directory_iterator(directory_, error)) {
      if (entry.path().filename().string().rfind("create-", 0) == 0) {
        std::filesystem::remove_all(entry.path(), error);
        if (error)
          break;
      }
    }
    if (error) {
      close(init_fd);
      errno = error.value();
      return false;
    }
    new (shared_) Shared{};
    if (ok)
      ok = Replay() && Scan() && (!prepare_user || PrepareUser(*this)) &&
           CheckpointLocked();
    if (ok)
      shared_->magic = kMagic;
    if (ok)
      ok = flock(lease_fd_, LOCK_SH) == 0;
  } else if (ok) {
    ok = shared_->magic == kMagic;
  }
  close(init_fd);
  return ok;
}
bool OwnershipStore::Lock() {
  if (flock(lock_fd_, LOCK_EX) != 0)
    return false;
  if (shared_->dirty && !Replay()) {
    __atomic_store_n(&shared_->failed, 1, __ATOMIC_RELEASE);
    Unlock();
    errno = EIO;
    return false;
  }
  if (__atomic_load_n(&shared_->failed, __ATOMIC_ACQUIRE)) {
    Unlock();
    errno = EIO;
    return false;
  }
  return true;
}
void OwnershipStore::Unlock() {
  auto version = __atomic_load_n(&shared_->version, __ATOMIC_RELAXED);
  if (version & 1)
    __atomic_store_n(&shared_->version, version + 1, __ATOMIC_RELEASE);
  flock(lock_fd_, LOCK_UN);
}

bool OwnershipStore::Put(const FileOwner& owner) {
  if (!owner.inode) {
    errno = EINVAL;
    return false;
  }
  size_t index = Hash(owner.device, owner.inode);
  for (size_t count = 0; count < kSlots;
      ++count, index = (index + 1) & (kSlots - 1)) {
    auto& slot = shared_->files[index];
    if (!slot.inode ||
        (slot.device == owner.device && slot.inode == owner.inode)) {
      const auto version = __atomic_load_n(&shared_->version, __ATOMIC_ACQUIRE);
      if (!(version & 1))
        __atomic_store_n(&shared_->version, version + 1, __ATOMIC_RELEASE);
      __atomic_thread_fence(__ATOMIC_SEQ_CST);
      WriteOwner(slot, owner);
      if (!(version & 1))
        __atomic_store_n(&shared_->version, version + 2, __ATOMIC_RELEASE);
      return true;
    }
  }
  errno = ENOSPC;
  return false;
}
bool OwnershipStore::Lookup(uint64_t device, uint64_t inode, FileOwner* owner) {
  for (;;) {
    if (__atomic_load_n(&shared_->failed, __ATOMIC_ACQUIRE)) {
      errno = EIO;
      return false;
    }
    const auto version = __atomic_load_n(&shared_->version, __ATOMIC_ACQUIRE);
    if (version & 1) {
      if (!Lock())
        return false;
      Unlock();
      continue;
    }
    size_t index = Hash(device, inode);
    bool   found = false;
    for (size_t n = 0; n < kSlots; ++n, index = (index + 1) & (kSlots - 1)) {
      const auto slot = ReadOwner(shared_->files[index]);
      if (!slot.inode)
        break;
      if (slot.device == device && slot.inode == inode) {
        *owner = slot;
        found  = true;
        break;
      }
    }
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    if (version != __atomic_load_n(&shared_->version, __ATOMIC_ACQUIRE))
      continue;
    if (!found)
      errno = ENOENT;
    return found;
  }
}
bool OwnershipStore::Identify(
    const std::string& path, FileOwner* owner, bool follow) {
  struct stat st{};
  if (fstatat(AT_FDCWD, path.c_str(), &st, follow ? 0 : AT_SYMLINK_NOFOLLOW) !=
      0)
    return false;
  struct statx sx{};
  const int    result = syscall(SYS_statx, AT_FDCWD, path.c_str(),
      follow ? 0 : AT_SYMLINK_NOFOLLOW, STATX_BTIME, &sx);
  // Birth time is optional; a usable lstat result must not require statx
  // support.
  if (result != 0 && errno != ENOSYS && errno != EOPNOTSUPP &&
      errno != EINVAL && errno != EPERM && errno != EACCES)
    return false;
  const bool has_birth = result == 0 && (sx.stx_mask & STATX_BTIME);
  *owner               = {uint64_t(st.st_dev), uint64_t(st.st_ino),
      has_birth ? uint64_t(sx.stx_btime.tv_sec) : 0,
      has_birth ? sx.stx_btime.tv_nsec : 0, 0, 0, uint32_t(st.st_mode)};
  return true;
}
bool OwnershipStore::SetPath(
    const std::string& path, uint32_t uid, uint32_t gid, mode_t mode) {
  FileOwner owner;
  if (!Identify(path, &owner))
    return false;
  owner.uid  = uid;
  owner.gid  = gid;
  owner.mode = (owner.mode & S_IFMT) | (mode & 07777);
  if (!Set(owner))
    return false;
  if (S_ISLNK(owner.mode))
    return true;
  // The kernel sees one app UID; virtual checks enforce the recorded mode.
  return chmod(path.c_str(),
             (mode & 07777) | (S_ISDIR(owner.mode) ? 0700 : 0600)) == 0;
}

bool OwnershipStore::Create(const std::string& path, const FileOwner& requested,
    const std::string& target) {
  if (!Lock())
    return false;
  std::string       pattern = directory_ + "/create-XXXXXX";
  std::vector<char> buffer(pattern.begin(), pattern.end());
  buffer.push_back(0);
  char* staging = mkdtemp(buffer.data());
  if (!staging) {
    Unlock();
    return false;
  }
  const std::string item = std::string(staging) + "/file";
  int               fd   = -1;
  bool              ok   = false;
  if (S_ISDIR(requested.mode))
    ok = mkdir(item.c_str(), 0700) == 0;
  else if (S_ISLNK(requested.mode))
    ok = symlink(target.c_str(), item.c_str()) == 0;
  else if (S_ISFIFO(requested.mode))
    ok = mkfifo(item.c_str(), 0600) == 0;
  else if (S_ISREG(requested.mode)) {
    fd = open(item.c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    ok = fd >= 0;
  } else
    errno = EINVAL;
  FileOwner owner;
  if (ok)
    ok = Identify(item, &owner);
  if (ok) {
    owner.uid  = requested.uid;
    owner.gid  = requested.gid;
    owner.mode = requested.mode;
    if (!S_ISLNK(owner.mode))
      ok = chmod(item.c_str(),
               (owner.mode & 07777) | (S_ISDIR(owner.mode) ? 0700 : 0600)) == 0;
    if (ok && fd >= 0)
      ok = fsync(fd) == 0;
    if (ok)
      ok = SetLocked(owner, true);
  }
  if (fd >= 0)
    close(fd);
  // Publishing only after the journal is durable prevents ownerless creations.
  if (ok)
    ok = syscall(SYS_renameat2, AT_FDCWD, item.c_str(), AT_FDCWD, path.c_str(),
             RENAME_NOREPLACE) == 0;
  if (ok) {
    int parent = open(std::filesystem::path(path).parent_path().c_str(),
        O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    ok         = parent >= 0 && fsync(parent) == 0;
    if (parent >= 0)
      close(parent);
  }
  const int error = errno;
  if (S_ISDIR(requested.mode))
    rmdir(item.c_str());
  else
    unlink(item.c_str());
  rmdir(staging);
  Unlock();
  errno = error;
  return ok;
}

bool OwnershipStore::Scan() {
  struct LiveFile {
    std::string path;
    FileOwner   owner;
    bool        widen;
  };
  std::vector<LiveFile>    live;
  std::vector<std::string> pending{root_};
  while (!pending.empty()) {
    std::string path = std::move(pending.back());
    pending.pop_back();
    FileOwner current;
    if (!Identify(path, &current))
      return false;
    const uint32_t required = S_ISDIR(current.mode) ? 0700 : 0600;
    bool           widen =
        !S_ISLNK(current.mode) && (current.mode & required) != required;
    FileOwner saved;
    if (Lookup(current.device, current.inode, &saved)) {
      const bool saved_birth = saved.birth_seconds || saved.birth_nanoseconds;
      const bool current_birth =
          current.birth_seconds || current.birth_nanoseconds;
      if (!saved_birth || !current_birth || SameBirth(saved, current)) {
        current.uid  = saved.uid;
        current.gid  = saved.gid;
        current.mode = saved.mode;
        if (!current_birth) {
          current.birth_seconds     = saved.birth_seconds;
          current.birth_nanoseconds = saved.birth_nanoseconds;
        }
      }
    }
    if (S_ISDIR(current.mode) && widen) {
      // Preserve the original mode before making a directory traversable.
      if (!Set(current) ||
          chmod(path.c_str(), (current.mode & 07777) | 0700) != 0)
        return false;
      widen = false;
    }
    live.push_back({path, current, widen});
    if (!S_ISDIR(current.mode))
      continue;
    DIR* dir = opendir(path.c_str());
    if (!dir)
      return false;
    errno = 0;
    while (auto* entry = readdir(dir)) {
      if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
        continue;
      pending.push_back(path + "/" + entry->d_name);
    }
    int error = errno;
    closedir(dir);
    if (error) {
      errno = error;
      return false;
    }
  }
  for (auto& owner : shared_->files) WriteOwner(owner, {});
  for (const auto& file : live)
    if (!Put(file.owner))
      return false;
  if (!CheckpointLocked())
    return false;
  for (const auto& file : live) {
    if (file.widen &&
        chmod(file.path.c_str(), (file.owner.mode & 07777) | 0600) != 0)
      return false;
  }
  return true;
}
bool OwnershipStore::RegisterProcess(const ProcessOwner& process) {
  const uint64_t start = ProcessStart(process.pid);
  if (!start) {
    errno = ESRCH;
    return false;
  }
  if (!Lock())
    return false;
  ProcessOwner* free  = nullptr;
  size_t        index = uint32_t(process.pid) % kProcesses;
  for (size_t n = 0; n < kProcesses; ++n, index = (index + 1) % kProcesses) {
    auto& slot = shared_->processes[index];
    if (slot.pid == process.pid) {
      free = &slot;
      break;
    }
    if (slot.pid <= 0 && !free)
      free = &slot;
    if (!slot.pid)
      break;
  }
  if (free) {
    auto version = __atomic_load_n(&shared_->version, __ATOMIC_RELAXED);
    __atomic_store_n(&shared_->version, version | 1, __ATOMIC_RELEASE);
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    __atomic_store_n(&free->pid, -1, __ATOMIC_RELEASE);
    __atomic_store_n(&free->real_uid, process.real_uid, __ATOMIC_RELAXED);
    __atomic_store_n(
        &free->effective_uid, process.effective_uid, __ATOMIC_RELAXED);
    __atomic_store_n(&free->real_gid, process.real_gid, __ATOMIC_RELAXED);
    __atomic_store_n(
        &free->effective_gid, process.effective_gid, __ATOMIC_RELAXED);
    __atomic_store_n(&free->start_time, start, __ATOMIC_RELAXED);
    __atomic_store_n(&free->pid, process.pid, __ATOMIC_RELEASE);
  }
  Unlock();
  if (!free)
    errno = ENOSPC;
  return free != nullptr;
}
bool OwnershipStore::Process(pid_t pid, ProcessOwner* process) {
  for (;;) {
    if (__atomic_load_n(&shared_->failed, __ATOMIC_ACQUIRE)) {
      errno = EIO;
      return false;
    }
    const auto version = __atomic_load_n(&shared_->version, __ATOMIC_ACQUIRE);
    if (version & 1) {
      if (!Lock())
        return false;
      Unlock();
      continue;
    }
    bool   found = false;
    size_t index = uint32_t(pid) % kProcesses;
    for (size_t n = 0; n < kProcesses; ++n, index = (index + 1) % kProcesses) {
      const auto& slot      = shared_->processes[index];
      const auto  saved_pid = __atomic_load_n(&slot.pid, __ATOMIC_ACQUIRE);
      if (!saved_pid)
        break;
      if (saved_pid != pid)
        continue;
      *process = {pid, __atomic_load_n(&slot.real_uid, __ATOMIC_RELAXED),
          __atomic_load_n(&slot.effective_uid, __ATOMIC_RELAXED),
          __atomic_load_n(&slot.real_gid, __ATOMIC_RELAXED),
          __atomic_load_n(&slot.effective_gid, __ATOMIC_RELAXED),
          __atomic_load_n(&slot.start_time, __ATOMIC_RELAXED)};
      found    = true;
      break;
    }
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    if (version == __atomic_load_n(&shared_->version, __ATOMIC_ACQUIRE))
      return found && process->start_time == ProcessStart(pid);
  }
}
void OwnershipStore::ForgetProcess(pid_t pid) {
  if (!Lock())
    return;
  size_t index = uint32_t(pid) % kProcesses;
  for (size_t n = 0; n < kProcesses; ++n, index = (index + 1) % kProcesses) {
    auto& slot = shared_->processes[index];
    if (!slot.pid)
      break;
    if (slot.pid == pid) {
      auto version = __atomic_load_n(&shared_->version, __ATOMIC_RELAXED);
      __atomic_store_n(&shared_->version, version | 1, __ATOMIC_RELEASE);
      __atomic_store_n(&slot.pid, -1, __ATOMIC_RELEASE);
      break;
    }
  }
  Unlock();
}
}  // namespace andlify
