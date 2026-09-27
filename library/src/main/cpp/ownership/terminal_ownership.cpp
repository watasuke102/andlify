#include <fcntl.h>
#include <linux/magic.h>
#include <sys/vfs.h>
#include <unistd.h>

#include <cerrno>

#include "ownership_store_internal.h"

namespace andlify {
using namespace ownership_detail;
namespace {
bool Live(const Terminal& entry) {
  if (!entry.owner.inode || ProcessStart(entry.keeper) != entry.start_time)
    return false;
  struct stat info{};
  const auto  path = "/proc/" + std::to_string(entry.keeper) + "/fd/" +
                     std::to_string(entry.fd);
  // A pinned inode survives unlink; its link count distinguishes index reuse.
  return stat(path.c_str(), &info) == 0 && info.st_nlink != 0 &&
         info.st_dev == entry.owner.device && info.st_ino == entry.owner.inode;
}
}  // namespace

bool OwnershipStore::LookupTerminal(const struct stat& info, FileOwner* owner) {
  if (!S_ISCHR(info.st_mode) || !info.st_nlink || !Lock())
    return false;
  bool found = false;
  for (const auto& entry : shared_->terminals) {
    if (entry.owner.device == info.st_dev && entry.owner.inode == info.st_ino &&
        Live(entry)) {
      *owner = entry.owner;
      found  = true;
      break;
    }
  }
  Unlock();
  return found;
}

bool OwnershipStore::TerminalOwner(const std::string& path, bool follow,
    FileOwner* owner, const FileOwner* replacement) {
  int fd = open(path.c_str(), O_PATH | O_CLOEXEC | (follow ? 0 : O_NOFOLLOW));
  if (fd < 0)
    return false;
  struct stat   info{};
  struct statfs filesystem{};
  bool          valid = fstat(fd, &info) == 0 && fstatfs(fd, &filesystem) == 0;
  if (!valid || !S_ISCHR(info.st_mode) ||
      filesystem.f_type != DEVPTS_SUPER_MAGIC || info.st_uid != getuid() ||
      !info.st_nlink) {
    close(fd);
    errno = ENOTTY;
    return false;
  }
  // The shared ptmx node is not an individual allocated terminal.
  if (info.st_ino == 2) {
    close(fd);
    errno = ENOTTY;
    return false;
  }
  if (!Lock()) {
    close(fd);
    return false;
  }
  for (auto it = terminal_pins_.begin(); it != terminal_pins_.end();) {
    struct stat pinned{};
    if (fstat(it->second, &pinned) == 0 && pinned.st_nlink != 0) {
      ++it;
      continue;
    }
    auto& old = shared_->terminals[it->first];
    if (old.keeper == getpid() && old.fd == it->second)
      old.owner.inode = 0;
    close(it->second);
    it = terminal_pins_.erase(it);
  }
  size_t index     = kTerminals;
  size_t available = kTerminals;
  for (size_t i = 0; i < kTerminals; ++i) {
    const auto& entry = shared_->terminals[i];
    if (entry.owner.device == info.st_dev && entry.owner.inode == info.st_ino) {
      index = i;
      break;
    }
    if (!entry.owner.inode && available == kTerminals)
      available = i;
  }
  if (index == kTerminals) {
    index = available;
    if (index == kTerminals) {
      for (size_t i = 0; i < kTerminals; ++i) {
        if (!Live(shared_->terminals[i])) {
          index = i;
          break;
        }
      }
    }
  }
  if (index == kTerminals) {
    Unlock();
    close(fd);
    errno = ENOSPC;
    return false;
  }
  auto&      entry = shared_->terminals[index];
  const bool live  = entry.owner.device == info.st_dev &&
                     entry.owner.inode == info.st_ino && Live(entry);
  FileOwner  current =
      live ? entry.owner :
             FileOwner{uint64_t(info.st_dev), uint64_t(info.st_ino),
                 uint64_t(info.st_ctim.tv_sec), uint32_t(info.st_ctim.tv_nsec),
                 1000, info.st_gid == getgid() ? 1000U : uint32_t(info.st_gid),
                 uint32_t(info.st_mode)};
  if (replacement &&
      (!live || owner->uid != current.uid || owner->gid != current.gid ||
          owner->mode != current.mode || !SameBirth(*owner, current))) {
    Unlock();
    close(fd);
    errno = EAGAIN;
    return false;
  }
  if (!live || replacement) {
    if (!live) {
      const auto pin = terminal_pins_.find(index);
      if (pin != terminal_pins_.end())
        close(pin->second);
      terminal_pins_[index] = fd;
    }
    const auto keeper  = live ? entry.keeper : getpid();
    const auto pin_fd  = live ? entry.fd : fd;
    const auto start   = live ? entry.start_time : ProcessStart(getpid());
    FileOwner  updated = replacement ? *replacement : current;
    // A killed writer must leave an invalid entry, never partially new owners.
    __atomic_store_n(&entry.owner.inode, 0, __ATOMIC_SEQ_CST);
    const auto inode = updated.inode;
    updated.inode    = 0;
    entry.owner      = updated;
    entry.keeper     = keeper;
    entry.fd         = pin_fd;
    entry.start_time = start;
    __atomic_store_n(&entry.owner.inode, inode, __ATOMIC_RELEASE);
  }
  *owner = entry.owner;
  Unlock();
  if (live)
    close(fd);
  return true;
}
}  // namespace andlify
