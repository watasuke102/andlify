#pragma once

#include <sys/stat.h>
#include <sys/types.h>

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace andlify {
struct FileOwner {
  uint64_t device            = 0;
  uint64_t inode             = 0;
  uint64_t birth_seconds     = 0;
  uint32_t birth_nanoseconds = 0;
  uint32_t uid               = 0;
  uint32_t gid               = 0;
  uint32_t mode              = 0;
};

struct ProcessOwner {
  int32_t  pid           = 0;
  uint32_t real_uid      = 1000;
  uint32_t effective_uid = 1000;
  uint32_t real_gid      = 1000;
  uint32_t effective_gid = 1000;
  uint64_t start_time    = 0;
};

class OwnershipStore {
 public:
  OwnershipStore() = default;
  ~OwnershipStore();
  OwnershipStore(const OwnershipStore&)            = delete;
  OwnershipStore& operator=(const OwnershipStore&) = delete;
  bool            Open(const std::string& root, bool prepare_user = false);
  bool TerminalOwner(const std::string& path, bool follow, FileOwner* owner,
      const FileOwner* replacement = nullptr);
  bool LookupTerminal(const struct stat& info, FileOwner* owner);
  bool Lookup(uint64_t device, uint64_t inode, FileOwner* owner);
  bool Identify(const std::string& path, FileOwner* owner, bool follow = false);
  bool Set(const FileOwner& owner, bool durable = true,
      const FileOwner* previous = nullptr);
  bool SetPath(
      const std::string& path, uint32_t uid, uint32_t gid, mode_t mode);
  bool               Create(const std::string& path, const FileOwner& owner,
      const std::string& target = {});
  bool               Checkpoint();
  bool               RegisterProcess(const ProcessOwner& process);
  bool               Process(pid_t pid, ProcessOwner* process);
  void               ForgetProcess(pid_t pid);
  const std::string& root() const {
    return root_;
  }

 private:
  struct Shared;
  std::unordered_map<size_t, int> terminal_pins_;
  int                             journal_fd_   = -1;
  int                             lock_fd_      = -1;
  Shared*                         shared_       = nullptr;
  int                             lease_fd_     = -1;
  int                             memory_fd_    = -1;
  int                             directory_fd_ = -1;
  std::string                     root_;
  std::string                     directory_;
  bool SetLocked(const FileOwner& owner, bool durable,
      const FileOwner* previous = nullptr);
  bool Lock();
  void Unlock();
  bool Replay();
  bool CheckpointLocked();
  bool Put(const FileOwner& owner);
  bool Scan();
};
}  // namespace andlify
