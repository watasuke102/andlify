#pragma once

#include <functional>
#include <string>
#include <vector>

#include "ownership/ownership_store.h"

namespace andlify {
struct FileCredentials {
  uint32_t                     uid;
  uint32_t                     gid;
  const std::vector<uint32_t>& groups;
  uint32_t                     mask;
};
struct PendingFile {
  std::string path;
  FileOwner   owner;
  bool        creation         = false;
  bool        open             = false;
  uint64_t    open_how_address = 0;
  uint64_t    open_how_flags   = 0;
};
using ResolveFile = std::function<bool(int, int, bool, std::string*)>;
bool PrepareFileOperation(pid_t pid, uint64_t syscall, uint64_t* args,
    const FileCredentials& credentials, OwnershipStore& store,
    const ResolveFile& resolve, PendingFile* pending, int64_t* result);
bool FinishFileOperation(pid_t pid, int64_t result, OwnershipStore& store,
    const FileCredentials& credentials, PendingFile* pending);
int  CheckFileAccess(OwnershipStore& store, const std::string& path,
    const FileCredentials& credentials, int mask);
}  // namespace andlify
