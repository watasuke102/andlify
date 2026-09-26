#include <fcntl.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstring>

#include "ownership_store_internal.h"

namespace andlify {
using namespace ownership_detail;
namespace {
constexpr size_t   kRecordSize         = 64;
constexpr uint64_t kCheckpointInterval = 16384;
using Record                           = std::array<uint8_t, kRecordSize>;
void Encode(uint8_t* data, uint64_t value, size_t size) {
  for (size_t i = 0; i < size; ++i) data[i] = value >> (8 * i);
}
uint64_t Decode(const uint8_t* data, size_t size) {
  uint64_t result = 0;
  for (size_t i = 0; i < size; ++i) result |= uint64_t(data[i]) << (8 * i);
  return result;
}
uint32_t Checksum(const uint8_t* data, size_t size) {
  uint32_t value = 2166136261U;
  for (size_t i = 0; i < size; ++i) value = (value ^ data[i]) * 16777619U;
  return value;
}
bool WriteAll(int fd, const void* data, size_t size) {
  const auto* bytes = static_cast<const uint8_t*>(data);
  while (size) {
    const ssize_t n = write(fd, bytes, size);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
      return false;
    bytes += n;
    size -= n;
  }
  return true;
}
Record Pack(const FileOwner& owner, uint64_t sequence) {
  Record r{};
  Encode(r.data(), kMagic, 8);
  Encode(r.data() + 8, sequence, 8);
  Encode(r.data() + 16, owner.device, 8);
  Encode(r.data() + 24, owner.inode, 8);
  Encode(r.data() + 32, owner.birth_seconds, 8);
  Encode(r.data() + 40, owner.birth_nanoseconds, 4);
  Encode(r.data() + 44, owner.uid, 4);
  Encode(r.data() + 48, owner.gid, 4);
  Encode(r.data() + 52, owner.mode, 4);
  Encode(r.data() + 60, Checksum(r.data(), 60), 4);
  return r;
}
FileOwner Unpack(const Record& r) {
  return {Decode(r.data() + 16, 8), Decode(r.data() + 24, 8),
      Decode(r.data() + 32, 8), uint32_t(Decode(r.data() + 40, 4)),
      uint32_t(Decode(r.data() + 44, 4)), uint32_t(Decode(r.data() + 48, 4)),
      uint32_t(Decode(r.data() + 52, 4))};
}
}  // namespace

bool OwnershipStore::Set(
    const FileOwner& owner, bool durable, const FileOwner* previous) {
  if (!Lock())
    return false;
  bool ok = SetLocked(owner, durable, previous);
  Unlock();
  return ok;
}
bool OwnershipStore::SetLocked(
    const FileOwner& owner, bool durable, const FileOwner* previous) {
  bool   same      = false;
  size_t index     = Hash(owner.device, owner.inode);
  bool   available = false;
  for (size_t n = 0; n < kSlots; ++n, index = (index + 1) & (kSlots - 1)) {
    const auto& slot = shared_->files[index];
    if (!slot.inode ||
        (slot.device == owner.device && slot.inode == owner.inode)) {
      if (previous &&
          (!SameBirth(slot, *previous) || slot.uid != previous->uid ||
              slot.gid != previous->gid || slot.mode != previous->mode)) {
        errno = EAGAIN;
        return false;
      }
      available = true;
      same = slot.inode && SameBirth(slot, owner) && slot.uid == owner.uid &&
             slot.gid == owner.gid && slot.mode == owner.mode;
      break;
    }
  }
  if (same) {
    return true;
  }
  if (!available) {
    errno = ENOSPC;
    return false;
  }
  shared_->dirty = true;
  if (journal_fd_ < 0)
    journal_fd_ = openat(directory_fd_, "journal",
        O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
  const auto record = Pack(owner, shared_->sequence + 1);
  bool       ok     = journal_fd_ >= 0 &&
                      WriteAll(journal_fd_, record.data(), record.size()) &&
                      (!durable || fdatasync(journal_fd_) == 0);
  if (ok) {
    ++shared_->sequence;
    ok = Put(owner);
  }
  if (ok)
    shared_->dirty = false;
  if (ok && shared_->sequence - shared_->checkpoint >= kCheckpointInterval)
    ok = CheckpointLocked();
  return ok;
}

bool OwnershipStore::Replay() {
  const auto version = __atomic_load_n(&shared_->version, __ATOMIC_ACQUIRE);
  __atomic_store_n(&shared_->version, version | 1, __ATOMIC_RELEASE);
  __atomic_thread_fence(__ATOMIC_SEQ_CST);
  for (auto& owner : shared_->files) WriteOwner(owner, {});
  shared_->sequence = shared_->checkpoint = 0;
  for (const char* name : {"snapshot", "journal"}) {
    const bool snapshot = strcmp(name, "snapshot") == 0;
    int fd = openat(directory_fd_, name, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
      if (errno == ENOENT)
        continue;
      return false;
    }
    struct stat st{};
    bool        ok     = fstat(fd, &st) == 0;
    off_t       offset = 0;
    while (ok && offset < st.st_size) {
      Record  r{};
      ssize_t n;
      do {
        n = pread(fd, r.data(), r.size(), offset);
      } while (n < 0 && errno == EINTR);
      if (n != ssize_t(r.size())) {
        if (!snapshot && n >= 0 && offset + n == st.st_size)
          ok = ftruncate(fd, offset) == 0;
        else
          ok = false;
        break;
      }
      if (Decode(r.data(), 8) != kMagic ||
          Decode(r.data() + 60, 4) != Checksum(r.data(), 60)) {
        ok = false;
        break;
      }
      const uint64_t sequence = Decode(r.data() + 8, 8);
      FileOwner      owner    = Unpack(r);
      if (snapshot) {
        if (offset == 0) {
          if (owner.inode != 0) {
            ok = false;
            break;
          }
          shared_->sequence = shared_->checkpoint = sequence;
        } else {
          ok = sequence == shared_->checkpoint && Put(owner);
        }
      } else if (sequence > shared_->checkpoint) {
        ok = sequence == shared_->sequence + 1 && Put(owner);
        if (ok)
          shared_->sequence = sequence;
      }
      offset += r.size();
    }
    if (snapshot && st.st_size == 0)
      ok = false;
    close(fd);
    if (!ok) {
      errno = EIO;
      return false;
    }
  }
  shared_->dirty = false;
  __atomic_store_n(&shared_->version, (version | 1) + 1, __ATOMIC_RELEASE);
  return true;
}
bool OwnershipStore::CheckpointLocked() {
  int fd = openat(directory_fd_, "snapshot.tmp",
      O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (fd < 0)
    return false;
  std::array<uint8_t, 65536> buffer;
  size_t                     used   = 0;
  const auto                 append = [&](const Record& record) {
    if (used + record.size() > buffer.size()) {
      if (!WriteAll(fd, buffer.data(), used))
        return false;
      used = 0;
    }
    memcpy(buffer.data() + used, record.data(), record.size());
    used += record.size();
    return true;
  };
  bool ok = append(Pack({}, shared_->sequence));
  for (const auto& owner : shared_->files) {
    if (!ok)
      break;
    if (owner.inode)
      ok = append(Pack(owner, shared_->sequence));
  }
  ok = ok && WriteAll(fd, buffer.data(), used);
  ok = ok && fsync(fd) == 0;
  close(fd);
  ok =
      ok &&
      renameat(directory_fd_, "snapshot.tmp", directory_fd_, "snapshot") == 0 &&
      fsync(directory_fd_) == 0;
  if (!ok)
    return false;
  shared_->checkpoint = shared_->sequence;
  fd                  = openat(directory_fd_, "journal",
      O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
  ok                  = fd >= 0 && fsync(fd) == 0 && fsync(directory_fd_) == 0;
  if (fd >= 0)
    close(fd);
  return ok;
}
bool OwnershipStore::Checkpoint() {
  if (!Lock())
    return false;
  const bool ok = CheckpointLocked();
  Unlock();
  return ok;
}
}  // namespace andlify
