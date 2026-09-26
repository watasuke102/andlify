#pragma once

#include "ownership_store.h"

namespace andlify {
namespace ownership_detail {
constexpr size_t   kSlots     = 1 << 19;
constexpr size_t   kProcesses = 16384;
constexpr uint64_t kMagic     = 0x314154454d444e41ULL;
inline size_t      Hash(uint64_t device, uint64_t inode) {
  uint64_t value = inode ^ (device * 0x9e3779b97f4a7c15ULL);
  value ^= value >> 30;
  value *= 0xbf58476d1ce4e5b9ULL;
  value ^= value >> 27;
  return value & (kSlots - 1);
}
inline FileOwner ReadOwner(const FileOwner& slot) {
  return {__atomic_load_n(&slot.device, __ATOMIC_RELAXED),
      __atomic_load_n(&slot.inode, __ATOMIC_RELAXED),
      __atomic_load_n(&slot.birth_seconds, __ATOMIC_RELAXED),
      __atomic_load_n(&slot.birth_nanoseconds, __ATOMIC_RELAXED),
      __atomic_load_n(&slot.uid, __ATOMIC_RELAXED),
      __atomic_load_n(&slot.gid, __ATOMIC_RELAXED),
      __atomic_load_n(&slot.mode, __ATOMIC_RELAXED)};
}
inline void WriteOwner(FileOwner& slot, const FileOwner& owner) {
  __atomic_store_n(&slot.device, owner.device, __ATOMIC_RELAXED);
  __atomic_store_n(&slot.inode, owner.inode, __ATOMIC_RELAXED);
  __atomic_store_n(&slot.birth_seconds, owner.birth_seconds, __ATOMIC_RELAXED);
  __atomic_store_n(
      &slot.birth_nanoseconds, owner.birth_nanoseconds, __ATOMIC_RELAXED);
  __atomic_store_n(&slot.uid, owner.uid, __ATOMIC_RELAXED);
  __atomic_store_n(&slot.gid, owner.gid, __ATOMIC_RELAXED);
  __atomic_store_n(&slot.mode, owner.mode, __ATOMIC_RELAXED);
}
inline bool SameBirth(const FileOwner& a, const FileOwner& b) {
  return a.birth_seconds == b.birth_seconds &&
         a.birth_nanoseconds == b.birth_nanoseconds;
}
}  // namespace ownership_detail

struct OwnershipStore::Shared {
  uint64_t     magic;
  uint64_t     version;
  uint64_t     sequence;
  uint64_t     checkpoint;
  bool         dirty;
  uint32_t     failed;
  FileOwner    files[ownership_detail::kSlots];
  ProcessOwner processes[ownership_detail::kProcesses];
};

}  // namespace andlify
