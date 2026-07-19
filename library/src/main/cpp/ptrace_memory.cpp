#include "ptrace_memory.h"

#include <errno.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/uio.h>

#include <algorithm>
#include <vector>

namespace {

bool ReadTraceeMemoryProcessVm(
    pid_t pid, uint64_t remote_address, void* out, size_t len) {
  iovec         local_iov{out, len};
  iovec         remote_iov{reinterpret_cast<void*>(remote_address), len};
  const ssize_t copied =
      process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
  return copied == static_cast<ssize_t>(len);
}

bool WriteTraceeMemoryProcessVm(
    pid_t pid, uint64_t remote_address, const void* data, size_t len) {
  iovec         local_iov{const_cast<void*>(data), len};
  iovec         remote_iov{reinterpret_cast<void*>(remote_address), len};
  const ssize_t copied =
      process_vm_writev(pid, &local_iov, 1, &remote_iov, 1, 0);
  return copied == static_cast<ssize_t>(len);
}

bool ReadTraceeCStringPtrace(
    pid_t pid, uint64_t remote_address, size_t max_len, std::string* out) {
  out->clear();
  out->reserve(max_len);
  size_t copied = 0;
  while (copied < max_len) {
    errno = 0;
    const long word =
        ptrace(PTRACE_PEEKDATA, pid, remote_address + copied, nullptr);
    if (errno != 0) {
      return false;
    }
    for (size_t i = 0; i < sizeof(long) && copied < max_len; ++i, ++copied) {
      const char ch = static_cast<char>(
          (static_cast<unsigned long>(word) >> (i * 8U)) & 0xFFU);
      if (ch == '\0') {
        return true;
      }
      out->push_back(ch);
    }
  }
  return false;
}

bool WriteTraceeMemoryPtrace(
    pid_t pid, uint64_t remote_address, const void* data, size_t len) {
  const auto* bytes  = static_cast<const uint8_t*>(data);
  size_t      offset = 0;
  while (offset < len) {
    long         word  = 0;
    const size_t chunk = std::min(sizeof(long), len - offset);
    if (chunk != sizeof(long)) {
      errno = 0;
      word  = ptrace(PTRACE_PEEKDATA, pid, remote_address + offset, nullptr);
      if (errno != 0) {
        return false;
      }
    }

    memcpy(reinterpret_cast<uint8_t*>(&word), bytes + offset, chunk);
    if (ptrace(PTRACE_POKEDATA, pid, remote_address + offset, word) == -1) {
      return false;
    }
    offset += chunk;
  }
  return true;
}

}  // namespace

bool ReadTraceeCString(
    pid_t pid, uint64_t remote_address, size_t max_len, std::string* out) {
  if (out == nullptr || remote_address == 0 || max_len == 0) {
    return false;
  }

  std::vector<char> buffer(max_len, '\0');
  if (ReadTraceeMemoryProcessVm(
          pid, remote_address, buffer.data(), buffer.size())) {
    const char* terminator =
        static_cast<const char*>(memchr(buffer.data(), '\0', buffer.size()));
    if (terminator == nullptr) {
      return false;
    }
    out->assign(buffer.data(), static_cast<size_t>(terminator - buffer.data()));
    return true;
  }

  return ReadTraceeCStringPtrace(pid, remote_address, max_len, out);
}

bool ReadTraceeMemory(
    pid_t pid, uint64_t remote_address, void* out, size_t len) {
  if (remote_address == 0 || out == nullptr || len == 0) {
    return false;
  }

  if (ReadTraceeMemoryProcessVm(pid, remote_address, out, len)) {
    return true;
  }

  auto*  bytes  = static_cast<uint8_t*>(out);
  size_t copied = 0;
  while (copied < len) {
    errno = 0;
    const long word =
        ptrace(PTRACE_PEEKDATA, pid, remote_address + copied, nullptr);
    if (errno != 0) {
      return false;
    }

    const size_t chunk = std::min(sizeof(long), len - copied);
    memcpy(bytes + copied, &word, chunk);
    copied += chunk;
  }
  return true;
}

bool WriteTraceeMemory(
    pid_t pid, uint64_t remote_address, const void* data, size_t len) {
  if (remote_address == 0 || data == nullptr || len == 0) {
    return false;
  }

  if (WriteTraceeMemoryProcessVm(pid, remote_address, data, len)) {
    return true;
  }

  return WriteTraceeMemoryPtrace(pid, remote_address, data, len);
}
