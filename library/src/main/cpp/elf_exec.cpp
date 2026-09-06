#include "elf_exec.h"

#include <asm/ptrace.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <limits>

#include "ptrace_memory.h"

namespace {

uint64_t PageUp(uint64_t value, uint64_t page_size) {
  return (value + page_size - 1) & ~(page_size - 1);
}

struct RemoteSyscalls {
  pid_t        pid;
  user_pt_regs original{};
  uint64_t     pc          = 0;
  uint64_t     sp          = 0;
  long         instruction = 0;
  bool         installed   = false;

  bool Install() {
    iovec io{&original, sizeof(original)};
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &io) != 0) {
      return false;
    }
    pc                  = original.pc;
    sp                  = original.sp;
    constexpr long code = 0xd4200000d4000001UL;
    errno               = 0;
    instruction         = ptrace(PTRACE_PEEKTEXT, pid, pc, nullptr);
    if (errno != 0) {
      return false;
    }
    // process_vm_writev does not synchronize the AArch64 instruction cache.
    installed = ptrace(PTRACE_POKETEXT, pid, pc, code) == 0;
    return installed;
  }

  int64_t Call(long number, std::array<uint64_t, 6> args = {}) {
    auto regs = original;
    std::copy(args.begin(), args.end(), regs.regs);
    regs.regs[8] = number;
    iovec io{&regs, sizeof(regs)};
    if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &io) != 0 ||
        ptrace(PTRACE_CONT, pid, nullptr, nullptr) != 0) {
      return -errno;
    }
    for (;;) {
      int   status = 0;
      pid_t waited;
      do {
        waited = waitpid(pid, &status, __WALL);
      } while (waited < 0 && errno == EINTR);
      if (waited < 0 || !WIFSTOPPED(status)) {
        return waited < 0 ? -errno : -ESRCH;
      }
      if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &io) != 0) {
        return -errno;
      }
      const bool    finished = regs.pc == pc + 4;
      const int64_t result   = regs.regs[0];
      if (WSTOPSIG(status) == SIGTRAP && finished) {
        return result;
      }
      if (WSTOPSIG(status) == SIGSYS || WSTOPSIG(status) == SIGSEGV ||
          WSTOPSIG(status) == SIGBUS || WSTOPSIG(status) == SIGILL) {
        return -ENOEXEC;
      }
      const int signal = WSTOPSIG(status) == SIGSTOP ? 0 : WSTOPSIG(status);
      if (ptrace(PTRACE_CONT, pid, nullptr, signal) != 0) {
        return -errno;
      }
    }
  }

  bool Restore(uint64_t stack) {
    if (!installed) {
      return false;
    }
    installed = false;
    if (ptrace(PTRACE_POKETEXT, pid, pc, instruction) != 0) {
      return false;
    }
    original.sp = stack;
    iovec io{&original, sizeof(original)};
    return ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &io) == 0;
  }

  ~RemoteSyscalls() {
    if (installed) {
      Restore(sp);
    }
  }
};

int MapExecutable(RemoteSyscalls& remote, const ElfExecutable& executable,
    uint64_t* load_bias) {
  const uint64_t    page_size = sysconf(_SC_PAGESIZE);
  const std::string fd_path   = "/proc/" + std::to_string(getpid()) + "/fd/" +
                                std::to_string(executable.fd);
  const uint64_t    scratch   = remote.sp - 512;
  if (!WriteTraceeMemory(
          remote.pid, scratch, fd_path.c_str(), fd_path.size() + 1)) {
    return -EFAULT;
  }
  const int64_t fd = remote.Call(SYS_openat,
      {static_cast<uint64_t>(AT_FDCWD), scratch, O_RDONLY | O_CLOEXEC});
  if (fd < 0) {
    return fd;
  }
  const uint64_t size         = executable.end_page - executable.first_page;
  const bool     pie          = executable.header.e_type == ET_DYN;
  const uint64_t reserve_size = size + (pie ? executable.alignment : 0);
  const int64_t  mapping      = remote.Call(
      SYS_mmap, {pie ? 0 : executable.first_page, reserve_size, PROT_NONE,
                    MAP_PRIVATE | MAP_ANONYMOUS, static_cast<uint64_t>(-1), 0});
  int error = 0;
  if (mapping < 0) {
    error = mapping;
  } else if (!pie && static_cast<uint64_t>(mapping) != executable.first_page) {
    remote.Call(SYS_munmap, {static_cast<uint64_t>(mapping), reserve_size});
    error = -EEXIST;
  }
  if (error != 0) {
    remote.Call(SYS_close, {static_cast<uint64_t>(fd)});
    return error;
  }
  const uint64_t base =
      pie ? PageUp(mapping - executable.first_page, executable.alignment) +
                executable.first_page :
            mapping;
  *load_bias = base - executable.first_page;
  if (base != static_cast<uint64_t>(mapping)) {
    remote.Call(SYS_munmap, {static_cast<uint64_t>(mapping), base - mapping});
  }
  const uint64_t reserved_end = mapping + reserve_size;
  if (base + size < reserved_end) {
    remote.Call(SYS_munmap, {base + size, reserved_end - base - size});
  }

  for (const auto& segment : executable.segments) {
    if (segment.p_type != PT_LOAD || segment.p_memsz == 0) {
      continue;
    }
    const uint64_t address  = *load_bias + segment.p_vaddr;
    const uint64_t start    = address & ~(page_size - 1);
    const uint64_t file_end = address + segment.p_filesz;
    const uint64_t end      = PageUp(address + segment.p_memsz, page_size);
    const int      prot     = ((segment.p_flags & PF_R) ? PROT_READ : 0) |
                              ((segment.p_flags & PF_W) ? PROT_WRITE : 0) |
                              ((segment.p_flags & PF_X) ? PROT_EXEC : 0);
    const uint64_t anonymous_start =
        segment.p_filesz == 0 ? start : PageUp(file_end, page_size);
    if (segment.p_filesz != 0) {
      const int64_t result = remote.Call(SYS_mmap,
          {start, PageUp(file_end, page_size) - start,
              static_cast<uint64_t>(prot), MAP_PRIVATE | MAP_FIXED,
              static_cast<uint64_t>(fd), segment.p_offset & ~(page_size - 1)});
      if (result < 0) {
        error = result;
        break;
      }
    }
    if (anonymous_start < end) {
      const int64_t result = remote.Call(SYS_mmap,
          {anonymous_start, end - anonymous_start, static_cast<uint64_t>(prot),
              MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
              static_cast<uint64_t>(-1), 0});
      if (result < 0) {
        error = result;
        break;
      }
    }
    if (segment.p_memsz > segment.p_filesz && segment.p_filesz != 0 &&
        file_end < anonymous_start) {
      std::vector<char> zero(anonymous_start - file_end, 0);
      if (!WriteTraceeMemory(remote.pid, file_end, zero.data(), zero.size())) {
        error = -EFAULT;
        break;
      }
    }
  }
  const int64_t closed = remote.Call(SYS_close, {static_cast<uint64_t>(fd)});
  return error != 0 ? error : (closed < 0 ? closed : 0);
}

}  // namespace

ElfExecutable::~ElfExecutable() {
  if (fd >= 0) {
    close(fd);
  }
}

std::shared_ptr<ElfExecutable> OpenElfExecutable(const std::string& path) {
  auto executable = std::make_shared<ElfExecutable>();
  executable->fd  = open(path.c_str(), O_RDONLY | O_CLOEXEC);
  if (executable->fd < 0) {
    return nullptr;
  }
  struct stat info{};
  if (fstat(executable->fd, &info) != 0) {
    return nullptr;
  }
  if (!S_ISREG(info.st_mode) || (info.st_mode & 0111) == 0) {
    errno = EACCES;
    return nullptr;
  }
  auto&          header    = executable->header;
  const ssize_t  bytes     = pread(executable->fd, &header, sizeof(header), 0);
  const uint64_t page_size = sysconf(_SC_PAGESIZE);
  constexpr int  machine   = EM_AARCH64;
  if (bytes != sizeof(header) || memcmp(header.e_ident, ELFMAG, SELFMAG) != 0 ||
      header.e_ident[EI_CLASS] != ELFCLASS64 ||
      header.e_ident[EI_DATA] != ELFDATA2LSB ||
      header.e_ident[EI_VERSION] != EV_CURRENT ||
      header.e_version != EV_CURRENT || header.e_machine != machine ||
      (header.e_type != ET_EXEC && header.e_type != ET_DYN) ||
      header.e_phentsize != sizeof(Elf64_Phdr) || header.e_phnum == 0 ||
      header.e_phnum > 65536 / sizeof(Elf64_Phdr) ||
      header.e_phoff > static_cast<uint64_t>(info.st_size) ||
      header.e_phnum * sizeof(Elf64_Phdr) >
          static_cast<uint64_t>(info.st_size) - header.e_phoff) {
    errno = ENOEXEC;
    return nullptr;
  }
  executable->segments.resize(header.e_phnum);
  const size_t table_size = header.e_phnum * sizeof(Elf64_Phdr);
  if (pread(executable->fd, executable->segments.data(), table_size,
          header.e_phoff) != static_cast<ssize_t>(table_size)) {
    errno = ENOEXEC;
    return nullptr;
  }
  executable->first_page = UINT64_MAX;
  executable->alignment  = page_size;
  bool entry_mapped      = false;
  bool phdr_mapped       = false;
  for (const auto& segment : executable->segments) {
    if (segment.p_type == PT_INTERP) {
      if (!executable->interpreter.empty() || segment.p_filesz < 2 ||
          segment.p_filesz > 4096 ||
          segment.p_offset > static_cast<uint64_t>(info.st_size) ||
          segment.p_filesz >
              static_cast<uint64_t>(info.st_size) - segment.p_offset) {
        errno = ENOEXEC;
        return nullptr;
      }
      std::vector<char> path_buffer(segment.p_filesz);
      if (pread(executable->fd, path_buffer.data(), path_buffer.size(),
              segment.p_offset) != static_cast<ssize_t>(path_buffer.size()) ||
          path_buffer.back() != '\0') {
        errno = ENOEXEC;
        return nullptr;
      }
      executable->interpreter = path_buffer.data();
    }
    if (segment.p_type != PT_LOAD || segment.p_memsz == 0) {
      continue;
    }
    if (segment.p_filesz > segment.p_memsz ||
        segment.p_vaddr > INT64_MAX - page_size ||
        segment.p_memsz > INT64_MAX - page_size - segment.p_vaddr ||
        segment.p_offset > static_cast<uint64_t>(info.st_size) ||
        segment.p_filesz >
            static_cast<uint64_t>(info.st_size) - segment.p_offset ||
        (segment.p_vaddr % page_size) != (segment.p_offset % page_size) ||
        (segment.p_align > 1 &&
            ((segment.p_align & (segment.p_align - 1)) != 0 ||
                segment.p_align > (1ULL << 32) ||
                segment.p_vaddr % segment.p_align !=
                    segment.p_offset % segment.p_align))) {
      errno = ENOEXEC;
      return nullptr;
    }
    executable->first_page = std::min<uint64_t>(
        executable->first_page, segment.p_vaddr & ~(page_size - 1));
    executable->end_page = std::max(executable->end_page,
        PageUp(segment.p_vaddr + segment.p_memsz, page_size));
    executable->alignment =
        std::max<uint64_t>(executable->alignment, segment.p_align);
    if ((segment.p_flags & PF_X) && header.e_entry >= segment.p_vaddr &&
        header.e_entry - segment.p_vaddr < segment.p_memsz) {
      entry_mapped = true;
    }
    if (header.e_phoff >= segment.p_offset &&
        header.e_phoff - segment.p_offset <= segment.p_filesz &&
        table_size <= segment.p_filesz - (header.e_phoff - segment.p_offset)) {
      executable->phdr_address =
          segment.p_vaddr + header.e_phoff - segment.p_offset;
      phdr_mapped = true;
    }
  }
  if (!entry_mapped || !phdr_mapped ||
      executable->first_page >= executable->end_page) {
    errno = ENOEXEC;
    return nullptr;
  }
  return executable;
}

int InitializeElfExecutable(pid_t pid, const ElfExecutable& executable,
    const ElfExecutable* interpreter, const std::string& execfn,
    const std::string& comm, std::vector<Elf64_auxv_t>* auxiliary_vector) {
  RemoteSyscalls remote{pid};
  if (!remote.Install()) {
    return -errno;
  }
  uint64_t argc = 0;
  if (!ReadTraceeMemory(pid, remote.sp, &argc, sizeof(argc)) ||
      argc > 1 << 20) {
    return -E2BIG;
  }
  uint64_t cursor = remote.sp + (argc + 2) * sizeof(uint64_t);
  for (size_t count = 0;; ++count, cursor += sizeof(uint64_t)) {
    uint64_t pointer = 0;
    if (count > 1 << 20 ||
        !ReadTraceeMemory(pid, cursor, &pointer, sizeof(pointer))) {
      return -EFAULT;
    }
    if (pointer == 0) {
      cursor += sizeof(uint64_t);
      break;
    }
  }
  const uint64_t auxv_address = cursor;
  auxiliary_vector->clear();
  for (size_t count = 0;; ++count, cursor += sizeof(Elf64_auxv_t)) {
    Elf64_auxv_t entry{};
    if (count > 128 || !ReadTraceeMemory(pid, cursor, &entry, sizeof(entry))) {
      return -EFAULT;
    }
    auxiliary_vector->push_back(entry);
    if (entry.a_type == AT_NULL) {
      cursor += sizeof(entry);
      break;
    }
  }
  uint64_t bias             = 0;
  uint64_t interpreter_bias = 0;
  if (interpreter != nullptr) {
    interpreter_bias = remote.pc - interpreter->header.e_entry;
    const int error  = MapExecutable(remote, executable, &bias);
    if (error != 0) {
      return error;
    }
  }

  const uint64_t    new_sp         = remote.sp - PageUp(execfn.size() + 1, 16);
  const uint64_t    execfn_address = new_sp + cursor - remote.sp;
  std::vector<char> stack(cursor - remote.sp);
  if (!ReadTraceeMemory(pid, remote.sp, stack.data(), stack.size())) {
    return -EFAULT;
  }
  for (auto& entry : *auxiliary_vector) {
    switch (entry.a_type) {
      case AT_PHDR:
        if (interpreter != nullptr)
          entry.a_un.a_val = bias + executable.phdr_address;
        break;
      case AT_PHENT:
        entry.a_un.a_val = sizeof(Elf64_Phdr);
        break;
      case AT_PHNUM:
        entry.a_un.a_val = executable.header.e_phnum;
        break;
      case AT_ENTRY:
        if (interpreter != nullptr)
          entry.a_un.a_val = bias + executable.header.e_entry;
        break;
      case AT_BASE:
        if (interpreter != nullptr)
          entry.a_un.a_val = interpreter_bias;
        break;
      case AT_EXECFN:
        entry.a_un.a_val = execfn_address;
        break;
    }
  }
  memcpy(stack.data() + auxv_address - remote.sp, auxiliary_vector->data(),
      auxiliary_vector->size() * sizeof(Elf64_auxv_t));
  if (!WriteTraceeMemory(pid, new_sp, stack.data(), stack.size()) ||
      !WriteTraceeMemory(
          pid, execfn_address, execfn.c_str(), execfn.size() + 1)) {
    return -EFAULT;
  }
  const uint64_t    name_address = new_sp - 32;
  const std::string name =
      comm.substr(comm.find_last_of('/') + 1).substr(0, 15);
  if (!WriteTraceeMemory(pid, name_address, name.c_str(), name.size() + 1)) {
    return -EFAULT;
  }
  const int64_t result = remote.Call(SYS_prctl, {PR_SET_NAME, name_address});
  if (result < 0) {
    return result;
  }
  if (interpreter != nullptr) {
    for (const auto& segment : executable.segments) {
      if (segment.p_type == PT_GNU_STACK && (segment.p_flags & PF_X)) {
        const uint64_t page   = sysconf(_SC_PAGESIZE);
        const uint64_t start  = new_sp & ~(page - 1);
        const int64_t  result = remote.Call(SYS_mprotect,
            {start, PageUp(execfn_address + execfn.size() + 1, page) - start,
                PROT_READ | PROT_WRITE | PROT_EXEC | PROT_GROWSDOWN});
        if (result < 0)
          return result;
      }
    }
  }
  return remote.Restore(new_sp) ? 0 : -errno;
}
