#include "ptrace_engine.h"

#include "path_rewrite.h"
#include "ptrace_memory.h"

#include <android/log.h>
#include <asm/ptrace.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/ptrace.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace {

constexpr const char* kLogTag = "andlify-ptrace";
constexpr uint64_t kSysOpenat = 56;
constexpr uint64_t kSysChdir = 49;
constexpr uint64_t kSysFaccessat = 48;
constexpr uint64_t kSysNewfstatat = 79;
constexpr uint64_t kSysReadlinkat = 78;
constexpr uint64_t kSysFaccessat2 = 439;
constexpr uint64_t kSysOpenat2 = 437;
constexpr uint64_t kSysStatx = 291;
constexpr uint64_t kSysExecve = 221;
constexpr uint64_t kSysCapset = 91;
constexpr uint64_t kSysSocket = 198;
constexpr uint64_t kSysBind = 200;
constexpr uint64_t kSysConnect = 203;
constexpr uint64_t kSysSendto = 206;
constexpr uint64_t kSysSetgid = 144;
constexpr uint64_t kSysSetuid = 146;
constexpr uint64_t kSysSetresuid = 147;
constexpr uint64_t kSysGetresuid = 148;
constexpr uint64_t kSysSetresgid = 149;
constexpr uint64_t kSysGetresgid = 150;
constexpr uint64_t kSysGetgroups = 158;
constexpr uint64_t kSysSetgroups = 159;
constexpr uint64_t kSysGetuid = 174;
constexpr uint64_t kSysGeteuid = 175;
constexpr uint64_t kSysGetgid = 176;
constexpr uint64_t kSysGetegid = 177;
constexpr uint64_t kSysIoctl = 29;
constexpr uint64_t kTcgets = 0x5401;
constexpr uint64_t kTiocgpgrp = 0x540F;
constexpr uint64_t kTiocspgrp = 0x5410;
constexpr uint64_t kTiocgwinsz = 0x5413;
constexpr size_t kPathReadLimit = 4096;
constexpr uint64_t kStackScratchOffset = 0x800;
constexpr uint64_t kExecScratchSize = 0x2000;
constexpr size_t kMaxExecArgCount = 64;
constexpr uint64_t kSkippedSyscall = static_cast<uint64_t>(-1);
constexpr uint64_t kRootUid = 0;
constexpr uint64_t kRootGid = 0;
constexpr uint64_t kAfUnix = 1;
constexpr uint64_t kAfInet = 2;
constexpr uint64_t kAfInet6 = 10;
constexpr uint64_t kSockDgram = 2;
constexpr uint64_t kSockRaw = 3;
constexpr uint64_t kSockTypeMask = 0xf;
constexpr uint64_t kIpProtoIcmp = 1;
constexpr uint64_t kIpProtoIcmpv6 = 58;

struct TraceeState {
    bool expect_entry = true;
    bool options_applied = false;
    bool has_emulated_return = false;
    uint64_t emulated_return = 0;
};

struct ExecPlan {
    std::string executable_path;
    std::vector<std::string> args;
};

enum class ExecRewriteResult {
    kNotApplicable,
    kApplied,
    kFailed,
};

bool GetRegs(pid_t pid, user_pt_regs* regs) {
    iovec io{regs, sizeof(*regs)};
    return ptrace(PTRACE_GETREGSET, pid, reinterpret_cast<void*>(NT_PRSTATUS), &io) == 0;
}

bool SetRegs(pid_t pid, const user_pt_regs& regs) {
    iovec io{const_cast<user_pt_regs*>(&regs), sizeof(regs)};
    return ptrace(PTRACE_SETREGSET, pid, reinterpret_cast<void*>(NT_PRSTATUS), &io) == 0;
}

bool ApplyTraceOptions(pid_t pid) {
    const long options = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE |
                         PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL;
    return ptrace(PTRACE_SETOPTIONS, pid, nullptr, options) == 0;
}

bool ReadFullyAt(int fd, off_t offset, void* out, size_t len) {
    auto* bytes = static_cast<uint8_t*>(out);
    size_t copied = 0;
    while (copied < len) {
        const ssize_t n = pread(fd, bytes + copied, len - copied, offset + static_cast<off_t>(copied));
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (n == 0) {
            return false;
        }
        copied += static_cast<size_t>(n);
    }
    return true;
}

uint64_t AlignUp(uint64_t value, uint64_t alignment) {
    return (value + alignment - 1U) & ~(alignment - 1U);
}

bool ReadElfInterpreter(const std::string& executable_path, std::string* interpreter_path) {
    if (interpreter_path == nullptr) {
        return false;
    }
    interpreter_path->clear();

    const int fd = open(executable_path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        __android_log_print(
            ANDROID_LOG_WARN,
            kLogTag,
            "Failed to open command for ELF inspection: %s (%s)",
            executable_path.c_str(),
            strerror(errno));
        return false;
    }

    Elf64_Ehdr header {};
    if (!ReadFullyAt(fd, 0, &header, sizeof(header))) {
        close(fd);
        return false;
    }
    if (memcmp(header.e_ident, ELFMAG, SELFMAG) != 0 || header.e_ident[EI_CLASS] != ELFCLASS64 ||
        header.e_phoff == 0 || header.e_phentsize != sizeof(Elf64_Phdr)) {
        close(fd);
        return false;
    }

    for (uint16_t i = 0; i < header.e_phnum; ++i) {
        Elf64_Phdr phdr {};
        const off_t phdr_offset = static_cast<off_t>(header.e_phoff + static_cast<Elf64_Off>(i) * header.e_phentsize);
        if (!ReadFullyAt(fd, phdr_offset, &phdr, sizeof(phdr))) {
            close(fd);
            return false;
        }
        if (phdr.p_type != PT_INTERP || phdr.p_filesz == 0) {
            continue;
        }

        std::vector<char> buffer(static_cast<size_t>(phdr.p_filesz), '\0');
        if (!ReadFullyAt(fd, static_cast<off_t>(phdr.p_offset), buffer.data(), buffer.size())) {
            close(fd);
            return false;
        }
        close(fd);
        interpreter_path->assign(buffer.data(), strnlen(buffer.data(), buffer.size()));
        return !interpreter_path->empty();
    }

    close(fd);
    return false;
}

ExecPlan BuildExecPlan(const std::string& extract_dst_path, const std::string& command_path_in_rootfs) {
    const std::string real_exec_path = BuildRealPathInRootfs(extract_dst_path, command_path_in_rootfs);
    ExecPlan plan {real_exec_path, {command_path_in_rootfs.empty() ? std::string("/bin/sh") : command_path_in_rootfs}};
    if (real_exec_path.empty()) {
        return plan;
    }

    std::string interpreter_path;
    if (!ReadElfInterpreter(real_exec_path, &interpreter_path)) {
        return plan;
    }

    const std::string real_interpreter_path = BuildRealPathInRootfs(extract_dst_path, interpreter_path);
    if (real_interpreter_path.empty()) {
        return plan;
    }

    __android_log_print(
        ANDROID_LOG_INFO,
        kLogTag,
        "Launching dynamic ELF through interpreter: command=%s interpreter=%s",
        real_exec_path.c_str(),
        real_interpreter_path.c_str());
    plan.executable_path = real_interpreter_path;
    plan.args = {interpreter_path, real_exec_path};
    return plan;
}

bool ReadTraceeArgv(pid_t pid, uint64_t argv_address, std::vector<uint64_t>* argv_out) {
    if (argv_out == nullptr || argv_address == 0) {
        return false;
    }

    argv_out->clear();
    for (size_t i = 0; i < kMaxExecArgCount; ++i) {
        uint64_t arg_ptr = 0;
        if (!ReadTraceeMemory(pid, argv_address + (i * sizeof(uint64_t)), &arg_ptr, sizeof(arg_ptr))) {
            return false;
        }
        if (arg_ptr == 0) {
            return !argv_out->empty();
        }
        argv_out->push_back(arg_ptr);
    }
    return false;
}

ExecRewriteResult RewriteExecveForDynamicElfIfNeeded(
    pid_t pid,
    const std::string& normalized_rootfs,
    user_pt_regs* regs) {
    if (regs == nullptr || regs->regs[8] != kSysExecve) {
        return ExecRewriteResult::kNotApplicable;
    }

    const uint64_t source_path_address = regs->regs[0];
    const uint64_t argv_address = regs->regs[1];
    if (source_path_address == 0 || argv_address == 0) {
        return ExecRewriteResult::kNotApplicable;
    }

    std::string original_path;
    if (!ReadTraceeCString(pid, source_path_address, kPathReadLimit, &original_path) ||
        !IsAbsoluteUnixPath(original_path)) {
        return ExecRewriteResult::kNotApplicable;
    }

    const std::string rewritten_path = RewritePathToRootfs(normalized_rootfs, original_path);
    std::string interpreter_path;
    if (!ReadElfInterpreter(rewritten_path, &interpreter_path)) {
        return ExecRewriteResult::kNotApplicable;
    }

    const std::string rewritten_interpreter_path = BuildRealPathInRootfs(normalized_rootfs, interpreter_path);
    if (rewritten_interpreter_path.empty()) {
        __android_log_print(
            ANDROID_LOG_WARN,
            kLogTag,
            "Dynamic execve interpreter resolved to empty path for %s",
            rewritten_path.c_str());
        return ExecRewriteResult::kFailed;
    }

    std::vector<uint64_t> original_argv;
    if (!ReadTraceeArgv(pid, argv_address, &original_argv)) {
        __android_log_print(
            ANDROID_LOG_WARN,
            kLogTag,
            "Failed to read argv for execve pid=%d path=%s",
            pid,
            rewritten_path.c_str());
        return ExecRewriteResult::kFailed;
    }

    if (regs->sp <= kExecScratchSize + kStackScratchOffset) {
        return ExecRewriteResult::kFailed;
    }

    const uint64_t scratch_base = regs->sp - kExecScratchSize;
    uint64_t cursor = scratch_base;

    const uint64_t interpreter_string_address = cursor;
    if (!WriteTraceeMemory(
            pid,
            cursor,
            rewritten_interpreter_path.c_str(),
            rewritten_interpreter_path.size() + 1)) {
        return ExecRewriteResult::kFailed;
    }
    cursor += rewritten_interpreter_path.size() + 1;
    cursor = AlignUp(cursor, sizeof(uint64_t));

    const uint64_t binary_string_address = cursor;
    if (!WriteTraceeMemory(pid, cursor, rewritten_path.c_str(), rewritten_path.size() + 1)) {
        return ExecRewriteResult::kFailed;
    }
    cursor += rewritten_path.size() + 1;
    cursor = AlignUp(cursor, sizeof(uint64_t));

    std::vector<uint64_t> rewritten_argv;
    rewritten_argv.reserve(original_argv.size() + 2);
    rewritten_argv.push_back(interpreter_string_address);
    rewritten_argv.push_back(binary_string_address);
    for (size_t i = 1; i < original_argv.size(); ++i) {
        rewritten_argv.push_back(original_argv[i]);
    }
    rewritten_argv.push_back(0);

    const uint64_t rewritten_argv_address = cursor;
    if (!WriteTraceeMemory(
            pid,
            rewritten_argv_address,
            rewritten_argv.data(),
            rewritten_argv.size() * sizeof(uint64_t))) {
        return ExecRewriteResult::kFailed;
    }

    regs->regs[0] = interpreter_string_address;
    regs->regs[1] = rewritten_argv_address;
    if (!SetRegs(pid, *regs)) {
        return ExecRewriteResult::kFailed;
    }

    __android_log_print(
        ANDROID_LOG_INFO,
        kLogTag,
        "Rewrote execve to interpreter pid=%d command=%s interpreter=%s",
        pid,
        rewritten_path.c_str(),
        rewritten_interpreter_path.c_str());
    return ExecRewriteResult::kApplied;
}

void SetEmulatedSyscallReturn(pid_t pid, TraceeState* state, user_pt_regs* regs, int64_t return_value) {
    if (state == nullptr || regs == nullptr) {
        return;
    }

    regs->regs[8] = kSkippedSyscall;
    if (!SetRegs(pid, *regs)) {
        __android_log_print(ANDROID_LOG_WARN, kLogTag, "Failed to skip syscall for pid=%d", pid);
        return;
    }

#if defined(__aarch64__)
    int syscall_no = -1;
    iovec io_syscall { &syscall_no, sizeof(syscall_no) };
    if (ptrace(PTRACE_SETREGSET, pid, reinterpret_cast<void*>(0x404 /* NT_ARM_SYSTEM_CALL */), &io_syscall) != 0) {
        __android_log_print(ANDROID_LOG_WARN, kLogTag, "Failed to set NT_ARM_SYSTEM_CALL for pid=%d", pid);
    }
#endif

    state->has_emulated_return = true;
    state->emulated_return = static_cast<uint64_t>(return_value);
}

bool MaybeEmulateUidGidSyscall(pid_t pid, TraceeState* state, user_pt_regs* regs) {
    if (regs == nullptr) {
        return false;
    }

    switch (regs->regs[8]) {
        case kSysGetuid:
        case kSysGeteuid:
            SetEmulatedSyscallReturn(pid, state, regs, kRootUid);
            return true;
        case kSysGetgid:
        case kSysGetegid:
            SetEmulatedSyscallReturn(pid, state, regs, kRootGid);
            return true;
        case kSysSetuid:
        case kSysSetgid:
        case kSysSetresuid:
        case kSysSetresgid:
        case kSysSetgroups:
        case kSysCapset:
            SetEmulatedSyscallReturn(pid, state, regs, 0);
            return true;
        case kSysGetresuid: {
            const uint32_t root = 0;
            WriteTraceeMemory(pid, regs->regs[0], &root, sizeof(root));
            WriteTraceeMemory(pid, regs->regs[1], &root, sizeof(root));
            WriteTraceeMemory(pid, regs->regs[2], &root, sizeof(root));
            SetEmulatedSyscallReturn(pid, state, regs, 0);
            return true;
        }
        case kSysGetresgid: {
            const uint32_t root = 0;
            WriteTraceeMemory(pid, regs->regs[0], &root, sizeof(root));
            WriteTraceeMemory(pid, regs->regs[1], &root, sizeof(root));
            WriteTraceeMemory(pid, regs->regs[2], &root, sizeof(root));
            SetEmulatedSyscallReturn(pid, state, regs, 0);
            return true;
        }
        case kSysGetgroups: {
            const uint64_t size = regs->regs[0];
            const uint64_t list = regs->regs[1];
            if (size == 0) {
                SetEmulatedSyscallReturn(pid, state, regs, 1);
                return true;
            }
            if (list == 0) {
                SetEmulatedSyscallReturn(pid, state, regs, -EFAULT);
                return true;
            }
            const uint32_t root = 0;
            WriteTraceeMemory(pid, list, &root, sizeof(root));
            SetEmulatedSyscallReturn(pid, state, regs, 1);
            return true;
        }
        default:
            return false;
    }
}

bool MaybeEmulateIoctlSyscall(pid_t pid, TraceeState* state, user_pt_regs* regs) {
    if (regs == nullptr || regs->regs[8] != kSysIoctl) {
        return false;
    }

    const uint64_t request = regs->regs[1];
    const uint64_t fd = regs->regs[0];
    
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/fd/%llu", pid, static_cast<unsigned long long>(fd));
    char target[256];
    ssize_t len = readlink(path, target, sizeof(target) - 1);
    if (len > 0) {
        target[len] = '\0';
    } else {
        target[0] = '\0';
    }

    __android_log_print(ANDROID_LOG_INFO, kLogTag, "ioctl pid=%d fd=%llu request=0x%llx target=%s", pid, static_cast<unsigned long long>(fd), static_cast<unsigned long long>(request), target);

    if (request == kTiocgwinsz || request == kTcgets || request == kTiocgpgrp || request == kTiocspgrp) {
        if (len > 0) {
            if (strncmp(target, "pipe:", 5) == 0 || strncmp(target, "socket:", 7) == 0 || strncmp(target, "anon_inode:", 11) == 0) {
                __android_log_print(ANDROID_LOG_INFO, kLogTag, "emulating ioctl for target=%s", target);
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

    const uint64_t domain = regs->regs[0];
    const uint64_t type = regs->regs[1];
    const uint64_t protocol = regs->regs[2];
    const uint64_t base_type = type & kSockTypeMask;
    const bool is_icmp_v4 = domain == kAfInet && protocol == kIpProtoIcmp;
    const bool is_icmp_v6 = domain == kAfInet6 && protocol == kIpProtoIcmpv6;
    if (base_type != kSockRaw || (!is_icmp_v4 && !is_icmp_v6)) {
        return false;
    }

    regs->regs[1] = (type & ~kSockTypeMask) | kSockDgram;
    if (!SetRegs(pid, *regs)) {
        __android_log_print(ANDROID_LOG_WARN, kLogTag, "Failed to rewrite ping socket for pid=%d", pid);
        return false;
    }

    __android_log_print(
        ANDROID_LOG_INFO,
        kLogTag,
        "rewrote ICMP raw socket to datagram ping socket pid=%d domain=%llu protocol=%llu",
        pid,
        static_cast<unsigned long long>(domain),
        static_cast<unsigned long long>(protocol));
    return true;
}

bool ApplyEmulatedSyscallReturn(pid_t pid, TraceeState* state) {
    if (state == nullptr || !state->has_emulated_return) {
        return false;
    }

    user_pt_regs regs {};
    if (!GetRegs(pid, &regs)) {
        __android_log_print(ANDROID_LOG_WARN, kLogTag, "Failed to read regs for emulated syscall pid=%d", pid);
        return false;
    }

    regs.regs[0] = state->emulated_return;
    if (!SetRegs(pid, regs)) {
        __android_log_print(ANDROID_LOG_WARN, kLogTag, "Failed to set emulated syscall result pid=%d", pid);
        return false;
    }

    state->has_emulated_return = false;
    state->emulated_return = 0;
    return true;
}

int PathArgumentIndexForSyscall(uint64_t syscall_number) {
    switch (syscall_number) {
        case kSysOpenat:
        case kSysOpenat2:
            return 1;
        case kSysFaccessat:
        case kSysFaccessat2:
        case kSysNewfstatat:
        case kSysReadlinkat:
        case kSysStatx:
            return 1;
        case kSysChdir:
        case kSysExecve:
            return 0;
        default:
            return -1;
    }
}

void RewritePathArgumentIfNeeded(pid_t pid, const std::string& normalized_rootfs, user_pt_regs* regs) {
    const int arg_index = PathArgumentIndexForSyscall(regs->regs[8]);
    if (arg_index < 0) {
        return;
    }

    const uint64_t source_path_address = regs->regs[arg_index];
    if (source_path_address == 0) {
        return;
    }

    std::string original_path;
    if (!ReadTraceeCString(pid, source_path_address, kPathReadLimit, &original_path)) {
        return;
    }
    if (!IsAbsoluteUnixPath(original_path)) {
        return;
    }

    const std::string rewritten_path = RewritePathToRootfs(normalized_rootfs, original_path);
    if (rewritten_path == original_path) {
        return;
    }

    __android_log_print(
        ANDROID_LOG_VERBOSE,
        kLogTag,
        "rewrite pid=%d syscall=%llu %s -> %s",
        pid,
        static_cast<unsigned long long>(regs->regs[8]),
        original_path.c_str(),
        rewritten_path.c_str());

    const uint64_t scratch_address = regs->sp > kStackScratchOffset ? regs->sp - kStackScratchOffset : 0;
    if (scratch_address != 0 &&
        WriteTraceeMemory(pid, scratch_address, rewritten_path.c_str(), rewritten_path.size() + 1)) {
        regs->regs[arg_index] = scratch_address;
        if (!SetRegs(pid, *regs)) {
            __android_log_print(ANDROID_LOG_WARN, kLogTag, "Failed to set regs for pid=%d", pid);
        }
        return;
    }

    if (rewritten_path.size() <= original_path.size() &&
        WriteTraceeMemory(pid, source_path_address, rewritten_path.c_str(), rewritten_path.size() + 1)) {
        return;
    }
}

void RewriteSockaddrIfNeeded(pid_t pid, const std::string& normalized_rootfs, user_pt_regs* regs) {
    const uint64_t syscall_number = regs->regs[8];
    int sockaddr_arg_index = -1;
    int addrlen_arg_index = -1;

    if (syscall_number == kSysBind || syscall_number == kSysConnect) {
        sockaddr_arg_index = 1;
        addrlen_arg_index = 2;
    } else if (syscall_number == kSysSendto) {
        sockaddr_arg_index = 4;
        addrlen_arg_index = 5;
    } else {
        return;
    }

    const uint64_t sockaddr_address = regs->regs[sockaddr_arg_index];
    const uint64_t addrlen = regs->regs[addrlen_arg_index];

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

    char first_byte = 0;
    if (!ReadTraceeMemory(pid, sockaddr_address + sizeof(sa_family_t), &first_byte, 1)) {
        return;
    }
    if (first_byte == '\0') {
        return;
    }

    std::string original_path;
    if (!ReadTraceeCString(pid, sockaddr_address + sizeof(sa_family_t), 108, &original_path)) {
        return;
    }

    if (!IsAbsoluteUnixPath(original_path)) {
        return;
    }

    const std::string rewritten_path = RewritePathToRootfs(normalized_rootfs, original_path);
    if (rewritten_path == original_path) {
        return;
    }

    __android_log_print(
        ANDROID_LOG_VERBOSE,
        kLogTag,
        "rewrite_sockaddr pid=%d syscall=%llu %s -> %s",
        pid,
        static_cast<unsigned long long>(syscall_number),
        original_path.c_str(),
        rewritten_path.c_str());

    size_t new_addrlen = sizeof(sa_family_t) + rewritten_path.size() + 1;
    if (new_addrlen > sizeof(sa_family_t) + 108) {
        __android_log_print(ANDROID_LOG_WARN, kLogTag, "rewritten unix socket path too long");
        return;
    }

    const uint64_t scratch_address = regs->sp > kStackScratchOffset ? regs->sp - kStackScratchOffset : 0;
    if (scratch_address == 0) {
        return;
    }

    if (!WriteTraceeMemory(pid, scratch_address, &family, sizeof(family))) {
        return;
    }
    if (!WriteTraceeMemory(pid, scratch_address + sizeof(family), rewritten_path.c_str(), rewritten_path.size() + 1)) {
        return;
    }

    regs->regs[sockaddr_arg_index] = scratch_address;
    regs->regs[addrlen_arg_index] = new_addrlen;
    if (!SetRegs(pid, *regs)) {
        __android_log_print(ANDROID_LOG_WARN, kLogTag, "Failed to set regs for pid=%d sockaddr", pid);
    }
}

int ChildTraceeMain(
    const std::string& extract_dst_path,
    const std::string& command_path_in_rootfs,
    int stdin_fd,
    int stdout_fd,
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

    const ExecPlan exec_plan = BuildExecPlan(extract_dst_path, command_path_in_rootfs);
    if (exec_plan.executable_path.empty() || exec_plan.args.empty()) {
        return 127;
    }

    if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) != 0) {
        return 127;
    }
    raise(SIGSTOP);

    std::vector<char*> argv;
    argv.reserve(exec_plan.args.size() + 1);
    for (const std::string& arg : exec_plan.args) {
        argv.push_back(const_cast<char*>(arg.c_str()));
    }
    argv.push_back(nullptr);

    char* const envp[] = {
        const_cast<char*>("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
        const_cast<char*>("HOME=/root"),
        const_cast<char*>("USER=root"),
        const_cast<char*>("LOGNAME=root"),
        const_cast<char*>("SHELL=/usr/bin/bash"),
        const_cast<char*>("PWD=/"),
        const_cast<char*>("TERM=xterm-256color"),
        nullptr,
    };
    execve(exec_plan.executable_path.c_str(), argv.data(), envp);
    __android_log_print(
        ANDROID_LOG_ERROR,
        kLogTag,
        "execve failed: executable=%s errno=%d (%s)",
        exec_plan.executable_path.c_str(),
        errno,
        strerror(errno));
    return 126;
}

void ResumeSyscall(pid_t pid, int signal_number) {
    if (ptrace(PTRACE_SYSCALL, pid, nullptr, signal_number) != 0) {
        __android_log_print(ANDROID_LOG_WARN, kLogTag, "PTRACE_SYSCALL failed for pid=%d (%d)", pid, errno);
    }
}

bool SuppressBlockedSyscall(pid_t pid, TraceeState* state) {
    user_pt_regs regs {};
    if (!GetRegs(pid, &regs)) {
        __android_log_print(ANDROID_LOG_WARN, kLogTag, "Failed to read regs for SIGSYS pid=%d", pid);
        return false;
    }

    siginfo_t siginfo {};
    const bool has_siginfo = ptrace(PTRACE_GETSIGINFO, pid, nullptr, &siginfo) == 0;
    if (has_siginfo) {
        __android_log_print(
            ANDROID_LOG_WARN,
            kLogTag,
            "pid=%d blocked syscall=%d arch=0x%x code=%d",
            pid,
            siginfo.si_syscall,
            siginfo.si_arch,
            siginfo.si_code);
    } else {
        __android_log_print(
            ANDROID_LOG_WARN,
            kLogTag,
            "pid=%d blocked syscall=%llu",
            pid,
            static_cast<unsigned long long>(regs.regs[8]));
    }

    const int blocked_syscall = has_siginfo ? siginfo.si_syscall : static_cast<int>(regs.regs[8]);
    int64_t return_value = -ENOSYS;
    switch (blocked_syscall) {
        case kSysSetuid:
        case kSysSetgid:
        case kSysSetresuid:
        case kSysSetresgid:
        case kSysSetgroups:
        case kSysCapset:
            return_value = 0;
            break;
        default:
            break;
    }

    regs.regs[0] = static_cast<uint64_t>(return_value);
    if (!SetRegs(pid, regs)) {
        __android_log_print(ANDROID_LOG_WARN, kLogTag, "Failed to set SIGSYS result for pid=%d", pid);
        return false;
    }
    if (state != nullptr) {
        state->expect_entry = true;
        state->has_emulated_return = false;
    }
    return true;
}

int TracerMain(
    const std::string& extract_dst_path,
    const std::string& command_path_in_rootfs,
    int stdin_fd,
    int stdout_fd,
    int stderr_fd) {
    prctl(PR_SET_PDEATHSIG, SIGKILL);

    const std::string normalized_rootfs = NormalizeRootfsPrefix(extract_dst_path);

    const pid_t tracee_pid = fork();
    if (tracee_pid < 0) {
        return 1;
    }
    if (tracee_pid == 0) {
        _exit(ChildTraceeMain(extract_dst_path, command_path_in_rootfs, stdin_fd, stdout_fd, stderr_fd));
    }

    int status = 0;
    if (waitpid(tracee_pid, &status, 0) != tracee_pid || !WIFSTOPPED(status)) {
        return 1;
    }

    std::unordered_map<pid_t, TraceeState> states;
    std::unordered_set<pid_t> tracked_pids;

    states.emplace(tracee_pid, TraceeState{});
    tracked_pids.emplace(tracee_pid);
    if (!ApplyTraceOptions(tracee_pid)) {
        return 1;
    }
    states[tracee_pid].options_applied = true;
    ResumeSyscall(tracee_pid, 0);

    while (!tracked_pids.empty()) {
        int wait_status = 0;
        const pid_t pid = waitpid(-1, &wait_status, __WALL);
        if (pid < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }

        if (WIFEXITED(wait_status)) {
            __android_log_print(
                ANDROID_LOG_INFO,
                kLogTag,
                "pid=%d exited status=%d",
                pid,
                WEXITSTATUS(wait_status));
            tracked_pids.erase(pid);
            states.erase(pid);
            continue;
        }
        if (WIFSIGNALED(wait_status)) {
            __android_log_print(
                ANDROID_LOG_WARN,
                kLogTag,
                "pid=%d killed signal=%d",
                pid,
                WTERMSIG(wait_status));
            tracked_pids.erase(pid);
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

        const int signal_number = WSTOPSIG(wait_status);
        const unsigned event = static_cast<unsigned>(wait_status) >> 16U;
        if (signal_number == (SIGTRAP | 0x80)) {
            if (state.expect_entry) {
                user_pt_regs regs {};
                if (GetRegs(pid, &regs)) {
                    if (!MaybeEmulateUidGidSyscall(pid, &state, &regs) &&
                        !MaybeEmulateIoctlSyscall(pid, &state, &regs)) {
                        MaybeRewritePingSocket(pid, &regs);
                        const ExecRewriteResult exec_rewrite_result =
                            RewriteExecveForDynamicElfIfNeeded(pid, normalized_rootfs, &regs);
                        if (exec_rewrite_result == ExecRewriteResult::kNotApplicable) {
                            RewritePathArgumentIfNeeded(pid, normalized_rootfs, &regs);
                            RewriteSockaddrIfNeeded(pid, normalized_rootfs, &regs);
                        }
                    }
                }
            } else if (state.has_emulated_return) {
                ApplyEmulatedSyscallReturn(pid, &state);
            }
            state.expect_entry = !state.expect_entry;
            ResumeSyscall(pid, 0);
            continue;
        }

        if (signal_number == SIGTRAP && event != 0U) {
            __android_log_print(
                ANDROID_LOG_VERBOSE,
                kLogTag,
                "pid=%d ptrace event=%u",
                pid,
                event);
            if (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK || event == PTRACE_EVENT_CLONE) {
                unsigned long new_pid = 0;
                if (ptrace(PTRACE_GETEVENTMSG, pid, nullptr, &new_pid) == 0 && new_pid > 0) {
                    tracked_pids.insert(static_cast<pid_t>(new_pid));
                    states.emplace(static_cast<pid_t>(new_pid), TraceeState{});
                }
            }
            ResumeSyscall(pid, 0);
            continue;
        }

        if (signal_number == SIGSTOP || signal_number == SIGCHLD) {
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

        __android_log_print(
            ANDROID_LOG_VERBOSE,
            kLogTag,
            "pid=%d signal stop=%d",
            pid,
            signal_number);
        ResumeSyscall(pid, signal_number);
    }

    return 0;
}

}  // namespace

int StartChroot(
    const std::string& extract_dst_path,
    const std::string& command_path_in_rootfs,
    int stdin_fd,
    int stdout_fd,
    int stderr_fd) {
    if (extract_dst_path.empty() || command_path_in_rootfs.empty()) {
        return -EINVAL;
    }
    if (stdin_fd < 0 || stdout_fd < 0 || stderr_fd < 0) {
        return -EBADF;
    }

    const pid_t tracer_pid = fork();
    if (tracer_pid < 0) {
        return -errno;
    }

    if (tracer_pid == 0) {
        _exit(TracerMain(extract_dst_path, command_path_in_rootfs, stdin_fd, stdout_fd, stderr_fd));
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
