#include "ptrace_engine.h"

#include "path_rewrite.h"
#include "ptrace_memory.h"

#include <android/log.h>
#include <asm/ptrace.h>
#include <elf.h>
#include <errno.h>
#include <linux/ptrace.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include <string>
#include <unordered_map>
#include <unordered_set>

namespace {

constexpr const char* kLogTag = "andlify-ptrace";
constexpr uint64_t kSysOpenat = 56;
constexpr uint64_t kSysFaccessat = 48;
constexpr uint64_t kSysExecve = 221;
constexpr size_t kPathReadLimit = 4096;
constexpr uint64_t kStackScratchOffset = 0x800;

struct TraceeState {
    bool expect_entry = true;
    bool options_applied = false;
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

int PathArgumentIndexForSyscall(uint64_t syscall_number) {
    switch (syscall_number) {
        case kSysOpenat:
            return 1;
        case kSysFaccessat:
            return 1;
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

    const std::string real_exec_path = BuildRealPathInRootfs(extract_dst_path, command_path_in_rootfs);
    if (real_exec_path.empty()) {
        return 127;
    }

    if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) != 0) {
        return 127;
    }
    raise(SIGSTOP);

    std::string argv0 = command_path_in_rootfs;
    if (argv0.empty()) {
        argv0 = "/bin/sh";
    }

    char* const argv[] = {const_cast<char*>(argv0.c_str()), nullptr};
    char* const envp[] = {
        const_cast<char*>("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
        const_cast<char*>("HOME=/root"),
        const_cast<char*>("PWD=/"),
        const_cast<char*>("TERM=xterm-256color"),
        nullptr,
    };
    execve(real_exec_path.c_str(), argv, envp);
    return 126;
}

void ResumeSyscall(pid_t pid, int signal_number) {
    if (ptrace(PTRACE_SYSCALL, pid, nullptr, signal_number) != 0) {
        __android_log_print(ANDROID_LOG_WARN, kLogTag, "PTRACE_SYSCALL failed for pid=%d (%d)", pid, errno);
    }
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

        if (WIFEXITED(wait_status) || WIFSIGNALED(wait_status)) {
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
                    RewritePathArgumentIfNeeded(pid, normalized_rootfs, &regs);
                }
            }
            state.expect_entry = !state.expect_entry;
            ResumeSyscall(pid, 0);
            continue;
        }

        if (signal_number == SIGTRAP && event != 0U) {
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
