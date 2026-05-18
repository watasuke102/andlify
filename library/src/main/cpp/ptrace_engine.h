#pragma once

#include <sys/types.h>

#include <string>

int StartChroot(
    const std::string& extract_dst_path,
    const std::string& command_path_in_rootfs,
    int stdin_fd,
    int stdout_fd,
    int stderr_fd);
void StopChroot(pid_t tracer_pid);
