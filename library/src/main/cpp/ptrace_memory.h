#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include <string>

bool ReadTraceeCString(pid_t pid, uint64_t remote_address, size_t max_len, std::string* out);
bool WriteTraceeMemory(pid_t pid, uint64_t remote_address, const void* data, size_t len);
