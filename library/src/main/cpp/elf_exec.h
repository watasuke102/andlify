#pragma once

#include <elf.h>
#include <sys/types.h>

#include <memory>
#include <string>
#include <vector>

struct ElfExecutable {
  int                     fd = -1;
  Elf64_Ehdr              header{};
  std::vector<Elf64_Phdr> segments;
  std::string             interpreter;
  uint64_t                first_page   = 0;
  uint64_t                end_page     = 0;
  uint64_t                alignment    = 0;
  uint64_t                phdr_address = 0;

  ~ElfExecutable();
};

std::shared_ptr<ElfExecutable> OpenElfExecutable(const std::string& path);
int InitializeElfExecutable(pid_t pid, const ElfExecutable& executable,
    const ElfExecutable* interpreter, const std::string& execfn,
    const std::string& comm, std::vector<Elf64_auxv_t>* auxiliary_vector);
