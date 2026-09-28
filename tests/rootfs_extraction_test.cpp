#include <sys/stat.h>

#include <cassert>
#include <fstream>
#include <string>

#include "ownership/ownership_store.h"
#include "rootfs_extractor.h"

extern "C" int __android_log_print(int, const char*, const char*, ...) {
  return 0;
}

int main(int argc, char** argv) {
  assert(argc == 3);
  const std::string root = argv[2];
  assert(ExtractRootfs(argv[1], root));
  assert(IsRootfsExtracted(root));
  {
    struct stat info{};
    assert(lstat((root + "/bin/alias").c_str(), &info) == 0);
    std::ifstream snapshot(root + ".andlify-owners/snapshot", std::ios::binary);
    unsigned char record[64];
    bool          found = false;
    while (snapshot.read(reinterpret_cast<char*>(record), sizeof(record))) {
      uint64_t inode = 0;
      uint32_t mode  = 0;
      for (int i = 0; i < 8; ++i) inode |= uint64_t(record[24 + i]) << (8 * i);
      for (int i = 0; i < 4; ++i) mode |= uint32_t(record[52 + i]) << (8 * i);
      if (inode != info.st_ino)
        continue;
      assert(mode == (S_IFREG | 04755));
      found = true;
    }
    assert(found);
  }
  {
    andlify::OwnershipStore store;
    assert(store.Open(root));
    for (const auto& name : {"driver", "alias", "link"}) {
      andlify::FileOwner actual, saved;
      assert(store.Identify(root + "/bin/" + name, &actual));
      assert(store.Lookup(actual.device, actual.inode, &saved));
      assert((saved.mode & S_IFMT) == (actual.mode & S_IFMT));
      assert(saved.uid == 1234 && saved.gid == 2345);
      assert((saved.mode & 07777) ==
             (std::string(name) == "link" ? 0777U : 04755U));
    }
    std::ifstream copy(root + "/bin/alias");
    std::string   content;
    std::getline(copy, content);
    assert(content == "executable payload");
  }
  {
    andlify::OwnershipStore store;
    assert(store.Open(root));
    for (const auto& name : {"bin", "bin/alias"}) {
      andlify::FileOwner actual, saved;
      assert(store.Identify(root + "/" + name, &actual));
      assert(store.Lookup(actual.device, actual.inode, &saved));
      assert((saved.mode & S_IFMT) == (actual.mode & S_IFMT));
      assert(saved.uid == 1234 && saved.gid == 2345);
      assert((saved.mode & 07777) ==
             (std::string(name) == "bin" ? 02755U : 04755U));
    }
  }
}
