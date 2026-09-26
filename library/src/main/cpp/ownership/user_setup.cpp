#include "user_setup.h"

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <fstream>
#include <sstream>

#include "ownership_store.h"

namespace andlify {
bool PrepareUser(OwnershipStore& store) {
  for (const auto& item : std::vector<std::pair<std::string, std::string>>{
           {"passwd",  "user:x:1000:1000:User:/home/user:/bin/sh"},
           {"group",   "user:x:1000:"                            },
           {"shadow",  "user:!:0:0:99999:7:::"                   },
           {"gshadow", "user:!::"                                }
  }) {
    std::string   path = store.root() + "/etc/" + item.first;
    std::ifstream input(path);
    std::string   data, line;
    bool          found = false;
    while (std::getline(input, line)) {
      std::istringstream fields(line);
      std::string        name, password, id;
      std::getline(fields, name, ':');
      std::getline(fields, password, ':');
      std::getline(fields, id, ':');
      const bool numeric = item.first == "passwd" || item.first == "group";
      if (name == "user" || (numeric && id == "1000")) {
        if (name != "user" || (numeric && id != "1000")) {
          errno = EEXIST;
          return false;
        }
        found = true;
      }
      data += line + "\n";
    }
    if (found)
      continue;
    data += item.second + "\n";
    const std::string temporary = path + ".andlify-new";
    int               fd        = open(temporary.c_str(),
        O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0)
      return false;
    size_t offset = 0;
    while (offset < data.size()) {
      ssize_t n = write(fd, data.data() + offset, data.size() - offset);
      if (n < 0 && errno == EINTR)
        continue;
      if (n <= 0) {
        close(fd);
        return false;
      }
      offset += n;
    }
    bool ok = fsync(fd) == 0;
    close(fd);
    if (!ok ||
        !store.SetPath(temporary, 0, 0,
            (item.first == "shadow" || item.first == "gshadow") ? 0600 :
                                                                  0644) ||
        rename(temporary.c_str(), path.c_str()) != 0)
      return false;
    int directory = open(
        (store.root() + "/etc").c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory < 0)
      return false;
    ok = fsync(directory) == 0;
    close(directory);
    if (!ok)
      return false;
  }
  for (const auto& path :
      {"/home", "/home/user", "/run", "/run/user", "/run/user/1000"}) {
    const std::string real = store.root() + path;
    if (mkdir(real.c_str(), 0700) != 0 && errno != EEXIST)
      return false;
    struct stat st{};
    if (lstat(real.c_str(), &st) != 0 || !S_ISDIR(st.st_mode))
      return false;
    const bool user =
        strcmp(path, "/home/user") == 0 || strcmp(path, "/run/user/1000") == 0;
    if (!store.SetPath(
            real, user ? 1000 : 0, user ? 1000 : 0, user ? 0700 : 0755))
      return false;
  }
  return true;
}
}  // namespace andlify
