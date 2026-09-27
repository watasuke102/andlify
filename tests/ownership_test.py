#!/usr/bin/env python3
import errno
import pathlib
import subprocess
import tempfile

SOURCE = r'''
#include "ownership/ownership_store.h"
#include "filesystem/virtual_filesystem.h"
#include <cassert>
#include <cstdarg>
#include <cstdlib>
#include <linux/stat.h>
#include <sys/syscall.h>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>
using namespace andlify;
namespace fs = std::filesystem;
int statx_error = 0;
extern "C" long __real_syscall(long, ...);
extern "C" long __wrap_syscall(long number, ...) {
  va_list args;
  va_start(args, number);
  int dir = va_arg(args, int);
  const char* path = va_arg(args, const char*);
  if (number == SYS_statx) {
    int flags = va_arg(args, int);
    unsigned mask = va_arg(args, unsigned);
    auto* result = va_arg(args, struct statx*);
    va_end(args);
    if (statx_error > 0) { errno = statx_error; return -1; }
    long status = __real_syscall(number, dir, path, flags, mask, result);
    if (status == 0 && statx_error == -1) result->stx_mask &= ~STATX_BTIME;
    return status;
  }
  assert(number == SYS_renameat2);
  int target_dir = va_arg(args, int);
  const char* target = va_arg(args, const char*);
  unsigned flags = va_arg(args, unsigned);
  va_end(args);
  return __real_syscall(number, dir, path, target_dir, target, flags);
}
int main(int argc, char** argv) {
  assert(argc == 3);
  statx_error = std::atoi(argv[2]);
  const int original_statx_error = statx_error;
  std::string root = argv[1];
  fs::create_directories(root+"/etc");
  fs::create_directories(root+"/tmp");
  chmod((root+"/tmp").c_str(),01777);
  std::ofstream(root+"/etc/passwd") << "root:x:0:0:root:/root:/bin/sh\n";
  std::ofstream(root+"/etc/group") << "root:x:0:\n";
  std::ofstream(root+"/file") << "test";
  std::ofstream(root+"/readonly") << "test";assert(chmod((root+"/readonly").c_str(),0444)==0);
  {
    OwnershipStore store;FileOwner owner;
    statx_error = EIO;
    assert(!store.Identify(root+"/file",&owner) && errno==EIO);
    statx_error = original_statx_error;
    assert(!store.Identify(root+"/missing",&owner) && errno==ENOENT);
  }
  FileOwner file;
  {
    OwnershipStore store;
    assert(store.Open(root,true));
    FileOwner imported;assert(store.Identify(root+"/readonly",&imported));
    FileOwner original;assert(store.Lookup(imported.device,imported.inode,&original));assert((original.mode&0777)==0444);
    assert(store.Identify(root+"/home/user",&imported));assert(store.Lookup(imported.device,imported.inode,&original));
    assert(original.uid==1000 && (original.mode&0777)==0700);
    std::ifstream shadow(root+"/etc/shadow");std::string shadow_text;std::getline(shadow,shadow_text);assert(shadow_text.rfind("user:!:",0)==0);
    assert(store.Identify(root+"/file",&file));
    file.uid=1000;file.gid=1000;file.mode=S_IFREG|0640;
    assert(store.Set(file));
    assert(link((root+"/file").c_str(),(root+"/hardlink").c_str())==0);
    assert(rename((root+"/file").c_str(),(root+"/renamed").c_str())==0);
    int pipefd[2], ack[2]; assert(pipe(pipefd)==0);assert(pipe(ack)==0);
    auto child=fork();assert(child>=0);
    if(child==0) {
      close(pipefd[0]);
      OwnershipStore second;assert(second.Open(root));
      FileOwner read;assert(second.Lookup(file.device,file.inode,&read));assert(read.uid==1000);
      read.uid=1234;assert(second.Set(read));
      assert(second.RegisterProcess({getpid(),1234,1234,1000,1000}));
      assert(write(pipefd[1],"x",1)==1);
      char c;assert(::read(ack[0],&c,1)==1);_exit(0);
    }
    close(pipefd[1]);char c;assert(read(pipefd[0],&c,1)==1);close(pipefd[0]);
    ProcessOwner identity;assert(store.Process(child,&identity));assert(identity.real_uid==1234);
    assert(write(ack[1],"x",1)==1);close(ack[0]);close(ack[1]);
    int status;assert(waitpid(child,&status,0)==child && status==0);
    store.ForgetProcess(child);assert(!store.Process(child,&identity));
    FileOwner read;assert(store.Lookup(file.device,file.inode,&read));assert(read.uid==1234);
    std::vector<uint32_t> groups{1000};
    FileCredentials user{1000,1000,groups,0022};
    PendingFile pending;int64_t result;uint64_t args[6]{};
    std::string path=root+"/renamed";
    auto resolver=[&](int,int,bool,std::string* out){*out=path;return true;};
    args[2]=O_RDONLY;
    assert(!PrepareFileOperation(getpid(),56,args,user,store,resolver,&pending,&result));
    args[2]=O_WRONLY;
    assert(PrepareFileOperation(getpid(),56,args,user,store,resolver,&pending,&result));assert(result==-EACCES);
    args[2]=1000;args[3]=1000;
    assert(PrepareFileOperation(getpid(),54,args,user,store,resolver,&pending,&result));assert(result==-EPERM);
    FileCredentials administrator{0,0,groups,0022};
    assert(PrepareFileOperation(getpid(),54,args,administrator,store,resolver,&pending,&result));assert(result==0);
    args[2]=0600;
    assert(PrepareFileOperation(getpid(),53,args,user,store,resolver,&pending,&result));assert(result==0);
    assert(store.Lookup(file.device,file.inode,&read));assert(read.uid==1000 && (read.mode&0777)==0600);
    path=root+"/home/user/new";args[2]=O_CREAT|O_EXCL|O_WRONLY;args[3]=0666;
    assert(!PrepareFileOperation(getpid(),56,args,user,store,resolver,&pending,&result));
    assert(!(args[2]&O_EXCL));
    int fd=open(path.c_str(),args[2],0666);assert(fd>=0);
    assert(FinishFileOperation(getpid(),fd,store,user,&pending));close(fd);
    FileOwner created;assert(store.Identify(path,&created));assert(store.Lookup(created.device,created.inode,&read));
    assert(read.uid==1000 && (read.mode&0777)==0644);
    FileOwner stale=read;read.gid=555;assert(store.Set(read));
    stale.uid=77;assert(!store.Set(stale,true,&created));assert(errno==EAGAIN);
    FileOwner sticky;sticky.uid=1234;sticky.gid=1234;sticky.mode=S_IFREG|0600;
    path=root+"/tmp/other";assert(store.Create(path,sticky));
    assert(PrepareFileOperation(getpid(),35,args,user,store,resolver,&pending,&result));assert(result==-EPERM);
    path=root+"/home/user/link";sticky.uid=1000;sticky.gid=1000;sticky.mode=S_IFLNK|0777;
    assert(store.Create(path,sticky,"/missing"));
    assert(store.Identify(path,&created));assert(store.Lookup(created.device,created.inode,&read));assert(read.uid==1000 && S_ISLNK(read.mode));
    path=root+"/etc/forbidden";args[2]=O_CREAT|O_WRONLY;
    assert(PrepareFileOperation(getpid(),56,args,user,store,resolver,&pending,&result));assert(result==-EACCES);
    for(int attempt=0;attempt<8;++attempt) {
      auto writer=fork();assert(writer>=0);
      if(writer==0) {
        OwnershipStore second;assert(second.Open(root));
        FileOwner changing=file;
        for(int n=0;;++n) {changing.uid=1000+(n&1);assert(second.Set(changing));}
      }
      usleep(3000);assert(kill(writer,SIGKILL)==0);
      assert(waitpid(writer,&status,0)==writer);
      assert(store.Lookup(file.device,file.inode,&read));
      assert(read.uid==1000 || read.uid==1001);
      assert(store.Set(file));
    }
    assert(store.Checkpoint());
    read=file;read.uid=4321;assert(store.Set(read));
  }
  // Losing birth-time support must not reset persisted ownership or modes.
  statx_error = -1;
  {
    OwnershipStore store;assert(store.Open(root));FileOwner read;
    assert(store.Lookup(file.device,file.inode,&read));assert(read.uid==4321);
  }
  statx_error = 0;
  {
    OwnershipStore store;assert(store.Open(root));FileOwner read;
    assert(store.Lookup(file.device,file.inode,&read));assert(read.uid==4321);
  }
  statx_error = original_statx_error;
  // A short trailing write must not discard complete preceding records.
  {std::ofstream log(root+".andlify-owners/journal",std::ios::app|std::ios::binary);log<<"short";}
  {
    OwnershipStore store;assert(store.Open(root));
    FileOwner read;assert(store.Lookup(file.device,file.inode,&read));assert(read.uid==4321);
    struct stat st{};assert(lstat((root+"/hardlink").c_str(),&st)==0);
    assert(store.Lookup(st.st_dev,st.st_ino,&read));assert(read.uid==4321);
    int held=open((root+"/renamed").c_str(),O_RDONLY);assert(held>=0);
    assert(unlink((root+"/hardlink").c_str())==0);
    assert(unlink((root+"/renamed").c_str())==0);
    assert(fstat(held,&st)==0 && st.st_nlink==0);
    assert(store.Lookup(st.st_dev,st.st_ino,&read) && read.uid==4321);
    close(held);
  }
  {
    OwnershipStore store;assert(store.Open(root));FileOwner read;
    assert(!store.Lookup(file.device,file.inode,&read));
    FileOwner owner;assert(store.Identify(root+"/etc/passwd",&owner));owner.uid=77;assert(store.Set(owner));
  }
  {
    int fd=open((root+".andlify-owners/journal").c_str(),O_RDWR);assert(fd>=0);
    char byte=0;assert(pwrite(fd,&byte,1,0)==1);close(fd);
    OwnershipStore store;assert(!store.Open(root));
  }
}
'''

with tempfile.TemporaryDirectory(prefix="andlify-ownership-") as tmp:
    tmp = pathlib.Path(tmp)
    source = tmp / "test.cpp"
    source.write_text(SOURCE)
    cpp = pathlib.Path(__file__).resolve().parents[1] / "library/src/main/cpp"
    subprocess.run(["c++", "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror", "-I", str(cpp),
                    str(source), str(cpp / "ownership/ownership_store.cpp"),
                    str(cpp / "ownership/ownership_persistence.cpp"), str(cpp / "ownership/user_setup.cpp"),
                    str(cpp / "filesystem/virtual_filesystem.cpp"),
                    str(cpp / "ptrace_memory.cpp"), "-Wl,--wrap=syscall", "-o", str(tmp / "test")], check=True)
    for error in (0, -1, errno.ENOSYS, errno.EOPNOTSUPP, errno.EINVAL, errno.EPERM, errno.EACCES):
        subprocess.run([str(tmp / "test"), str(tmp / f"root-{error}"), str(error)],
                       check=True, timeout=60)
print("ownership persistence, shared visibility, permissions, recovery: passed")
