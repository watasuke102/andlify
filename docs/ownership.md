# Users and file ownership

New sessions run as virtual UID/GID **1000:1000**, named `user`, with
`HOME=/home/user` and `XDG_RUNTIME_DIR=/run/user/1000`. The first session
creates the account, a locked password entry, the home directory, and the
0700 runtime directory. Conflicting existing account names/IDs cause startup
to fail rather than silently changing an existing account. Existing `/root`
configuration is retained; it is not copied into the new user's home.

`StartChroot`, `StartChrootFunc`, and their Kotlin counterparts accept optional
initial `uid` and `gid` arguments. Defaults are 1000. Explicit `0, 0` can be
used for environment initialization or administration. Consumers that start
system daemons must use the appropriate initial identity and drop privileges
for their user session; they must also update any hard-coded root session-bus
paths. These identities never change the Android application's kernel UID.

Ownership is stored beside the rootfs in `<canonical-rootfs>.andlify-owners`:

- `snapshot` and `journal` contain versioned, little-endian, checksummed records.
  Sequence numbers allow recovery when snapshot publication completed but log
  truncation did not. An incomplete trailing record is truncated on recovery;
  checksum corruption fails startup instead of guessing ownership.
- `table` is a disposable shared mmap cache, rebuilt by the first live session.
  Subsequent tracers attach to the same table. File lookups use atomic fields
  and a generation counter, without database access or an uncontended read
  lock syscall. Writers are serialized with `flock`; process death releases
  the lock. Interrupted table publication is recovered from the journal.
- Ownership/mode changes are synchronized to the journal before publication.
  This intentionally makes metadata mutations more expensive than reads;
  ordinary `read`/`write` calls do not consult the ownership database. Snapshot
  compaction runs after 16,384 updates. Archive import batches its durability
  boundary at the final checkpoint.
- Regular files, directories, symlinks and FIFOs created through the supported
  creation syscalls are staged with durable metadata before atomic publication.
  Staging remnants are discarded at the next session-group startup. Socket
  binds and anonymous `O_TMPFILE` creation are registered at syscall exit.

The table records virtual UID, GID and mode per device/inode. Hard links share
an entry and rename preserves it. Unlinked entries remain available for open
file descriptors and are pruned when the next session group starts. Startup
uses `statx` birth timestamps to reject stale records for reused inode numbers;
the rootfs filesystem must support `STATX_BTIME` and atomic rename within the
rootfs/metadata filesystem. Filesystem metadata must not be changed externally
while sessions are running. Host-side copies of the rootfs and database are
not a portable ownership backup: inode identities change. Archives produced
inside the virtual environment can preserve the virtual identities.

Archive extraction records numeric owners from the archive. Existing rootfs
installations without an ownership database are imported as root-owned, since
the original archive owners were not retained by previous versions. Unknown
host-created entries are likewise imported as root-owned. The metadata directory
is part of the environment's persistent data and must not be discarded while
retaining the rootfs.

The current shared table supports 524,288 distinct inode entries per session
group and 16,384 process identities; capacity exhaustion reports `ENOSPC`.
File entry storage is about 20 MiB, plus process identities and control data.
Startup traversal and checkpointing have costs proportional to the entry count.

Virtual checks cover path traversal, open/access/exec, creation, chmod/chown,
sticky directories, link/rename/unlink and filesystem Unix sockets. Set-ID
execution uses the recorded owner and honors `no_new_privs`; ELF auxiliary
UID/GID values are also virtualized. This is compatibility emulation, not a
kernel-enforced multi-user security boundary. ACLs, capabilities, raw kernel
`/proc` identity views, and races with external filesystem changes are not a
complete Linux security model. IPC identities are shared across tracers and
validated against process start times; credential changes after a socket was
connected are not yet tracked as per-socket credential snapshots.

Host regression checks (no Android device required):

```sh
python3 tests/ownership_test.py
```
