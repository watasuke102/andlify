#!/usr/bin/env python3
import io
import pathlib
import subprocess
import tarfile
import tempfile

project = pathlib.Path(__file__).resolve().parents[1]
cpp = project / "library/src/main/cpp"
with tempfile.TemporaryDirectory(prefix="andlify-extraction-") as temporary:
    temporary = pathlib.Path(temporary)
    stub = temporary / "android"
    stub.mkdir()
    (stub / "log.h").write_text(
        '#pragma once\n#define ANDROID_LOG_ERROR 6\n#define ANDROID_LOG_INFO 4\n'
        'extern "C" int __android_log_print(int, const char*, const char*, ...);\n'
    )
    archive = temporary / "rootfs.tar"
    with tarfile.open(archive, "w", format=tarfile.USTAR_FORMAT) as tar:
        for name, kind, mode in (
            ("bin", tarfile.DIRTYPE, 0o2755),
            ("bin/driver", tarfile.REGTYPE, 0o4755),
            ("bin/alias", tarfile.LNKTYPE, 0o4755),
            ("bin/link", tarfile.SYMTYPE, 0o777),
        ):
            entry = tarfile.TarInfo(name)
            entry.type, entry.mode = kind, mode
            entry.uid, entry.gid = 1234, 2345
            payload = None
            if kind == tarfile.REGTYPE:
                data = b"executable payload\n"
                entry.size = len(data)
                payload = io.BytesIO(data)
            elif kind == tarfile.LNKTYPE:
                entry.linkname = "bin/driver"
            elif kind == tarfile.SYMTYPE:
                entry.linkname = "alias"
            tar.addfile(entry, payload)
    binary = temporary / "test"
    subprocess.run([
        "c++", "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror",
        "-I", str(temporary), "-I", str(cpp),
        str(project / "tests/rootfs_extraction_test.cpp"),
        str(cpp / "rootfs_extractor.cpp"),
        *(str(cpp / "ownership" / source) for source in (
            "ownership_store.cpp", "ownership_persistence.cpp",
            "terminal_ownership.cpp", "user_setup.cpp",
        )),
        "-larchive", "-lzstd", "-o", str(binary),
    ], check=True)
    subprocess.run([str(binary), str(archive), str(temporary / "root")],
                   check=True, timeout=60)
print("archive file types and permissions: passed")
