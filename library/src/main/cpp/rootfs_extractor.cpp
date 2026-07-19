#include "rootfs_extractor.h"

#include <android/log.h>
#include <archive.h>
#include <archive_entry.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <zstd.h>

#include <string>
#include <vector>

#include "path_rewrite.h"

namespace {

constexpr const char* kLogTag      = "andlify-rootfs";
constexpr const char* kReadyMarker = ".andlify_rootfs_ready";

void LogErrno(const char* context, const std::string& path) {
  const int error_code = errno;
  __android_log_print(ANDROID_LOG_ERROR, kLogTag, "%s: %s (errno=%d, %s)",
      context, path.c_str(), error_code, strerror(error_code));
}

void LogErrno(const char* context) {
  const int error_code = errno;
  __android_log_print(ANDROID_LOG_ERROR, kLogTag, "%s (errno=%d, %s)", context,
      error_code, strerror(error_code));
}

std::string JoinPath(const std::string& left, const std::string& right) {
  if (left.empty()) {
    return right;
  }
  if (right.empty()) {
    return left;
  }
  if (left.back() == '/') {
    if (right.front() == '/') {
      return left + right.substr(1);
    }
    return left + right;
  }
  if (right.front() == '/') {
    return left + right;
  }
  return left + "/" + right;
}

bool EnsureDirectoryRecursive(const std::string& path) {
  if (path.empty()) {
    __android_log_print(
        ANDROID_LOG_ERROR, kLogTag, "EnsureDirectoryRecursive: empty path");
    return false;
  }

  std::string normalized_path = path;
  while (normalized_path.size() > 1 && normalized_path.back() == '/') {
    normalized_path.pop_back();
  }
  if (normalized_path == "/") {
    return true;
  }

  struct stat st{};
  if (stat(normalized_path.c_str(), &st) == 0) {
    if (!S_ISDIR(st.st_mode)) {
      __android_log_print(ANDROID_LOG_ERROR, kLogTag,
          "EnsureDirectoryRecursive: path exists but not directory: %s",
          normalized_path.c_str());
      return false;
    }
    return true;
  }

  const bool is_absolute =
      !normalized_path.empty() && normalized_path.front() == '/';
  std::string current = is_absolute ? "/" : "";
  size_t      start   = is_absolute ? 1 : 0;
  while (start <= normalized_path.size()) {
    const size_t slash = normalized_path.find('/', start);
    const size_t end =
        (slash == std::string::npos) ? normalized_path.size() : slash;
    const std::string token = normalized_path.substr(start, end - start);

    if (!token.empty() && token != ".") {
      if (current.empty()) {
        current = token;
      } else if (current == "/") {
        current += token;
      } else {
        current += "/" + token;
      }

      if (stat(current.c_str(), &st) == 0) {
        if (!S_ISDIR(st.st_mode)) {
          __android_log_print(ANDROID_LOG_ERROR, kLogTag,
              "EnsureDirectoryRecursive: path exists but not directory: %s",
              current.c_str());
          return false;
        }
      } else if (mkdir(current.c_str(), 0755) != 0 && errno != EEXIST) {
        LogErrno("EnsureDirectoryRecursive: mkdir failed", current);
        return false;
      }
    }

    if (slash == std::string::npos) {
      break;
    }
    start = slash + 1;
  }

  if (stat(normalized_path.c_str(), &st) == 0) {
    return S_ISDIR(st.st_mode);
  }
  if (mkdir(normalized_path.c_str(), 0755) == 0 || errno == EEXIST) {
    return true;
  }
  LogErrno("EnsureDirectoryRecursive: final mkdir failed", normalized_path);
  return false;
}

bool NormalizeArchivePath(
    const char* archive_path, std::string* out_relative_path) {
  if (archive_path == nullptr || out_relative_path == nullptr) {
    __android_log_print(
        ANDROID_LOG_ERROR, kLogTag, "NormalizeArchivePath: null input");
    return false;
  }

  std::string input(archive_path);
  while (!input.empty() && input.front() == '/') {
    input.erase(input.begin());
  }
  while (!input.empty() && input.back() == '/') {
    input.pop_back();
  }
  if (input.empty()) {
    *out_relative_path = ".";
    return true;
  }

  std::string normalized;
  size_t      start = 0;
  while (start <= input.size()) {
    const size_t      slash = input.find('/', start);
    const size_t      end   = slash == std::string::npos ? input.size() : slash;
    const std::string token = input.substr(start, end - start);
    if (!token.empty() && token != ".") {
      if (token == "..") {
        __android_log_print(ANDROID_LOG_ERROR, kLogTag,
            "NormalizeArchivePath: '..' is not allowed: %s", input.c_str());
        return false;
      }
      if (!normalized.empty()) {
        normalized.push_back('/');
      }
      normalized.append(token);
    }
    if (slash == std::string::npos) {
      break;
    }
    start = slash + 1;
  }

  if (normalized.empty()) {
    normalized = ".";
  }
  *out_relative_path = normalized;
  return true;
}

std::string ResolveRelativeSymlinkTarget(
    const std::string& link_path, const char* symlink_target) {
  if (symlink_target == nullptr || symlink_target[0] == '\0' ||
      symlink_target[0] == '/') {
    return "";
  }

  std::vector<std::string> components;
  const size_t             last_slash = link_path.rfind('/');
  const std::string        parent_path =
      last_slash == std::string::npos ? "" : link_path.substr(0, last_slash);
  size_t start = 0;
  while (start < parent_path.size()) {
    const size_t slash = parent_path.find('/', start);
    const size_t end = slash == std::string::npos ? parent_path.size() : slash;
    components.emplace_back(parent_path.substr(start, end - start));
    if (slash == std::string::npos) {
      break;
    }
    start = slash + 1;
  }

  const std::string target(symlink_target);
  start = 0;
  while (start <= target.size()) {
    const size_t      slash = target.find('/', start);
    const size_t      end = slash == std::string::npos ? target.size() : slash;
    const std::string component = target.substr(start, end - start);
    if (component == "..") {
      if (!components.empty()) {
        components.pop_back();
      }
    } else if (!component.empty() && component != ".") {
      components.emplace_back(component);
    }
    if (slash == std::string::npos) {
      break;
    }
    start = slash + 1;
  }

  std::string resolved = "/";
  for (size_t i = 0; i < components.size(); ++i) {
    if (i != 0) {
      resolved.push_back('/');
    }
    resolved.append(components[i]);
  }
  return resolved;
}

bool CopyArchiveData(struct archive* source, struct archive* destination) {
  while (true) {
    const void* buffer = nullptr;
    size_t      size   = 0;
    la_int64_t  offset = 0;
    const int   read_status =
        archive_read_data_block(source, &buffer, &size, &offset);
    if (read_status == ARCHIVE_EOF) {
      return true;
    }
    if (read_status != ARCHIVE_OK) {
      __android_log_print(ANDROID_LOG_ERROR, kLogTag,
          "archive_read_data_block failed: %s", archive_error_string(source));
      return false;
    }

    const int write_status =
        archive_write_data_block(destination, buffer, size, offset);
    if (write_status != ARCHIVE_OK) {
      __android_log_print(ANDROID_LOG_ERROR, kLogTag,
          "archive_write_data_block failed: %s",
          archive_error_string(destination));
      return false;
    }
  }
}

bool CopyFileDataToArchive(
    const std::string& source_path, struct archive* destination) {
  const int source_fd = open(source_path.c_str(), O_RDONLY | O_CLOEXEC);
  if (source_fd < 0) {
    LogErrno("CopyFileDataToArchive: open failed", source_path);
    return false;
  }

  std::vector<char> buffer(64 * 1024);
  la_int64_t        offset = 0;
  while (true) {
    const ssize_t read_size = read(source_fd, buffer.data(), buffer.size());
    if (read_size < 0) {
      if (errno == EINTR) {
        continue;
      }
      LogErrno("CopyFileDataToArchive: read failed", source_path);
      close(source_fd);
      return false;
    }
    if (read_size == 0) {
      close(source_fd);
      return true;
    }

    const int write_status = archive_write_data_block(
        destination, buffer.data(), static_cast<size_t>(read_size), offset);
    if (write_status != ARCHIVE_OK) {
      __android_log_print(ANDROID_LOG_ERROR, kLogTag,
          "CopyFileDataToArchive: write failed: %s",
          archive_error_string(destination));
      close(source_fd);
      return false;
    }
    offset += read_size;
  }
}

std::string MarkerPath(const std::string& extract_dst_path) {
  return JoinPath(extract_dst_path, kReadyMarker);
}

bool WriteExtractionMarker(const std::string& extract_dst_path) {
  const std::string marker_path = MarkerPath(extract_dst_path);
  const int         fd =
      open(marker_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
  if (fd < 0) {
    LogErrno("WriteExtractionMarker: open failed", marker_path);
    return false;
  }

  constexpr const char kMarkerContents[] = "ready\n";
  const ssize_t        written =
      write(fd, kMarkerContents, sizeof(kMarkerContents) - 1);
  close(fd);
  if (written != static_cast<ssize_t>(sizeof(kMarkerContents) - 1)) {
    LogErrno("WriteExtractionMarker: write failed", marker_path);
    return false;
  }
  return true;
}

bool EndsWith(const std::string& value, const std::string& suffix) {
  return value.size() >= suffix.size() &&
         value.compare(value.size() - suffix.size(), suffix.size(), suffix) ==
             0;
}

bool WriteAll(int fd, const void* data, size_t size) {
  const auto* bytes = static_cast<const uint8_t*>(data);
  size_t      total = 0;
  while (total < size) {
    const ssize_t written = write(fd, bytes + total, size - total);
    if (written < 0) {
      if (errno == EINTR) {
        continue;
      }
      LogErrno("WriteAll: write failed");
      return false;
    }
    total += static_cast<size_t>(written);
  }
  return true;
}

bool DecompressZstdFileToTar(
    const std::string& input_path, const std::string& output_path) {
  int in_fd = open(input_path.c_str(), O_RDONLY | O_CLOEXEC);
  if (in_fd < 0) {
    LogErrno("DecompressZstdFileToTar: open input failed", input_path);
    return false;
  }

  int out_fd =
      open(output_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
  if (out_fd < 0) {
    LogErrno("DecompressZstdFileToTar: open output failed", output_path);
    close(in_fd);
    return false;
  }

  ZSTD_DStream* stream = ZSTD_createDStream();
  if (stream == nullptr) {
    __android_log_print(ANDROID_LOG_ERROR, kLogTag,
        "DecompressZstdFileToTar: ZSTD_createDStream failed");
    close(in_fd);
    close(out_fd);
    return false;
  }
  size_t zstd_result = ZSTD_initDStream(stream);
  if (ZSTD_isError(zstd_result)) {
    __android_log_print(ANDROID_LOG_ERROR, kLogTag,
        "DecompressZstdFileToTar: ZSTD_initDStream failed: %s",
        ZSTD_getErrorName(zstd_result));
    ZSTD_freeDStream(stream);
    close(in_fd);
    close(out_fd);
    return false;
  }

  std::vector<char> in_buffer(ZSTD_DStreamInSize());
  std::vector<char> out_buffer(ZSTD_DStreamOutSize());
  bool              reached_frame_end = false;
  bool              ok                = true;

  while (ok) {
    ssize_t read_size = read(in_fd, in_buffer.data(), in_buffer.size());
    if (read_size < 0) {
      if (errno == EINTR) {
        continue;
      }
      LogErrno("DecompressZstdFileToTar: read failed", input_path);
      ok = false;
      break;
    }
    if (read_size == 0) {
      break;
    }

    ZSTD_inBuffer input{in_buffer.data(), static_cast<size_t>(read_size), 0};
    while (input.pos < input.size) {
      ZSTD_outBuffer output{out_buffer.data(), out_buffer.size(), 0};

      zstd_result = ZSTD_decompressStream(stream, &output, &input);
      if (ZSTD_isError(zstd_result)) {
        __android_log_print(ANDROID_LOG_ERROR, kLogTag,
            "DecompressZstdFileToTar: ZSTD_decompressStream failed: %s",
            ZSTD_getErrorName(zstd_result));
        ok = false;
        break;
      }
      reached_frame_end = reached_frame_end || (zstd_result == 0);

      if (output.pos > 0 && !WriteAll(out_fd, out_buffer.data(), output.pos)) {
        ok = false;
        break;
      }
    }
  }

  if (ok && !reached_frame_end) {
    __android_log_print(ANDROID_LOG_ERROR, kLogTag,
        "DecompressZstdFileToTar: truncated zstd stream: %s",
        input_path.c_str());
    ok = false;
  }

  ZSTD_freeDStream(stream);
  close(in_fd);
  close(out_fd);
  if (!ok) {
    unlink(output_path.c_str());
  }
  return ok;
}

}  // namespace

bool IsRootfsExtracted(const std::string& extract_dst_path) {
  if (extract_dst_path.empty()) {
    __android_log_print(
        ANDROID_LOG_ERROR, kLogTag, "IsRootfsExtracted: empty extract path");
    return false;
  }

  struct stat       st{};
  const std::string marker_path = MarkerPath(extract_dst_path);
  if (stat(marker_path.c_str(), &st) != 0) {
    return false;
  }
  return S_ISREG(st.st_mode);
}

bool ExtractRootfs(
    const std::string& archive_path, const std::string& extract_dst_path) {
  if (archive_path.empty() || extract_dst_path.empty()) {
    __android_log_print(ANDROID_LOG_ERROR, kLogTag,
        "ExtractRootfs: empty path(s), archive='%s', dst='%s'",
        archive_path.c_str(), extract_dst_path.c_str());
    return false;
  }

  if (!EnsureDirectoryRecursive(extract_dst_path)) {
    __android_log_print(ANDROID_LOG_ERROR, kLogTag,
        "ExtractRootfs: failed to ensure destination directory: %s",
        extract_dst_path.c_str());
    return false;
  }

  const std::string marker_path = MarkerPath(extract_dst_path);
  if (unlink(marker_path.c_str()) != 0 && errno != ENOENT) {
    LogErrno("ExtractRootfs: failed to remove marker", marker_path);
  }

  std::string       prepared_archive_path = archive_path;
  const std::string temp_tar_path =
      JoinPath(extract_dst_path, ".andlify_rootfs_tmp.tar");
  if (EndsWith(archive_path, ".zst") || EndsWith(archive_path, ".tzst")) {
    unlink(temp_tar_path.c_str());
    if (!DecompressZstdFileToTar(archive_path, temp_tar_path)) {
      __android_log_print(ANDROID_LOG_ERROR, kLogTag,
          "ExtractRootfs: zstd decompress failed, archive=%s, tempTar=%s",
          archive_path.c_str(), temp_tar_path.c_str());
      return false;
    }
    prepared_archive_path = temp_tar_path;
  }

  struct archive* archive_reader = archive_read_new();
  struct archive* archive_writer = archive_write_disk_new();
  if (archive_reader == nullptr || archive_writer == nullptr) {
    __android_log_print(ANDROID_LOG_ERROR, kLogTag,
        "ExtractRootfs: failed to allocate libarchive reader/writer");
    if (archive_reader != nullptr) {
      archive_read_free(archive_reader);
    }
    if (archive_writer != nullptr) {
      archive_write_free(archive_writer);
    }
    return false;
  }

  archive_read_support_filter_gzip(archive_reader);
  archive_read_support_format_tar(archive_reader);

  archive_write_disk_set_options(archive_writer,
      ARCHIVE_EXTRACT_TIME | ARCHIVE_EXTRACT_PERM | ARCHIVE_EXTRACT_ACL |
          ARCHIVE_EXTRACT_FFLAGS | ARCHIVE_EXTRACT_SECURE_NODOTDOT |
          ARCHIVE_EXTRACT_SECURE_SYMLINKS);
  archive_write_disk_set_standard_lookup(archive_writer);

  constexpr size_t kReadBlockSize = 10240;
  if (archive_read_open_filename(archive_reader, prepared_archive_path.c_str(),
          kReadBlockSize) != ARCHIVE_OK) {
    __android_log_print(ANDROID_LOG_ERROR, kLogTag,
        "archive_read_open_filename failed: %s",
        archive_error_string(archive_reader));
    archive_read_free(archive_reader);
    archive_write_free(archive_writer);
    if (prepared_archive_path == temp_tar_path) {
      unlink(temp_tar_path.c_str());
    }
    return false;
  }

  bool ok = true;
  while (ok) {
    archive_entry* entry    = nullptr;
    const int header_status = archive_read_next_header(archive_reader, &entry);
    if (header_status == ARCHIVE_EOF) {
      break;
    }
    if (header_status != ARCHIVE_OK) {
      __android_log_print(ANDROID_LOG_ERROR, kLogTag,
          "archive_read_next_header failed: %s",
          archive_error_string(archive_reader));
      ok = false;
      break;
    }

    std::string relative_path;
    if (!NormalizeArchivePath(archive_entry_pathname(entry), &relative_path)) {
      __android_log_print(ANDROID_LOG_ERROR, kLogTag,
          "Unsafe path in archive: %s", archive_entry_pathname(entry));
      ok = false;
      break;
    }

    std::string hardlink_source_path;
    if (const char* hardlink_target = archive_entry_hardlink(entry);
        hardlink_target != nullptr) {
      std::string relative_hardlink_path;
      if (!NormalizeArchivePath(hardlink_target, &relative_hardlink_path)) {
        __android_log_print(ANDROID_LOG_ERROR, kLogTag,
            "Unsafe hard-link target in archive: %s", hardlink_target);
        ok = false;
        break;
      }
      hardlink_source_path =
          relative_hardlink_path == "." ?
              extract_dst_path :
              JoinPath(extract_dst_path, relative_hardlink_path);

      struct stat source_stat{};
      if (stat(hardlink_source_path.c_str(), &source_stat) != 0) {
        LogErrno("ExtractRootfs: hard-link source is unavailable",
            hardlink_source_path);
        ok = false;
        break;
      }
      if (!S_ISREG(source_stat.st_mode)) {
        __android_log_print(ANDROID_LOG_ERROR, kLogTag,
            "ExtractRootfs: hard-link source is not a regular file: %s",
            hardlink_source_path.c_str());
        ok = false;
        break;
      }
      archive_entry_set_hardlink(entry, nullptr);
      archive_entry_set_size(entry, source_stat.st_size);
    }

    const std::string resolved_symlink_target = ResolveRelativeSymlinkTarget(
        relative_path, archive_entry_symlink(entry));
    if (IsPassthroughUnixPath(resolved_symlink_target)) {
      archive_entry_set_symlink(entry, resolved_symlink_target.c_str());
    }

    const std::string target_path =
        relative_path == "." ? extract_dst_path :
                               JoinPath(extract_dst_path, relative_path);
    archive_entry_set_pathname(entry, target_path.c_str());

    const int write_header_status = archive_write_header(archive_writer, entry);
    if (write_header_status < ARCHIVE_OK) {
      __android_log_print(ANDROID_LOG_ERROR, kLogTag,
          "archive_write_header warning/error: %s",
          archive_error_string(archive_writer));
    }
    if (write_header_status == ARCHIVE_OK) {
      const bool copied =
          hardlink_source_path.empty() ?
              CopyArchiveData(archive_reader, archive_writer) :
              CopyFileDataToArchive(hardlink_source_path, archive_writer);
      if (!copied) {
        ok = false;
        break;
      }
    }

    const int finish_status = archive_write_finish_entry(archive_writer);
    if (finish_status != ARCHIVE_OK) {
      __android_log_print(ANDROID_LOG_ERROR, kLogTag,
          "archive_write_finish_entry failed: %s",
          archive_error_string(archive_writer));
      ok = false;
      break;
    }
  }

  archive_read_close(archive_reader);
  archive_write_close(archive_writer);
  archive_read_free(archive_reader);
  archive_write_free(archive_writer);

  if (prepared_archive_path == temp_tar_path) {
    unlink(temp_tar_path.c_str());
  }

  if (!ok) {
    __android_log_print(ANDROID_LOG_ERROR, kLogTag,
        "ExtractRootfs: extraction loop failed, archive=%s dst=%s",
        prepared_archive_path.c_str(), extract_dst_path.c_str());
    return false;
  }
  if (!WriteExtractionMarker(extract_dst_path)) {
    __android_log_print(ANDROID_LOG_ERROR, kLogTag,
        "ExtractRootfs: failed to write marker, dst=%s",
        extract_dst_path.c_str());
    return false;
  }
  __android_log_print(ANDROID_LOG_INFO, kLogTag,
      "ExtractRootfs: success, archive=%s dst=%s", archive_path.c_str(),
      extract_dst_path.c_str());
  return true;
}
