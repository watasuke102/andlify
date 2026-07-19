#pragma once

#include <string>

bool IsRootfsExtracted(const std::string& extract_dst_path);
bool ExtractRootfs(
    const std::string& archive_path, const std::string& extract_dst_path);
