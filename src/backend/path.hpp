#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

namespace smithproxy::gui {

std::optional<std::string> normalize_base_path(std::string_view path);
std::optional<std::string> path_below_base(std::string_view request_path, std::string_view base_path);
std::optional<std::filesystem::path> safe_asset_path(
    const std::filesystem::path& root, std::string_view request_path);

// Accept only logical resource names owned by the native CFtar manifest.
bool valid_archive_resource_path(std::string_view path) noexcept;

} // namespace smithproxy::gui
