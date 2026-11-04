#pragma once

#include <chrono>
#include <string>
#include <string_view>

namespace smithproxy::gui {

enum class LogLevel {
    Info,
    Warning,
    Error,
};

[[nodiscard]] std::string format_log_timestamp(
    std::chrono::system_clock::time_point timestamp);
[[nodiscard]] std::string format_log_line(
    LogLevel level,
    std::string_view message,
    std::chrono::system_clock::time_point timestamp);
void write_log(LogLevel level, std::string_view message);

}
