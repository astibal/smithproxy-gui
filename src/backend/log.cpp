#include "log.hpp"

#include <array>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>

namespace smithproxy::gui {
namespace {

std::mutex log_mutex;

[[nodiscard]] std::string_view level_name(LogLevel level) {
    switch (level) {
        case LogLevel::Info: return "INFO";
        case LogLevel::Warning: return "WARNING";
        case LogLevel::Error: return "ERROR";
    }
    return "UNKNOWN";
}

[[nodiscard]] std::string timezone_offset(const std::tm& local_time) {
    std::array<char, 8> raw_offset{};
    if (std::strftime(raw_offset.data(), raw_offset.size(), "%z", &local_time) == 0U) {
        return "+00:00";
    }

    const std::string compact{raw_offset.data()};
    if (compact.size() != 5U) return "+00:00";
    return compact.substr(0U, 3U) + ':' + compact.substr(3U, 2U);
}

}

std::string format_log_timestamp(std::chrono::system_clock::time_point timestamp) {
    const auto seconds = std::chrono::time_point_cast<std::chrono::seconds>(timestamp);
    const auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(
        timestamp - seconds);
    const auto time = std::chrono::system_clock::to_time_t(timestamp);
    std::tm local_time{};
    localtime_r(&time, &local_time);

    std::array<char, 24> date_time{};
    if (std::strftime(
            date_time.data(), date_time.size(), "%Y-%m-%dT%H:%M:%S", &local_time) == 0U) {
        return "1970-01-01T00:00:00.000+00:00";
    }

    std::ostringstream result;
    result << date_time.data() << '.' << std::setfill('0') << std::setw(3)
           << milliseconds.count() << timezone_offset(local_time);
    return result.str();
}

std::string format_log_line(
    LogLevel level,
    std::string_view message,
    std::chrono::system_clock::time_point timestamp) {
    return format_log_timestamp(timestamp) + ' ' + std::string{level_name(level)} + ' ' +
           std::string{message};
}

void write_log(LogLevel level, std::string_view message) {
    const auto timestamp = std::chrono::system_clock::now();
    std::scoped_lock lock{log_mutex};

    std::size_t start = 0U;
    do {
        const auto end = message.find('\n', start);
        const auto line = message.substr(
            start, end == std::string_view::npos ? message.size() - start : end - start);
        std::cerr << format_log_line(level, line, timestamp) << '\n';
        if (end == std::string_view::npos) break;
        start = end + 1U;
    } while (start < message.size());
}

}
