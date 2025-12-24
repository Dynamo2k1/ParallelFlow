#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <optional>

namespace util {

std::string trim(const std::string& s);
bool starts_with(const std::string& s, const std::string& prefix);

std::string to_lower(std::string s);

bool ensure_dir(const std::string& path);
bool file_exists(const std::string& path);

std::string ip_to_string(uint32_t ipv4_be); // input is IPv4 in network byte order
uint32_t parse_ipv4_be(const std::string& s, bool* ok);

std::string iso8601_utc(double epoch_seconds);

std::string json_escape(const std::string& s);

std::vector<std::string> read_lines(const std::string& path, std::string* err);

} // namespace util
