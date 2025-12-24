#include "common.h"
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>

#if defined(_WIN32)
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #include <arpa/inet.h>
#endif

namespace util {

std::string trim(const std::string& s) {
  size_t a = 0, b = s.size();
  while (a < b && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n')) a++;
  while (b > a && (s[b-1] == ' ' || s[b-1] == '\t' || s[b-1] == '\r' || s[b-1] == '\n')) b--;
  return s.substr(a, b - a);
}

bool starts_with(const std::string& s, const std::string& prefix) {
  return s.size() >= prefix.size() && std::equal(prefix.begin(), prefix.end(), s.begin());
}

std::string to_lower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return (char)std::tolower(c); });
  return s;
}

bool ensure_dir(const std::string& path) {
  std::error_code ec;
  if (path.empty()) return false;
  std::filesystem::path p(path);
  if (std::filesystem::exists(p, ec)) return std::filesystem::is_directory(p, ec);
  return std::filesystem::create_directories(p, ec);
}

bool file_exists(const std::string& path) {
  std::error_code ec;
  return std::filesystem::exists(std::filesystem::path(path), ec);
}

std::string ip_to_string(uint32_t ipv4_be) {
  char buf[INET_ADDRSTRLEN] = {0};
  in_addr a;
  std::memcpy(&a, &ipv4_be, sizeof(a));
  const char* r = inet_ntop(AF_INET, &a, buf, sizeof(buf));
  return r ? std::string(r) : std::string("0.0.0.0");
}

uint32_t parse_ipv4_be(const std::string& s, bool* ok) {
  in_addr a;
  int rc = inet_pton(AF_INET, s.c_str(), &a);
  if (ok) *ok = (rc == 1);
  if (rc != 1) return 0;
  uint32_t be = 0;
  std::memcpy(&be, &a, sizeof(be));
  return be;
}

std::string iso8601_utc(double epoch_seconds) {
  using namespace std::chrono;
  auto sec = (time_t)epoch_seconds;
  std::tm tm{};
#if defined(_WIN32)
  gmtime_s(&tm, &sec);
#else
  gmtime_r(&sec, &tm);
#endif
  std::ostringstream os;
  os << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
  return os.str();
}

std::string json_escape(const std::string& s) {
  std::ostringstream o;
  for (unsigned char c : s) {
    switch (c) {
      case '\\': o << "\\\\"; break;
      case '"':  o << "\\\""; break;
      case '\b': o << "\\b";  break;
      case '\f': o << "\\f";  break;
      case '\n': o << "\\n";  break;
      case '\r': o << "\\r";  break;
      case '\t': o << "\\t";  break;
      default:
        if (c < 0x20) {
          o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)c << std::dec;
        } else {
          o << (char)c;
        }
    }
  }
  return o.str();
}

std::vector<std::string> read_lines(const std::string& path, std::string* err) {
  std::ifstream in(path);
  if (!in) {
    if (err) *err = "Failed to open file: " + path + " (" + std::strerror(errno) + ")";
    return {};
  }
  std::vector<std::string> lines;
  std::string line;
  while (std::getline(in, line)) {
    line = trim(line);
    if (line.empty()) continue;
    if (!line.empty() && line[0] == '#') continue;
    lines.push_back(line);
  }
  return lines;
}

} // namespace util
