#pragma once
#include <string>
#include <vector>
#include <optional>
#include <cstdint>

struct ScanConfig {
  std::string pcap_path;
  std::string out_dir;

  std::string ip_blocklist_path;
  std::string domain_blocklist_path;
  std::string keywords_path;

  int top_k = 50;
  int payload_max = 512;          // bytes scanned for keywords
  int portscan_threshold = 64;    // approx distinct ports in window -> alert
  int portscan_window_seconds = 10;
  int max_alerts_per_rank = 0;    // 0 = unlimited (be careful with RAM), recommended: 200000

  bool enable_openmp = false;
};

struct ArgParseResult {
  bool ok = false;
  std::string error;
  ScanConfig cfg;
};

ArgParseResult parse_args(int argc, char** argv);
std::string usage();
