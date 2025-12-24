#pragma once
#include "args.h"
#include "ioc.h"
#include "aho_corasick.h"
#include "pcap_decode.h"
#include "space_saving.h"
#include <cstdint>
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>

struct LocalCounters {
  uint64_t packets = 0;
  uint64_t bytes = 0;
  uint64_t ipv4 = 0;
  uint64_t tcp = 0;
  uint64_t udp = 0;
  uint64_t icmp = 0;
  uint64_t other = 0;

  uint64_t alerts = 0;
  uint64_t alerts_ip = 0;
  uint64_t alerts_domain = 0;
  uint64_t alerts_keyword = 0;
  uint64_t alerts_portscan = 0;
};

struct PortSketchWindow {
  // approximate distinct dest ports using 2048-bit sketch (hash(port) -> bit)
  uint64_t window_start_sec = 0;
  std::array<uint64_t, 32> bits{}; // 32*64 = 2048
  bool init = false;
};

struct LocalResults {
  LocalCounters ctr;
  SpaceSaving<uint32_t, uint64_t> top_src_bytes;
  SpaceSaving<uint32_t, uint64_t> top_dst_bytes;
  SpaceSaving<std::string, uint64_t> top_dns_qnames;

  // candidates (only suspicious) (src ip -> score)
  std::unordered_map<uint32_t, uint32_t> portscan_suspects;

  explicit LocalResults(int top_k)
    : top_src_bytes((size_t)top_k),
      top_dst_bytes((size_t)top_k),
      top_dns_qnames((size_t)top_k) {}
};

struct AlertWriter {
  std::ofstream out;
  uint64_t written = 0;
  int max_alerts = 0; // 0 unlimited

  bool open(const std::string& path, std::string* err);
  void close();
  bool can_write_more() const { return max_alerts == 0 || (int)written < max_alerts; }

  void write_alert(double ts, const std::string& type,
                   uint32_t src_ip_be, uint32_t dst_ip_be,
                   const std::string& proto,
                   uint16_t src_port, uint16_t dst_port,
                   const std::string& detail);
};

struct Scanner {
  ScanConfig cfg;
  IocLists iocs;
  AhoCorasick ac;

  std::unordered_map<uint32_t, PortSketchWindow> port_windows;

  explicit Scanner(const ScanConfig& c, IocLists lists);

  void process_packet(const PacketView& pv, size_t raw_len, AlertWriter& alerts, LocalResults& res);
};
