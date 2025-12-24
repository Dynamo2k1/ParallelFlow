#include "scanner.h"
#include "common.h"
#include <array>
#include <cmath>
#include <cstring>
#include <sstream>

#if defined(_WIN32)
  #include <winsock2.h>
#else
  #include <arpa/inet.h>
#endif

static inline uint32_t hash16(uint16_t x) {
  // simple mix; good enough for sketching
  uint32_t v = x;
  v ^= v >> 7;
  v *= 0x9E3779B1u;
  v ^= v >> 11;
  return v;
}

bool AlertWriter::open(const std::string& path, std::string* err) {
  out.open(path, std::ios::out | std::ios::binary | std::ios::trunc);
  if (!out) {
    if (err) *err = "Failed to open alerts file: " + path;
    return false;
  }
  return true;
}

void AlertWriter::close() {
  if (out.is_open()) out.close();
}

void AlertWriter::write_alert(double ts, const std::string& type,
                              uint32_t src_ip_be, uint32_t dst_ip_be,
                              const std::string& proto,
                              uint16_t src_port, uint16_t dst_port,
                              const std::string& detail) {
  if (!out || !can_write_more()) return;
  std::ostringstream os;
  os.setf(std::ios::fixed); os.precision(6);
  os << "{"
     << "\"ts\":" << ts << ","
     << "\"time\":\"" << util::iso8601_utc(ts) << "\","
     << "\"type\":\"" << util::json_escape(type) << "\","
     << "\"src_ip\":\"" << util::ip_to_string(src_ip_be) << "\","
     << "\"dst_ip\":\"" << util::ip_to_string(dst_ip_be) << "\","
     << "\"proto\":\"" << util::json_escape(proto) << "\","
     << "\"src_port\":" << (unsigned)src_port << ","
     << "\"dst_port\":" << (unsigned)dst_port << ","
     << "\"detail\":\"" << util::json_escape(detail) << "\""
     << "}\n";
  out << os.str();
  written++;
}

Scanner::Scanner(const ScanConfig& c, IocLists lists) : cfg(c), iocs(std::move(lists)) {
  if (!iocs.keywords.empty()) {
    ac.build(iocs.keywords);
  }
}

static const char* proto_name(L4Proto p) {
  switch (p) {
    case L4Proto::TCP: return "TCP";
    case L4Proto::UDP: return "UDP";
    case L4Proto::ICMP: return "ICMP";
    default: return "OTHER";
  }
}

void Scanner::process_packet(const PacketView& pv, size_t raw_len, AlertWriter& alerts, LocalResults& res) {
  res.ctr.packets++;
  res.ctr.bytes += raw_len;
  if (pv.ipv4) res.ctr.ipv4++;

  if (pv.l4 == L4Proto::TCP) res.ctr.tcp++;
  else if (pv.l4 == L4Proto::UDP) res.ctr.udp++;
  else if (pv.l4 == L4Proto::ICMP) res.ctr.icmp++;
  else res.ctr.other++;

  // Heavy hitters by bytes
  res.top_src_bytes.add(pv.src_ip_be, (uint64_t)raw_len);
  res.top_dst_bytes.add(pv.dst_ip_be, (uint64_t)raw_len);

  // IOC checks: IP blocklist
  if (ip_is_blocklisted(pv.src_ip_be, iocs) || ip_is_blocklisted(pv.dst_ip_be, iocs)) {
    res.ctr.alerts++;
    res.ctr.alerts_ip++;
    alerts.write_alert(pv.ts_epoch, "blocklisted_ip",
                       pv.src_ip_be, pv.dst_ip_be, proto_name(pv.l4),
                       pv.src_port, pv.dst_port,
                       "Matched IP blocklist (src or dst)");
  }

  // DNS domain IOC
  if (!pv.dns_qname_lower.empty()) {
    res.top_dns_qnames.add(pv.dns_qname_lower, 1);
    if (domain_is_blocklisted(pv.dns_qname_lower, iocs)) {
      res.ctr.alerts++;
      res.ctr.alerts_domain++;
      alerts.write_alert(pv.ts_epoch, "blocklisted_domain",
                         pv.src_ip_be, pv.dst_ip_be, proto_name(pv.l4),
                         pv.src_port, pv.dst_port,
                         "Matched domain blocklist: " + pv.dns_qname_lower);
    }
  }

  // Keyword match (payload)
  if (ac.built() && pv.payload && pv.payload_len > 0 && cfg.payload_max > 0) {
    size_t n = pv.payload_len;
    if ((int)n > cfg.payload_max) n = (size_t)cfg.payload_max;
    auto matches = ac.search(pv.payload, n, 1); // stop after 1 match (fast)
    if (!matches.empty()) {
      int id = matches[0].keyword_id;
      const auto& kw = ac.keywords()[id];
      res.ctr.alerts++;
      res.ctr.alerts_keyword++;
      alerts.write_alert(pv.ts_epoch, "keyword_match",
                         pv.src_ip_be, pv.dst_ip_be, proto_name(pv.l4),
                         pv.src_port, pv.dst_port,
                         "Matched keyword: " + kw);
    }
  }

  // Port-scan heuristic: TCP SYN/UDP to many ports (approx)
  if ((pv.l4 == L4Proto::TCP || pv.l4 == L4Proto::UDP) && pv.dst_port != 0) {
    uint64_t tsec = (uint64_t)pv.ts_epoch;
    auto& w = port_windows[pv.src_ip_be];
    if (!w.init) {
      w.init = true;
      w.window_start_sec = tsec;
      w.bits.fill(0);
    }
    if (tsec >= w.window_start_sec + (uint64_t)cfg.portscan_window_seconds) {
      // reset window
      w.window_start_sec = tsec;
      w.bits.fill(0);
    }
    uint32_t h = hash16(pv.dst_port) & 2047u;
    size_t idx = (size_t)h / 64;
    uint64_t mask = 1ull << (h % 64);
    w.bits[idx] |= mask;

    // Compute approx distinct via popcount of bits (2048 bits)
    // This is not super cheap but acceptable; optimization: compute every N packets per src.
    uint32_t pop = 0;
    for (uint64_t b : w.bits) pop += (uint32_t)__builtin_popcountll(b);

    if ((int)pop >= cfg.portscan_threshold) {
      // record suspect score (max)
      auto it = res.portscan_suspects.find(pv.src_ip_be);
      if (it == res.portscan_suspects.end() || it->second < pop) res.portscan_suspects[pv.src_ip_be] = pop;

      // Only write alert once per window per src (throttle)
      // Use a simple trick: set threshold a bit higher for repeated writes by masking bit 0 -> ensure stable.
      if (pop == (uint32_t)cfg.portscan_threshold) {
        res.ctr.alerts++;
        res.ctr.alerts_portscan++;
        alerts.write_alert(pv.ts_epoch, "port_scan_suspected",
                           pv.src_ip_be, pv.dst_ip_be, proto_name(pv.l4),
                           pv.src_port, pv.dst_port,
                           "Approx distinct dst ports in window >= " + std::to_string(cfg.portscan_threshold));
      }
    }
  }
}
