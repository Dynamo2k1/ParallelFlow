#include "ext_scanner.h"
#include "common.h"
#include <algorithm>
#include <cmath>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <regex>

#if defined(_WIN32)
  #include <winsock2.h>
#else
  #include <arpa/inet.h>
#endif

// Payload extraction configuration constants
static constexpr size_t PAYLOAD_MAX_SCAN_SIZE = 2048;    // Max payload bytes to scan for strings
static constexpr size_t PAYLOAD_MAX_STRINGS = 20;        // Max number of strings to extract per packet
static constexpr size_t PAYLOAD_HEX_PREVIEW_SIZE = 64;   // Size of hex preview in bytes

static inline uint32_t hash16(uint16_t x) {
    uint32_t v = x;
    v ^= v >> 7;
    v *= 0x9E3779B1u;
    v ^= v >> 11;
    return v;
}

bool ExtAlertWriter::open(const std::string& path, std::string* err) {
    out.open(path, std::ios::out | std::ios::binary | std::ios::trunc);
    if (!out) {
        if (err) *err = "Failed to open alerts file: " + path;
        return false;
    }
    return true;
}

void ExtAlertWriter::close() {
    if (out.is_open()) out.close();
}

void ExtAlertWriter::write_alert(double ts, AlertType type,
                                 const std::string& src_ip, const std::string& dst_ip,
                                 const std::string& proto,
                                 uint16_t src_port, uint16_t dst_port,
                                 const std::string& detail,
                                 const std::string& extra_json) {
    if (!out || !can_write_more()) return;
    
    std::ostringstream os;
    os.setf(std::ios::fixed);
    os.precision(6);
    os << "{"
       << "\"ts\":" << ts << ","
       << "\"time\":\"" << util::iso8601_utc(ts) << "\","
       << "\"type\":\"" << alert_type_str(type) << "\","
       << "\"src_ip\":\"" << util::json_escape(src_ip) << "\","
       << "\"dst_ip\":\"" << util::json_escape(dst_ip) << "\","
       << "\"proto\":\"" << util::json_escape(proto) << "\","
       << "\"src_port\":" << (unsigned)src_port << ","
       << "\"dst_port\":" << (unsigned)dst_port << ","
       << "\"detail\":\"" << util::json_escape(detail) << "\"";
    
    if (!extra_json.empty()) {
        os << "," << extra_json;
    }
    
    os << "}\n";
    out << os.str();
    written++;
}

bool ProtocolLogWriter::open(const std::string& base_dir) {
    dns_log.open(base_dir + "/dns.jsonl", std::ios::out | std::ios::binary | std::ios::trunc);
    http_log.open(base_dir + "/http.jsonl", std::ios::out | std::ios::binary | std::ios::trunc);
    tls_log.open(base_dir + "/tls.jsonl", std::ios::out | std::ios::binary | std::ios::trunc);
    payload_log.open(base_dir + "/payload.jsonl", std::ios::out | std::ios::binary | std::ios::trunc);
    return dns_log && http_log && tls_log && payload_log;
}

void ProtocolLogWriter::close() {
    if (dns_log.is_open()) dns_log.close();
    if (http_log.is_open()) http_log.close();
    if (tls_log.is_open()) tls_log.close();
    if (payload_log.is_open()) payload_log.close();
}

void ProtocolLogWriter::write_dns(double ts, const ExtPacketView& pv, 
                                  const std::string& src, const std::string& dst) {
    if (!dns_log) return;
    
    std::ostringstream os;
    os.setf(std::ios::fixed);
    os.precision(6);
    os << "{\"ts\":" << ts
       << ",\"src\":\"" << src << ":" << pv.src_port << "\""
       << ",\"dst\":\"" << dst << ":" << pv.dst_port << "\""
       << ",\"queries\":[";
    for (size_t i = 0; i < pv.dns_queries.size(); i++) {
        if (i > 0) os << ",";
        os << "\"" << util::json_escape(pv.dns_queries[i]) << "\"";
    }
    os << "],\"answers\":[";
    for (size_t i = 0; i < pv.dns_answers.size(); i++) {
        if (i > 0) os << ",";
        os << "\"" << util::json_escape(pv.dns_answers[i]) << "\"";
    }
    os << "]}\n";
    dns_log << os.str();
}

void ProtocolLogWriter::write_http(double ts, const ExtPacketView& pv,
                                   const std::string& src, const std::string& dst) {
    if (!http_log) return;
    
    std::ostringstream os;
    os.setf(std::ios::fixed);
    os.precision(6);
    os << "{\"ts\":" << ts
       << ",\"src\":\"" << src << ":" << pv.src_port << "\""
       << ",\"dst\":\"" << dst << ":" << pv.dst_port << "\"";
    
    if (!pv.http_method.empty()) {
        os << ",\"method\":\"" << util::json_escape(pv.http_method) << "\"";
    }
    if (!pv.http_uri.empty()) {
        os << ",\"uri\":\"" << util::json_escape(pv.http_uri) << "\"";
    }
    if (!pv.http_host.empty()) {
        os << ",\"host\":\"" << util::json_escape(pv.http_host) << "\"";
    }
    if (pv.http_status_code > 0) {
        os << ",\"status\":" << pv.http_status_code;
    }
    if (!pv.http_content_type.empty()) {
        os << ",\"content_type\":\"" << util::json_escape(pv.http_content_type) << "\"";
    }
    
    os << "}\n";
    http_log << os.str();
}

void ProtocolLogWriter::write_tls(double ts, const ExtPacketView& pv,
                                  const std::string& src, const std::string& dst) {
    if (!tls_log) return;
    
    std::ostringstream os;
    os.setf(std::ios::fixed);
    os.precision(6);
    os << "{\"ts\":" << ts
       << ",\"src\":\"" << src << ":" << pv.src_port << "\""
       << ",\"dst\":\"" << dst << ":" << pv.dst_port << "\""
       << ",\"version\":" << pv.tls_version;
    
    if (!pv.tls_sni.empty()) {
        os << ",\"sni\":\"" << util::json_escape(pv.tls_sni) << "\"";
    }
    if (!pv.tls_ja3.empty()) {
        os << ",\"ja3\":\"" << pv.tls_ja3 << "\"";
    }
    if (!pv.tls_alpn.empty()) {
        os << ",\"alpn\":[";
        for (size_t i = 0; i < pv.tls_alpn.size(); i++) {
            if (i > 0) os << ",";
            os << "\"" << util::json_escape(pv.tls_alpn[i]) << "\"";
        }
        os << "]";
    }
    
    os << "}\n";
    tls_log << os.str();
}

// Helper function to extract printable strings from binary data
static std::vector<std::string> extract_strings(const uint8_t* data, size_t len, size_t min_len = 4) {
    std::vector<std::string> strings;
    std::string current;
    
    for (size_t i = 0; i < len; i++) {
        unsigned char c = data[i];
        // Printable ASCII characters (including space, tab, newline)
        if ((c >= 0x20 && c < 0x7F) || c == '\t' || c == '\n' || c == '\r') {
            current += (char)c;
        } else {
            if (current.length() >= min_len) {
                // Trim whitespace
                size_t start = current.find_first_not_of(" \t\r\n");
                size_t end = current.find_last_not_of(" \t\r\n");
                if (start != std::string::npos && end != std::string::npos) {
                    std::string trimmed = current.substr(start, end - start + 1);
                    if (trimmed.length() >= min_len) {
                        strings.push_back(trimmed);
                    }
                }
            }
            current.clear();
        }
    }
    // Don't forget the last string
    if (current.length() >= min_len) {
        size_t start = current.find_first_not_of(" \t\r\n");
        size_t end = current.find_last_not_of(" \t\r\n");
        if (start != std::string::npos && end != std::string::npos) {
            std::string trimmed = current.substr(start, end - start + 1);
            if (trimmed.length() >= min_len) {
                strings.push_back(trimmed);
            }
        }
    }
    
    return strings;
}

// Get protocol name as string
static std::string get_proto_name(L4Proto proto) {
    switch (proto) {
        case L4Proto::TCP: return "TCP";
        case L4Proto::UDP: return "UDP";
        case L4Proto::ICMP: return "ICMP";
        case L4Proto::ICMPV6: return "ICMPv6";
        default: return "OTHER";
    }
}

void ProtocolLogWriter::write_payload(double ts, const ExtPacketView& pv,
                                      const std::string& src, const std::string& dst) {
    if (!payload_log) return;
    if (!pv.payload || pv.payload_len == 0) return;
    
    // Extract printable strings from payload
    auto strings = extract_strings(pv.payload, std::min(pv.payload_len, PAYLOAD_MAX_SCAN_SIZE), 4);
    
    // Only log if we found some strings
    if (strings.empty()) return;
    
    std::ostringstream os;
    os.setf(std::ios::fixed);
    os.precision(6);
    os << "{\"ts\":" << ts
       << ",\"src\":\"" << src << ":" << pv.src_port << "\""
       << ",\"dst\":\"" << dst << ":" << pv.dst_port << "\""
       << ",\"proto\":\"" << get_proto_name(pv.l4) << "\""
       << ",\"payload_len\":" << pv.payload_len;
    
    // Add ICMP-specific info
    if (pv.l4 == L4Proto::ICMP || pv.l4 == L4Proto::ICMPV6) {
        os << ",\"icmp_type\":" << (int)pv.icmp_type
           << ",\"icmp_code\":" << (int)pv.icmp_code;
    }
    
    // Add extracted strings (limited to PAYLOAD_MAX_STRINGS)
    os << ",\"strings\":[";
    for (size_t i = 0; i < strings.size() && i < PAYLOAD_MAX_STRINGS; i++) {
        if (i > 0) os << ",";
        os << "\"" << util::json_escape(strings[i]) << "\"";
    }
    os << "]";
    
    // Add hex preview of first PAYLOAD_HEX_PREVIEW_SIZE bytes
    os << ",\"hex_preview\":\"";
    for (size_t i = 0; i < std::min(pv.payload_len, PAYLOAD_HEX_PREVIEW_SIZE); i++) {
        char hex[4];
        snprintf(hex, sizeof(hex), "%02x", pv.payload[i]);
        os << hex;
    }
    os << "\"}\n";
    
    payload_log << os.str();
}

ExtScanner::ExtScanner(const ExtScanConfig& c, IocLists iocs_)
    : cfg(c), iocs(std::move(iocs_)) {
    if (!iocs.keywords.empty()) {
        ac.build(iocs.keywords);
    }
}

std::string ExtScanner::ip_to_str(const ExtPacketView& pv, bool src) {
    if (pv.is_ipv4) {
        return util::ip_to_string(src ? pv.src_ip4_be : pv.dst_ip4_be);
    } else if (pv.is_ipv6) {
        return ipv6_to_string(src ? pv.src_ip6 : pv.dst_ip6);
    }
    return "";
}

bool ExtScanner::is_private_ip(uint32_t ip_be) {
    uint32_t ip = ntohl(ip_be);
    // 10.0.0.0/8
    if ((ip & 0xFF000000) == 0x0A000000) return true;
    // 172.16.0.0/12
    if ((ip & 0xFFF00000) == 0xAC100000) return true;
    // 192.168.0.0/16
    if ((ip & 0xFFFF0000) == 0xC0A80000) return true;
    // 127.0.0.0/8
    if ((ip & 0xFF000000) == 0x7F000000) return true;
    return false;
}

double ExtScanner::compute_entropy(const std::string& s) {
    if (s.empty()) return 0.0;
    
    int freq[256] = {0};
    for (unsigned char c : s) freq[c]++;
    
    double entropy = 0.0;
    double n = (double)s.size();
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / n;
            entropy -= p * std::log2(p);
        }
    }
    return entropy;
}

std::string ExtScanner::redact(const std::string& s) {
    if (!cfg.redact_secrets || s.empty()) return s;
    if (s.size() <= 4) return std::string(s.size(), '*');
    return s.substr(0, 2) + std::string(s.size() - 4, '*') + s.substr(s.size() - 2);
}

void ExtScanner::process_packet(const ExtPacketView& pv, size_t raw_len,
                                ExtAlertWriter& alerts, ExtLocalResults& res,
                                ProtocolLogWriter* proto_logs) {
    res.ctr.packets++;
    res.ctr.bytes += raw_len;
    
    // Protocol counters
    if (pv.is_ipv4) res.ctr.ipv4++;
    if (pv.is_ipv6) res.ctr.ipv6++;
    if (pv.is_arp) res.ctr.arp++;
    
    if (pv.l4 == L4Proto::TCP) res.ctr.tcp++;
    else if (pv.l4 == L4Proto::UDP) res.ctr.udp++;
    else if (pv.l4 == L4Proto::ICMP) res.ctr.icmp++;
    else if (pv.l4 == L4Proto::ICMPV6) res.ctr.icmpv6++;
    else res.ctr.other++;
    
    // Protocol-specific counters
    if (pv.is_dns) res.ctr.dns_queries++;
    if (pv.is_http && !pv.http_method.empty()) res.ctr.http_requests++;
    if (pv.is_tls) res.ctr.tls_handshakes++;
    if (pv.is_dhcp) res.ctr.dhcp_messages++;
    
    // Heavy hitters (IPv4 only for simplicity)
    if (pv.is_ipv4) {
        res.top_src_bytes.add(pv.src_ip4_be, (uint64_t)raw_len);
        res.top_dst_bytes.add(pv.dst_ip4_be, (uint64_t)raw_len);
    }
    
    // Application-specific top-k
    if (!pv.dns_qname_lower.empty()) {
        res.top_dns_qnames.add(pv.dns_qname_lower, 1);
    }
    if (!pv.http_host.empty()) {
        res.top_http_hosts.add(pv.http_host, 1);
    }
    if (!pv.tls_sni.empty()) {
        res.top_tls_sni.add(pv.tls_sni, 1);
    }
    
    // Security checks
    check_ioc_ip(pv, alerts, res);
    check_ioc_domain(pv, alerts, res);
    check_keyword(pv, alerts, res);
    check_portscan(pv, alerts, res);
    check_dns_tunnel(pv, alerts, res);
    check_beaconing(pv, alerts, res);
    check_exfil(pv, alerts, res);
    check_sensitive_data(pv, alerts, res);
    
    // Flow tracking
    update_flow(pv, raw_len, res);
    
    // File carving
    if (cfg.enable_carving && pv.is_http && pv.http_status_code >= 200 && 
        pv.http_status_code < 300 && pv.http_body_len > 0) {
        carve_file(pv, res);
    }
    
    // Protocol logging
    if (proto_logs) {
        std::string src = ip_to_str(pv, true);
        std::string dst = ip_to_str(pv, false);
        
        if (pv.is_dns) proto_logs->write_dns(pv.ts_epoch, pv, src, dst);
        if (pv.is_http) proto_logs->write_http(pv.ts_epoch, pv, src, dst);
        if (pv.is_tls) proto_logs->write_tls(pv.ts_epoch, pv, src, dst);
        
        // Log payload data for ICMP and other protocols with payloads
        // Skip known protocols that have dedicated logs
        if (!pv.is_dns && !pv.is_http && !pv.is_tls && !pv.is_dhcp && 
            pv.payload && pv.payload_len > 0) {
            proto_logs->write_payload(pv.ts_epoch, pv, src, dst);
        }
    }
}

void ExtScanner::check_ioc_ip(const ExtPacketView& pv, ExtAlertWriter& alerts, ExtLocalResults& res) {
    if (!pv.is_ipv4) return;
    
    bool src_blocked = ip_is_blocklisted(pv.src_ip4_be, iocs);
    bool dst_blocked = ip_is_blocklisted(pv.dst_ip4_be, iocs);
    
    if (src_blocked || dst_blocked) {
        res.ctr.alerts++;
        res.ctr.alerts_ip++;
        
        std::string detail = "Matched IP blocklist";
        if (src_blocked) detail += " (src: " + util::ip_to_string(pv.src_ip4_be) + ")";
        if (dst_blocked) detail += " (dst: " + util::ip_to_string(pv.dst_ip4_be) + ")";
        
        alerts.write_alert(pv.ts_epoch, AlertType::BlocklistedIP,
                          ip_to_str(pv, true), ip_to_str(pv, false),
                          pv.l4 == L4Proto::TCP ? "TCP" : "UDP",
                          pv.src_port, pv.dst_port, detail);
    }
}

void ExtScanner::check_ioc_domain(const ExtPacketView& pv, ExtAlertWriter& alerts, ExtLocalResults& res) {
    std::vector<std::string> domains_to_check;
    
    if (!pv.dns_qname_lower.empty()) {
        domains_to_check.push_back(pv.dns_qname_lower);
    }
    if (!pv.http_host.empty()) {
        domains_to_check.push_back(util::to_lower(pv.http_host));
    }
    if (!pv.tls_sni.empty()) {
        domains_to_check.push_back(util::to_lower(pv.tls_sni));
    }
    
    for (const auto& domain : domains_to_check) {
        if (domain_is_blocklisted(domain, iocs)) {
            res.ctr.alerts++;
            res.ctr.alerts_domain++;
            
            alerts.write_alert(pv.ts_epoch, AlertType::BlocklistedDomain,
                              ip_to_str(pv, true), ip_to_str(pv, false),
                              pv.l4 == L4Proto::TCP ? "TCP" : "UDP",
                              pv.src_port, pv.dst_port,
                              "Matched domain blocklist: " + domain);
            break;
        }
    }
}

void ExtScanner::check_keyword(const ExtPacketView& pv, ExtAlertWriter& alerts, ExtLocalResults& res) {
    if (!ac.built() || !pv.payload || pv.payload_len == 0 || cfg.payload_max <= 0) return;
    
    size_t n = std::min(pv.payload_len, (size_t)cfg.payload_max);
    auto matches = ac.search(pv.payload, n, 1);
    
    if (!matches.empty()) {
        int id = matches[0].keyword_id;
        const auto& kw = ac.keywords()[id];
        res.ctr.alerts++;
        res.ctr.alerts_keyword++;
        
        alerts.write_alert(pv.ts_epoch, AlertType::KeywordMatch,
                          ip_to_str(pv, true), ip_to_str(pv, false),
                          pv.l4 == L4Proto::TCP ? "TCP" : "UDP",
                          pv.src_port, pv.dst_port,
                          "Matched keyword: " + kw);
    }
}

void ExtScanner::check_portscan(const ExtPacketView& pv, ExtAlertWriter& alerts, ExtLocalResults& res) {
    if (!pv.is_ipv4) return;
    if (pv.l4 != L4Proto::TCP && pv.l4 != L4Proto::UDP) return;
    if (pv.dst_port == 0) return;
    
    uint64_t tsec = (uint64_t)pv.ts_epoch;
    auto& w = port_windows[pv.src_ip4_be];
    
    if (!w.init) {
        w.init = true;
        w.window_start_sec = tsec;
        w.bits.fill(0);
    }
    
    if (tsec >= w.window_start_sec + (uint64_t)cfg.portscan_window_seconds) {
        w.window_start_sec = tsec;
        w.bits.fill(0);
    }
    
    uint32_t h = hash16(pv.dst_port) & 2047u;
    size_t idx = (size_t)h / 64;
    uint64_t mask = 1ull << (h % 64);
    w.bits[idx] |= mask;
    
    uint32_t pop = 0;
    for (uint64_t b : w.bits) pop += (uint32_t)__builtin_popcountll(b);
    
    if ((int)pop >= cfg.portscan_threshold) {
        auto it = res.portscan_suspects.find(pv.src_ip4_be);
        if (it == res.portscan_suspects.end() || it->second < pop) {
            res.portscan_suspects[pv.src_ip4_be] = pop;
        }
        
        if (pop == (uint32_t)cfg.portscan_threshold) {
            res.ctr.alerts++;
            res.ctr.alerts_portscan++;
            
            alerts.write_alert(pv.ts_epoch, AlertType::PortScan,
                              ip_to_str(pv, true), ip_to_str(pv, false),
                              pv.l4 == L4Proto::TCP ? "TCP" : "UDP",
                              pv.src_port, pv.dst_port,
                              "Approx distinct dst ports in window >= " + 
                              std::to_string(cfg.portscan_threshold));
        }
    }
}

void ExtScanner::check_dns_tunnel(const ExtPacketView& pv, ExtAlertWriter& alerts, ExtLocalResults& res) {
    if (!pv.is_dns || pv.dns_qname_lower.empty()) return;
    
    const std::string& qname = pv.dns_qname_lower;
    
    // Check for long subdomain labels (potential tunneling)
    size_t dot_pos = qname.find('.');
    if (dot_pos != std::string::npos && dot_pos > 0) {
        std::string subdomain = qname.substr(0, dot_pos);
        double entropy = compute_entropy(subdomain);
        
        if ((int)subdomain.length() >= cfg.dns_tunnel_len_threshold &&
            entropy >= cfg.dns_tunnel_entropy_threshold) {
            res.ctr.alerts++;
            res.ctr.alerts_dns_tunnel++;
            
            std::ostringstream extra;
            extra << "\"subdomain_len\":" << subdomain.length()
                  << ",\"entropy\":" << std::fixed << std::setprecision(2) << entropy;
            
            alerts.write_alert(pv.ts_epoch, AlertType::DNSTunnel,
                              ip_to_str(pv, true), ip_to_str(pv, false),
                              "DNS", pv.src_port, pv.dst_port,
                              "Potential DNS tunnel: " + qname,
                              extra.str());
        }
    }
}

void ExtScanner::check_beaconing(const ExtPacketView& pv, ExtAlertWriter& alerts, ExtLocalResults& res) {
    if (!pv.is_ipv4) return;
    if (pv.l4 != L4Proto::TCP && pv.l4 != L4Proto::UDP) return;
    
    // Track outbound connections from internal IPs
    if (!is_private_ip(pv.src_ip4_be)) return;
    if (is_private_ip(pv.dst_ip4_be)) return;
    
    std::string key = util::ip_to_string(pv.src_ip4_be) + "->" + 
                      util::ip_to_string(pv.dst_ip4_be) + ":" + 
                      std::to_string(pv.dst_port);
    
    auto& timing = conn_timing[key];
    timing.timestamps.push_back(pv.ts_epoch);
    
    // Keep only recent timestamps
    while (timing.timestamps.size() > 100) {
        timing.timestamps.pop_front();
    }
    
    // Check for beaconing if we have enough samples
    if ((int)timing.timestamps.size() >= cfg.beaconing_min_count) {
        // Calculate intervals
        std::vector<double> intervals;
        for (size_t i = 1; i < timing.timestamps.size(); i++) {
            intervals.push_back(timing.timestamps[i] - timing.timestamps[i-1]);
        }
        
        if (!intervals.empty()) {
            // Calculate mean and standard deviation
            double sum = 0;
            for (double d : intervals) sum += d;
            double mean = sum / intervals.size();
            
            double var_sum = 0;
            for (double d : intervals) var_sum += (d - mean) * (d - mean);
            double stddev = std::sqrt(var_sum / intervals.size());
            
            // Check for consistent intervals
            if (mean > 1.0 && stddev < mean * cfg.beaconing_interval_tolerance) {
                res.ctr.alerts++;
                res.ctr.alerts_beaconing++;
                
                std::ostringstream extra;
                extra << "\"interval_mean\":" << std::fixed << std::setprecision(2) << mean
                      << ",\"interval_stddev\":" << std::fixed << std::setprecision(2) << stddev
                      << ",\"sample_count\":" << timing.timestamps.size();
                
                alerts.write_alert(pv.ts_epoch, AlertType::Beaconing,
                                  ip_to_str(pv, true), ip_to_str(pv, false),
                                  pv.l4 == L4Proto::TCP ? "TCP" : "UDP",
                                  pv.src_port, pv.dst_port,
                                  "Potential beaconing detected",
                                  extra.str());
                
                // Reset to avoid repeated alerts
                timing.timestamps.clear();
            }
        }
    }
}

void ExtScanner::check_exfil(const ExtPacketView& pv, ExtAlertWriter& alerts, ExtLocalResults& res) {
    if (!pv.is_ipv4) return;
    
    // Track bytes from internal to external
    if (!is_private_ip(pv.src_ip4_be)) return;
    if (is_private_ip(pv.dst_ip4_be)) return;
    
    bytes_to_external[pv.dst_ip4_be] += pv.payload_len;
    
    if (bytes_to_external[pv.dst_ip4_be] >= cfg.exfil_bytes_threshold) {
        if (alerted_exfil.find(pv.dst_ip4_be) == alerted_exfil.end()) {
            alerted_exfil.insert(pv.dst_ip4_be);
            res.ctr.alerts++;
            res.ctr.alerts_exfil++;
            
            std::ostringstream extra;
            extra << "\"bytes_sent\":" << bytes_to_external[pv.dst_ip4_be];
            
            alerts.write_alert(pv.ts_epoch, AlertType::Exfiltration,
                              ip_to_str(pv, true), ip_to_str(pv, false),
                              pv.l4 == L4Proto::TCP ? "TCP" : "UDP",
                              pv.src_port, pv.dst_port,
                              "Potential data exfiltration detected",
                              extra.str());
        }
    }
}

void ExtScanner::check_sensitive_data(const ExtPacketView& pv, ExtAlertWriter& alerts, ExtLocalResults& res) {
    // Check for credentials in FTP/SMTP
    if (!pv.cred_username.empty() || !pv.cred_password.empty()) {
        res.ctr.alerts++;
        res.ctr.alerts_sensitive++;
        res.ctr.credentials_found++;
        
        std::string detail = "Plaintext credentials detected (" + pv.cred_protocol + ")";
        if (!pv.cred_username.empty()) {
            std::string user = cfg.redact_secrets ? redact(pv.cred_username) : pv.cred_username;
            detail += " user: " + user;
        }
        
        res.credentials.push_back({pv.cred_protocol, 
            redact(pv.cred_username) + ":" + redact(pv.cred_password)});
        
        alerts.write_alert(pv.ts_epoch, AlertType::SensitiveData,
                          ip_to_str(pv, true), ip_to_str(pv, false),
                          pv.cred_protocol,
                          pv.src_port, pv.dst_port,
                          detail);
    }
    
    // Check payload for common sensitive patterns
    if (pv.payload && pv.payload_len > 10) {
        std::string payload((const char*)pv.payload, std::min(pv.payload_len, (size_t)1024));
        std::string payload_lower = util::to_lower(payload);
        
        // Look for authorization headers, tokens, etc.
        static const std::vector<std::pair<std::string, std::string>> patterns = {
            {"authorization: basic", "Basic auth header"},
            {"authorization: bearer", "Bearer token"},
            {"api_key=", "API key"},
            {"apikey=", "API key"},
            {"password=", "Password in URL"},
            {"passwd=", "Password in URL"},
            {"secret=", "Secret in URL"},
            {"token=", "Token in URL"},
            {"set-cookie:", "Cookie being set"},
        };
        
        for (const auto& [pattern, desc] : patterns) {
            if (payload_lower.find(pattern) != std::string::npos) {
                res.ctr.alerts++;
                res.ctr.alerts_sensitive++;
                
                alerts.write_alert(pv.ts_epoch, AlertType::SensitiveData,
                                  ip_to_str(pv, true), ip_to_str(pv, false),
                                  pv.l4 == L4Proto::TCP ? "TCP" : "UDP",
                                  pv.src_port, pv.dst_port,
                                  "Sensitive data pattern: " + desc);
                break; // One alert per packet
            }
        }
    }
}

void ExtScanner::update_flow(const ExtPacketView& pv, size_t raw_len, ExtLocalResults& res) {
    if (!pv.is_ipv4 && !pv.is_ipv6) return;
    
    FlowKey key;
    key.is_ipv6 = pv.is_ipv6;
    if (pv.is_ipv4) {
        key.src_ip4 = pv.src_ip4_be;
        key.dst_ip4 = pv.dst_ip4_be;
    } else {
        key.src_ip6 = pv.src_ip6;
        key.dst_ip6 = pv.dst_ip6;
    }
    key.src_port = pv.src_port;
    key.dst_port = pv.dst_port;
    key.proto = (uint8_t)pv.l4;
    
    auto& flow = res.flows[key];
    if (flow.packets == 0) {
        flow.key = key;
        flow.first_ts = pv.ts_epoch;
        
        // Detect app protocol
        if (pv.is_dns) flow.app_proto = "DNS";
        else if (pv.is_http) flow.app_proto = "HTTP";
        else if (pv.is_tls) flow.app_proto = "TLS";
        else if (pv.is_dhcp) flow.app_proto = "DHCP";
    }
    
    flow.last_ts = pv.ts_epoch;
    flow.packets++;
    flow.bytes += raw_len;
}

void ExtScanner::carve_file(const ExtPacketView& pv, ExtLocalResults& res) {
    if (pv.http_body_offset >= pv.raw_len) return;
    
    const uint8_t* body = pv.payload + pv.http_body_offset - 
                          (pv.payload - pv.raw_data);
    size_t body_len = pv.http_body_len;
    
    if (body_len < 16) return;
    
    // Generate filename based on content type and hash
    std::string hash = sha256_hex(body, std::min(body_len, (size_t)65536));
    std::string ext = ".bin";
    
    if (pv.http_content_type.find("image/jpeg") != std::string::npos) ext = ".jpg";
    else if (pv.http_content_type.find("image/png") != std::string::npos) ext = ".png";
    else if (pv.http_content_type.find("image/gif") != std::string::npos) ext = ".gif";
    else if (pv.http_content_type.find("text/html") != std::string::npos) ext = ".html";
    else if (pv.http_content_type.find("application/pdf") != std::string::npos) ext = ".pdf";
    else if (pv.http_content_type.find("application/zip") != std::string::npos) ext = ".zip";
    else if (pv.http_content_type.find("application/javascript") != std::string::npos) ext = ".js";
    else if (pv.http_content_type.find("text/css") != std::string::npos) ext = ".css";
    
    // Check magic bytes
    if (body_len >= 4) {
        if (body[0] == 0xFF && body[1] == 0xD8 && body[2] == 0xFF) ext = ".jpg";
        else if (body[0] == 0x89 && body[1] == 'P' && body[2] == 'N' && body[3] == 'G') ext = ".png";
        else if (body[0] == 'G' && body[1] == 'I' && body[2] == 'F') ext = ".gif";
        else if (body[0] == '%' && body[1] == 'P' && body[2] == 'D' && body[3] == 'F') ext = ".pdf";
        else if (body[0] == 'P' && body[1] == 'K' && body[2] == 0x03 && body[3] == 0x04) ext = ".zip";
        else if (body[0] == 'M' && body[1] == 'Z') ext = ".exe";
        else if (body[0] == 0x7F && body[1] == 'E' && body[2] == 'L' && body[3] == 'F') ext = ".elf";
    }
    
    CarvedFile cf;
    cf.filename = hash.substr(0, 16) + ext;
    cf.sha256 = hash;
    cf.content_type = pv.http_content_type;
    cf.size = body_len;
    cf.ts = pv.ts_epoch;
    cf.src_ip = ip_to_str(pv, true);
    cf.dst_ip = ip_to_str(pv, false);
    
    // Write file
    std::string files_dir = cfg.out_dir + "/files";
    util::ensure_dir(files_dir);
    
    std::string path = files_dir + "/" + cf.filename;
    std::ofstream out(path, std::ios::binary);
    if (out) {
        out.write((const char*)body, body_len);
        out.close();
        res.carved_files.push_back(cf);
        res.ctr.files_carved++;
    }
}

void ExtScanner::write_progress(const std::string& path, const ScanProgress& progress) {
    std::ofstream out(path, std::ios::out | std::ios::trunc);
    if (!out) return;
    
    out << "{\n";
    out << "  \"packets_processed\": " << progress.packets_processed << ",\n";
    out << "  \"bytes_processed\": " << progress.bytes_processed << ",\n";
    out << "  \"time_elapsed\": " << std::fixed << std::setprecision(2) << progress.time_elapsed << ",\n";
    out << "  \"rank\": " << progress.rank << ",\n";
    out << "  \"world_size\": " << progress.world_size << ",\n";
    out << "  \"percentage\": " << std::fixed << std::setprecision(1) << progress.percentage << "\n";
    out << "}\n";
}

void write_flows_csv(const std::string& path, 
                     const std::unordered_map<FlowKey, FlowStats, FlowKeyHash>& flows) {
    std::ofstream out(path, std::ios::out | std::ios::trunc);
    if (!out) return;
    
    out << "src_ip,dst_ip,src_port,dst_port,proto,packets,bytes,first_ts,last_ts,app_proto\n";
    
    for (const auto& [key, flow] : flows) {
        std::string src, dst;
        if (key.is_ipv6) {
            src = ipv6_to_string(key.src_ip6);
            dst = ipv6_to_string(key.dst_ip6);
        } else {
            src = util::ip_to_string(key.src_ip4);
            dst = util::ip_to_string(key.dst_ip4);
        }
        
        std::string proto;
        switch (key.proto) {
            case 6: proto = "TCP"; break;
            case 17: proto = "UDP"; break;
            case 1: proto = "ICMP"; break;
            case 58: proto = "ICMPv6"; break;
            default: proto = std::to_string(key.proto); break;
        }
        
        out << src << "," << dst << ","
            << key.src_port << "," << key.dst_port << ","
            << proto << ","
            << flow.packets << "," << flow.bytes << ","
            << std::fixed << std::setprecision(6) << flow.first_ts << ","
            << flow.last_ts << ","
            << flow.app_proto << "\n";
    }
}
