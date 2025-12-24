#pragma once
#include "protocol_types.h"
#include "ext_decoder.h"
#include "ioc.h"
#include "aho_corasick.h"
#include "space_saving.h"
#include <cstdint>
#include <fstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <deque>
#include <mutex>

// Extended configuration
struct ExtScanConfig {
    std::string pcap_path;
    std::string out_dir;
    
    std::string ip_blocklist_path;
    std::string domain_blocklist_path;
    std::string keywords_path;
    std::string bpf_filter;
    std::string keylog_path;
    std::string progress_file;
    
    int top_k = 50;
    int payload_max = 512;
    int portscan_threshold = 64;
    int portscan_window_seconds = 10;
    int max_alerts_per_rank = 0;
    
    bool enable_openmp = false;
    bool enable_carving = false;
    bool redact_secrets = true;
    
    // Heuristic thresholds
    double dns_tunnel_entropy_threshold = 3.5;
    int dns_tunnel_len_threshold = 50;
    int beaconing_min_count = 10;
    double beaconing_interval_tolerance = 0.1;
    uint64_t exfil_bytes_threshold = 10000000; // 10 MB
};

// Extended counters
struct ExtCounters {
    uint64_t packets = 0;
    uint64_t bytes = 0;
    uint64_t ipv4 = 0;
    uint64_t ipv6 = 0;
    uint64_t tcp = 0;
    uint64_t udp = 0;
    uint64_t icmp = 0;
    uint64_t icmpv6 = 0;
    uint64_t arp = 0;
    uint64_t other = 0;
    
    uint64_t dns_queries = 0;
    uint64_t http_requests = 0;
    uint64_t tls_handshakes = 0;
    uint64_t dhcp_messages = 0;
    
    uint64_t alerts = 0;
    uint64_t alerts_ip = 0;
    uint64_t alerts_domain = 0;
    uint64_t alerts_keyword = 0;
    uint64_t alerts_portscan = 0;
    uint64_t alerts_dns_tunnel = 0;
    uint64_t alerts_beaconing = 0;
    uint64_t alerts_exfil = 0;
    uint64_t alerts_sensitive = 0;
    
    uint64_t files_carved = 0;
    uint64_t credentials_found = 0;
};

// Progress info
struct ScanProgress {
    uint64_t packets_processed = 0;
    uint64_t bytes_processed = 0;
    double time_elapsed = 0.0;
    int rank = 0;
    int world_size = 1;
    double percentage = 0.0;
};

// DNS query tracking for tunneling detection
struct DNSQueryRecord {
    std::string qname;
    double ts;
    size_t len;
    double entropy;
};

// Connection timing for beaconing detection
struct ConnectionTiming {
    std::deque<double> timestamps;
    uint64_t bytes_out = 0;
};

// Extended results
struct ExtLocalResults {
    ExtCounters ctr;
    SpaceSaving<uint32_t, uint64_t> top_src_bytes;
    SpaceSaving<uint32_t, uint64_t> top_dst_bytes;
    SpaceSaving<std::string, uint64_t> top_dns_qnames;
    SpaceSaving<std::string, uint64_t> top_http_hosts;
    SpaceSaving<std::string, uint64_t> top_tls_sni;
    
    // Flow tracking
    std::unordered_map<FlowKey, FlowStats, FlowKeyHash> flows;
    
    // Port scan suspects
    std::unordered_map<uint32_t, uint32_t> portscan_suspects;
    
    // Carved files
    std::vector<CarvedFile> carved_files;
    
    // Detected credentials
    std::vector<std::pair<std::string, std::string>> credentials; // protocol, redacted info
    
    explicit ExtLocalResults(int top_k)
        : top_src_bytes((size_t)top_k),
          top_dst_bytes((size_t)top_k),
          top_dns_qnames((size_t)top_k),
          top_http_hosts((size_t)top_k),
          top_tls_sni((size_t)top_k) {}
};

// Extended alert writer
class ExtAlertWriter {
public:
    bool open(const std::string& path, std::string* err);
    void close();
    bool can_write_more() const { return max_alerts == 0 || (int)written < max_alerts; }
    
    void write_alert(double ts, AlertType type,
                     const std::string& src_ip, const std::string& dst_ip,
                     const std::string& proto,
                     uint16_t src_port, uint16_t dst_port,
                     const std::string& detail,
                     const std::string& extra_json = "");
    
    std::ofstream out;
    uint64_t written = 0;
    int max_alerts = 0;
};

// Protocol log writers
class ProtocolLogWriter {
public:
    bool open(const std::string& base_dir);
    void close();
    
    void write_dns(double ts, const ExtPacketView& pv, const std::string& src, const std::string& dst);
    void write_http(double ts, const ExtPacketView& pv, const std::string& src, const std::string& dst);
    void write_tls(double ts, const ExtPacketView& pv, const std::string& src, const std::string& dst);
    void write_payload(double ts, const ExtPacketView& pv, const std::string& src, const std::string& dst);
    
private:
    std::ofstream dns_log;
    std::ofstream http_log;
    std::ofstream tls_log;
    std::ofstream payload_log;
};

// Extended scanner
class ExtScanner {
public:
    explicit ExtScanner(const ExtScanConfig& cfg, IocLists iocs);
    
    void process_packet(const ExtPacketView& pv, size_t raw_len, 
                       ExtAlertWriter& alerts, ExtLocalResults& res,
                       ProtocolLogWriter* proto_logs = nullptr);
    
    // Carve files from HTTP responses
    void carve_file(const ExtPacketView& pv, ExtLocalResults& res);
    
    // Write progress file
    void write_progress(const std::string& path, const ScanProgress& progress);
    
private:
    ExtScanConfig cfg;
    IocLists iocs;
    AhoCorasick ac;
    ExtPacketDecoder decoder;
    
    // Port scan tracking
    struct PortSketchWindow {
        uint64_t window_start_sec = 0;
        std::array<uint64_t, 32> bits{};
        bool init = false;
    };
    std::unordered_map<uint32_t, PortSketchWindow> port_windows;
    
    // DNS tunnel tracking
    std::unordered_map<std::string, std::vector<DNSQueryRecord>> dns_by_domain;
    
    // Beaconing tracking
    std::unordered_map<std::string, ConnectionTiming> conn_timing;
    
    // Exfil tracking (bytes to external IPs)
    std::unordered_map<uint32_t, uint64_t> bytes_to_external;
    std::unordered_set<uint32_t> alerted_exfil;
    
    // Helper functions
    bool is_private_ip(uint32_t ip_be);
    double compute_entropy(const std::string& s);
    std::string ip_to_str(const ExtPacketView& pv, bool src);
    void check_ioc_ip(const ExtPacketView& pv, ExtAlertWriter& alerts, ExtLocalResults& res);
    void check_ioc_domain(const ExtPacketView& pv, ExtAlertWriter& alerts, ExtLocalResults& res);
    void check_keyword(const ExtPacketView& pv, ExtAlertWriter& alerts, ExtLocalResults& res);
    void check_portscan(const ExtPacketView& pv, ExtAlertWriter& alerts, ExtLocalResults& res);
    void check_dns_tunnel(const ExtPacketView& pv, ExtAlertWriter& alerts, ExtLocalResults& res);
    void check_beaconing(const ExtPacketView& pv, ExtAlertWriter& alerts, ExtLocalResults& res);
    void check_exfil(const ExtPacketView& pv, ExtAlertWriter& alerts, ExtLocalResults& res);
    void check_sensitive_data(const ExtPacketView& pv, ExtAlertWriter& alerts, ExtLocalResults& res);
    void update_flow(const ExtPacketView& pv, size_t raw_len, ExtLocalResults& res);
    std::string redact(const std::string& s);
};

// Flow CSV writer
void write_flows_csv(const std::string& path, const std::unordered_map<FlowKey, FlowStats, FlowKeyHash>& flows);
