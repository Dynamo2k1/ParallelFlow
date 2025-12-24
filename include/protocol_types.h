#pragma once
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <array>
#include <optional>

// Extended L4 protocol enum
enum class L4Proto : uint8_t { 
    TCP = 6, 
    UDP = 17, 
    ICMP = 1, 
    ICMPV6 = 58,
    OTHER = 0 
};

// Extended packet view with IPv6 support
struct ExtPacketView {
    double ts_epoch = 0.0;
    
    bool is_ipv4 = false;
    bool is_ipv6 = false;
    bool is_arp = false;
    
    // IPv4
    uint32_t src_ip4_be = 0;
    uint32_t dst_ip4_be = 0;
    
    // IPv6 (16 bytes each)
    std::array<uint8_t, 16> src_ip6{};
    std::array<uint8_t, 16> dst_ip6{};
    
    L4Proto l4 = L4Proto::OTHER;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    
    const uint8_t* payload = nullptr;
    size_t payload_len = 0;
    
    // Original packet data for carving
    const uint8_t* raw_data = nullptr;
    size_t raw_len = 0;
    
    // Protocol-specific metadata
    std::string dns_qname_lower;
    
    // HTTP metadata
    bool is_http = false;
    std::string http_method;
    std::string http_uri;
    std::string http_host;
    std::string http_user_agent;
    std::string http_content_type;
    int http_status_code = 0;
    size_t http_body_offset = 0;
    size_t http_body_len = 0;
    
    // TLS metadata
    bool is_tls = false;
    uint16_t tls_version = 0;
    std::string tls_sni;
    std::vector<std::string> tls_alpn;
    std::vector<uint16_t> tls_cipher_suites;
    std::string tls_ja3;
    
    // DNS metadata
    bool is_dns = false;
    std::vector<std::string> dns_queries;
    std::vector<std::string> dns_answers;
    uint16_t dns_query_count = 0;
    uint16_t dns_answer_count = 0;
    
    // DHCP metadata
    bool is_dhcp = false;
    uint8_t dhcp_op = 0;
    std::string dhcp_hostname;
    uint32_t dhcp_client_ip = 0;
    uint32_t dhcp_your_ip = 0;
    std::array<uint8_t, 6> dhcp_client_mac{};
    
    // ARP metadata
    uint16_t arp_op = 0;
    uint32_t arp_sender_ip = 0;
    uint32_t arp_target_ip = 0;
    std::array<uint8_t, 6> arp_sender_mac{};
    std::array<uint8_t, 6> arp_target_mac{};
    
    // ICMP metadata
    uint8_t icmp_type = 0;
    uint8_t icmp_code = 0;
    
    // Credentials found (for SMTP/FTP)
    std::string cred_username;
    std::string cred_password;
    std::string cred_protocol;
    
    // TCP flags
    bool tcp_syn = false;
    bool tcp_ack = false;
    bool tcp_fin = false;
    bool tcp_rst = false;
    bool tcp_psh = false;
    uint32_t tcp_seq = 0;
    uint32_t tcp_ack_num = 0;
};

// Flow key for tracking connections
struct FlowKey {
    bool is_ipv6 = false;
    uint32_t src_ip4 = 0;
    uint32_t dst_ip4 = 0;
    std::array<uint8_t, 16> src_ip6{};
    std::array<uint8_t, 16> dst_ip6{};
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint8_t proto = 0;
    
    bool operator==(const FlowKey& other) const {
        if (is_ipv6 != other.is_ipv6) return false;
        if (is_ipv6) {
            return src_ip6 == other.src_ip6 && dst_ip6 == other.dst_ip6 &&
                   src_port == other.src_port && dst_port == other.dst_port && proto == other.proto;
        }
        return src_ip4 == other.src_ip4 && dst_ip4 == other.dst_ip4 &&
               src_port == other.src_port && dst_port == other.dst_port && proto == other.proto;
    }
};

struct FlowKeyHash {
    size_t operator()(const FlowKey& k) const {
        size_t h = 0;
        h ^= std::hash<uint32_t>{}(k.src_ip4) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint32_t>{}(k.dst_ip4) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint16_t>{}(k.src_port) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint16_t>{}(k.dst_port) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint8_t>{}(k.proto) + 0x9e3779b9 + (h << 6) + (h >> 2);
        if (k.is_ipv6) {
            for (auto b : k.src_ip6) h ^= std::hash<uint8_t>{}(b) + 0x9e3779b9 + (h << 6) + (h >> 2);
            for (auto b : k.dst_ip6) h ^= std::hash<uint8_t>{}(b) + 0x9e3779b9 + (h << 6) + (h >> 2);
        }
        return h;
    }
};

// Flow statistics
struct FlowStats {
    FlowKey key;
    double first_ts = 0.0;
    double last_ts = 0.0;
    uint64_t packets = 0;
    uint64_t bytes = 0;
    uint64_t packets_rev = 0;
    uint64_t bytes_rev = 0;
    std::string app_proto;  // detected application protocol
};

// Carved file record
struct CarvedFile {
    std::string filename;
    std::string sha256;
    std::string content_type;
    size_t size = 0;
    double ts = 0.0;
    std::string src_ip;
    std::string dst_ip;
};

// Alert types
enum class AlertType {
    BlocklistedIP,
    BlocklistedDomain,
    KeywordMatch,
    PortScan,
    DNSTunnel,
    Beaconing,
    Exfiltration,
    SensitiveData,
    SuspiciousTLS,
    ARPSpoof
};

inline const char* alert_type_str(AlertType t) {
    switch (t) {
        case AlertType::BlocklistedIP: return "blocklisted_ip";
        case AlertType::BlocklistedDomain: return "blocklisted_domain";
        case AlertType::KeywordMatch: return "keyword_match";
        case AlertType::PortScan: return "port_scan";
        case AlertType::DNSTunnel: return "dns_tunnel";
        case AlertType::Beaconing: return "beaconing";
        case AlertType::Exfiltration: return "exfiltration";
        case AlertType::SensitiveData: return "sensitive_data";
        case AlertType::SuspiciousTLS: return "suspicious_tls";
        case AlertType::ARPSpoof: return "arp_spoof";
        default: return "unknown";
    }
}
