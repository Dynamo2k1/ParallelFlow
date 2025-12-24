#pragma once
#include "protocol_types.h"
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

// Extended packet decoder with full protocol support
class ExtPacketDecoder {
public:
    // Decode a raw Ethernet frame (DLT_EN10MB)
    // Returns true if successfully decoded at least L2/L3
    bool decode(const uint8_t* data, size_t len, double ts_epoch, ExtPacketView* out);
    
private:
    // Layer 2
    bool decode_ethernet(const uint8_t* data, size_t len, size_t* offset, uint16_t* ethertype);
    bool decode_vlan(const uint8_t* data, size_t len, size_t* offset, uint16_t* ethertype);
    
    // Layer 3
    bool decode_ipv4(const uint8_t* data, size_t len, size_t offset, ExtPacketView* out);
    bool decode_ipv6(const uint8_t* data, size_t len, size_t offset, ExtPacketView* out);
    bool decode_arp(const uint8_t* data, size_t len, size_t offset, ExtPacketView* out);
    
    // Layer 4
    bool decode_tcp(const uint8_t* data, size_t len, size_t offset, ExtPacketView* out);
    bool decode_udp(const uint8_t* data, size_t len, size_t offset, ExtPacketView* out);
    bool decode_icmp(const uint8_t* data, size_t len, size_t offset, ExtPacketView* out);
    bool decode_icmpv6(const uint8_t* data, size_t len, size_t offset, ExtPacketView* out);
    
    // Application layer
    void decode_dns(const uint8_t* payload, size_t len, bool tcp, ExtPacketView* out);
    void decode_http(const uint8_t* payload, size_t len, ExtPacketView* out);
    void decode_tls(const uint8_t* payload, size_t len, ExtPacketView* out);
    void decode_dhcp(const uint8_t* payload, size_t len, ExtPacketView* out);
    void decode_smtp_ftp(const uint8_t* payload, size_t len, const std::string& proto, ExtPacketView* out);
    
    // TLS helpers
    std::string compute_ja3(const std::vector<uint16_t>& cipher_suites,
                           const std::vector<uint16_t>& extensions,
                           const std::vector<uint16_t>& ec_curves,
                           const std::vector<uint8_t>& ec_point_formats,
                           uint16_t version);
};

// Helper functions
std::string ipv6_to_string(const std::array<uint8_t, 16>& ip);
bool parse_ipv6(const std::string& s, std::array<uint8_t, 16>* out);
std::string mac_to_string(const std::array<uint8_t, 6>& mac);
std::string sha256_hex(const uint8_t* data, size_t len);

// DNS name parsing
std::string parse_dns_name(const uint8_t* packet, size_t pkt_len, size_t* offset, int depth = 0);
