#pragma once
#include <cstdint>
#include <cstddef>
#include <string>
#include <optional>

enum class L4Proto : uint8_t { TCP=6, UDP=17, ICMP=1, OTHER=0 };

struct PacketView {
  double ts_epoch = 0.0;

  bool ipv4 = false;
  uint32_t src_ip_be = 0;
  uint32_t dst_ip_be = 0;

  L4Proto l4 = L4Proto::OTHER;
  uint16_t src_port = 0;
  uint16_t dst_port = 0;

  const uint8_t* payload = nullptr;
  size_t payload_len = 0;

  // DNS (if detected)
  std::string dns_qname_lower; // empty if not DNS or parse fail
};

// Decode a raw Ethernet frame into PacketView (IPv4 only). Returns false if unsupported/unparsed.
bool decode_packet_ipv4(const uint8_t* data, size_t len, double ts_epoch, PacketView* out);

// If payload looks like DNS (udp/tcp 53), parse first query qname (lowercased).
std::string parse_dns_qname_lower(const uint8_t* payload, size_t len, bool tcp);
