#include "pcap_decode.h"
#include "common.h"
#include <cstring>
#include <string>

#if defined(_WIN32)
  #include <winsock2.h>
#else
  #include <arpa/inet.h>
#endif

// Ethertype constants for readability
static constexpr uint16_t ETHERTYPE_IPV4 = 0x0800;
static constexpr uint16_t ETHERTYPE_ARP = 0x0806;
static constexpr uint16_t ETHERTYPE_VLAN_8021Q = 0x8100;
static constexpr uint16_t ETHERTYPE_VLAN_8021AD = 0x88a8;
static constexpr uint16_t ETHERTYPE_IPV6 = 0x86DD;

static uint16_t be16(const uint8_t* p) {
  uint16_t v;
  std::memcpy(&v, p, sizeof(v));
  return ntohs(v);
}
static uint32_t be32(const uint8_t* p) {
  uint32_t v;
  std::memcpy(&v, p, sizeof(v));
  return ntohl(v);
}

static bool parse_qname(const uint8_t* p, size_t len, size_t* off, std::string* out) {
  // DNS QNAME: sequence of labels ending with 0. No compression expected in question.
  std::string name;
  size_t i = *off;
  while (i < len) {
    uint8_t lablen = p[i++];
    if (lablen == 0) {
      if (!name.empty() && name.back() == '.') name.pop_back();
      *off = i;
      *out = util::to_lower(name);
      return true;
    }
    if (lablen & 0xC0) {
      // compressed name pointer not supported in MVP; skip parse
      return false;
    }
    if (i + lablen > len) return false;
    for (size_t j = 0; j < lablen; j++) {
      unsigned char c = p[i + j];
      // allow dns label charset loosely
      name.push_back((char)c);
    }
    name.push_back('.');
    i += lablen;
    if (name.size() > 253) return false;
  }
  return false;
}

std::string parse_dns_qname_lower(const uint8_t* payload, size_t len, bool tcp) {
  // TCP DNS has 2-byte length prefix
  size_t off = 0;
  if (tcp) {
    if (len < 2) return {};
    uint16_t msglen = be16(payload);
    if ((size_t)msglen + 2 > len) return {};
    off = 2;
    len = msglen + 2;
  }

  if (len < off + 12) return {};
  const uint8_t* p = payload + off;
  size_t plen = len - off;

  uint16_t qdcount = be16(p + 4);
  if (qdcount < 1) return {};

  size_t qoff = 12;
  std::string qname;
  if (!parse_qname(p, plen, &qoff, &qname)) return {};

  // After qname: QTYPE(2) QCLASS(2) must exist
  if (qoff + 4 > plen) return {};
  return qname;
}

bool decode_packet_ipv4(const uint8_t* data, size_t len, double ts_epoch, PacketView* out) {
  if (!data || !out) return false;
  
  // Handle very small packets - still count them
  if (len < 14) {
    PacketView pv;
    pv.ts_epoch = ts_epoch;
    pv.ipv4 = false;
    pv.l4 = L4Proto::OTHER;
    pv.payload = data;
    pv.payload_len = len;
    *out = std::move(pv);
    return true;
  }

  size_t off = 0;
  // Ethernet header
  uint16_t ethertype = be16(data + 12);
  off = 14;

  // VLAN tags can be stacked
  while (ethertype == ETHERTYPE_VLAN_8021Q || ethertype == ETHERTYPE_VLAN_8021AD) {
    if (len < off + 4) {
      // VLAN tag incomplete, still count packet
      PacketView pv;
      pv.ts_epoch = ts_epoch;
      pv.ipv4 = false;
      pv.l4 = L4Proto::OTHER;
      pv.payload = data + off;
      pv.payload_len = (len > off) ? (len - off) : 0;
      *out = std::move(pv);
      return true;
    }
    ethertype = be16(data + off + 2);
    off += 4;
  }

  // Handle non-IPv4 ethertypes - still count them
  if (ethertype != ETHERTYPE_IPV4) {
    PacketView pv;
    pv.ts_epoch = ts_epoch;
    pv.ipv4 = false;
    pv.l4 = L4Proto::OTHER;
    pv.payload = data + off;
    pv.payload_len = (len > off) ? (len - off) : 0;
    *out = std::move(pv);
    return true;
  }

  if (len < off + 20) {
    // Truncated IP header, still count packet
    PacketView pv;
    pv.ts_epoch = ts_epoch;
    pv.ipv4 = false;
    pv.l4 = L4Proto::OTHER;
    pv.payload = data + off;
    pv.payload_len = (len > off) ? (len - off) : 0;
    *out = std::move(pv);
    return true;
  }
  const uint8_t* ip = data + off;

  uint8_t ver_ihl = ip[0];
  uint8_t ver = (ver_ihl >> 4) & 0xF;
  uint8_t ihl = ver_ihl & 0xF;
  if (ver != 4) {
    // Not IPv4, still count packet
    PacketView pv;
    pv.ts_epoch = ts_epoch;
    pv.ipv4 = false;
    pv.l4 = L4Proto::OTHER;
    pv.payload = data + off;
    pv.payload_len = (len > off) ? (len - off) : 0;
    *out = std::move(pv);
    return true;
  }
  size_t ip_hlen = (size_t)ihl * 4;
  if (ip_hlen < 20 || len < off + ip_hlen) {
    // Invalid IP header length, still count packet
    PacketView pv;
    pv.ts_epoch = ts_epoch;
    pv.ipv4 = true;
    pv.l4 = L4Proto::OTHER;
    pv.payload = data + off;
    pv.payload_len = (len > off) ? (len - off) : 0;
    *out = std::move(pv);
    return true;
  }

  uint16_t total_len = be16(ip + 2);
  if (total_len < ip_hlen) {
    // Invalid total length, still count packet
    PacketView pv;
    pv.ts_epoch = ts_epoch;
    pv.ipv4 = true;
    pv.l4 = L4Proto::OTHER;
    pv.payload = data + off;
    pv.payload_len = (len > off) ? (len - off) : 0;
    *out = std::move(pv);
    return true;
  }
  size_t ip_total = std::min((size_t)total_len, len - off);

  uint8_t proto = ip[9];
  uint32_t src_be = 0, dst_be = 0;
  std::memcpy(&src_be, ip + 12, 4);
  std::memcpy(&dst_be, ip + 16, 4);

  size_t l4_off = off + ip_hlen;
  size_t l4_len = (off + ip_total > l4_off) ? (off + ip_total - l4_off) : 0;

  PacketView pv;
  pv.ts_epoch = ts_epoch;
  pv.ipv4 = true;
  pv.src_ip_be = src_be;
  pv.dst_ip_be = dst_be;
  pv.l4 = L4Proto::OTHER;
  pv.src_port = 0;
  pv.dst_port = 0;
  pv.payload = nullptr;
  pv.payload_len = 0;

  if (proto == 6) { // TCP
    if (l4_len < 20) {
      // Truncated TCP header, set as OTHER
      pv.l4 = L4Proto::OTHER;
      pv.payload = data + l4_off;
      pv.payload_len = l4_len;
    } else {
      const uint8_t* tcp = data + l4_off;
      pv.l4 = L4Proto::TCP;
      pv.src_port = be16(tcp + 0);
      pv.dst_port = be16(tcp + 2);
      uint8_t doff = (tcp[12] >> 4) & 0xF;
      size_t tcp_hlen = (size_t)doff * 4;
      if (tcp_hlen < 20 || l4_len < tcp_hlen) {
        // Invalid TCP header, but still record ports
        pv.payload = tcp;
        pv.payload_len = l4_len;
      } else {
        pv.payload = tcp + tcp_hlen;
        pv.payload_len = l4_len - tcp_hlen;

        bool maybe_dns = (pv.src_port == 53 || pv.dst_port == 53);
        if (maybe_dns) {
          pv.dns_qname_lower = parse_dns_qname_lower(pv.payload, pv.payload_len, true);
        }
      }
    }
  } else if (proto == 17) { // UDP
    if (l4_len < 8) {
      // Truncated UDP header
      pv.l4 = L4Proto::OTHER;
      pv.payload = data + l4_off;
      pv.payload_len = l4_len;
    } else {
      const uint8_t* udp = data + l4_off;
      pv.l4 = L4Proto::UDP;
      pv.src_port = be16(udp + 0);
      pv.dst_port = be16(udp + 2);
      uint16_t ulen = be16(udp + 4);
      if (ulen < 8) {
        // Invalid UDP length
        pv.payload = udp + 8;
        pv.payload_len = (l4_len > 8) ? (l4_len - 8) : 0;
      } else {
        size_t udp_total = std::min((size_t)ulen, l4_len);
        pv.payload = udp + 8;
        pv.payload_len = (udp_total >= 8) ? (udp_total - 8) : 0;

        bool maybe_dns = (pv.src_port == 53 || pv.dst_port == 53);
        if (maybe_dns) {
          pv.dns_qname_lower = parse_dns_qname_lower(pv.payload, pv.payload_len, false);
        }
      }
    }
  } else if (proto == 1) {
    pv.l4 = L4Proto::ICMP;
    pv.payload = data + l4_off;
    pv.payload_len = l4_len;
  } else {
    // All other protocols (IGMP, GRE, ESP, OSPF, etc.)
    pv.l4 = L4Proto::OTHER;
    pv.payload = data + l4_off;
    pv.payload_len = l4_len;
  }

  *out = std::move(pv);
  return true;
}
