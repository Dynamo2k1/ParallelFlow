#include "ext_decoder.h"
#include "common.h"
#include <cstring>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>

#if defined(_WIN32)
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #include <arpa/inet.h>
#endif

// Simple MD5 for JA3 (we use a basic implementation)
// For production, use OpenSSL or similar
#include <array>

static uint16_t read_be16(const uint8_t* p) {
    return ((uint16_t)p[0] << 8) | (uint16_t)p[1];
}

static uint32_t read_be32(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | 
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

std::string ipv6_to_string(const std::array<uint8_t, 16>& ip) {
    char buf[INET6_ADDRSTRLEN] = {0};
    const char* r = inet_ntop(AF_INET6, ip.data(), buf, sizeof(buf));
    return r ? std::string(r) : std::string("::");
}

bool parse_ipv6(const std::string& s, std::array<uint8_t, 16>* out) {
    in6_addr addr;
    if (inet_pton(AF_INET6, s.c_str(), &addr) == 1) {
        std::memcpy(out->data(), &addr, 16);
        return true;
    }
    return false;
}

std::string mac_to_string(const std::array<uint8_t, 6>& mac) {
    std::ostringstream os;
    os << std::hex << std::setfill('0');
    for (int i = 0; i < 6; i++) {
        if (i > 0) os << ':';
        os << std::setw(2) << (int)mac[i];
    }
    return os.str();
}

// Simple SHA256 implementation (for file hashing)
namespace {
    static const uint32_t K256[] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };
    
    inline uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
    inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
    inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
    inline uint32_t sig0(uint32_t x) { return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22); }
    inline uint32_t sig1(uint32_t x) { return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25); }
    inline uint32_t gam0(uint32_t x) { return rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3); }
    inline uint32_t gam1(uint32_t x) { return rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10); }
}

std::string sha256_hex(const uint8_t* data, size_t len) {
    uint32_t h[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    
    // Padding
    size_t bit_len = len * 8;
    size_t padded_len = ((len + 8) / 64 + 1) * 64;
    std::vector<uint8_t> msg(padded_len, 0);
    std::memcpy(msg.data(), data, len);
    msg[len] = 0x80;
    for (int i = 0; i < 8; i++) {
        msg[padded_len - 1 - i] = (uint8_t)((bit_len >> (i * 8)) & 0xff);
    }
    
    // Process blocks
    for (size_t i = 0; i < padded_len; i += 64) {
        uint32_t w[64];
        for (int j = 0; j < 16; j++) {
            w[j] = read_be32(&msg[i + j * 4]);
        }
        for (int j = 16; j < 64; j++) {
            w[j] = gam1(w[j-2]) + w[j-7] + gam0(w[j-15]) + w[j-16];
        }
        
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
        
        for (int j = 0; j < 64; j++) {
            uint32_t t1 = hh + sig1(e) + ch(e, f, g) + K256[j] + w[j];
            uint32_t t2 = sig0(a) + maj(a, b, c);
            hh = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }
    
    std::ostringstream os;
    os << std::hex << std::setfill('0');
    for (int i = 0; i < 8; i++) {
        os << std::setw(8) << h[i];
    }
    return os.str();
}

// Simple MD5 for JA3 (minimal implementation)
namespace {
    static const uint32_t S[] = {
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
    };
    static const uint32_t K[] = {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
    };
    
    inline uint32_t leftrotate(uint32_t x, uint32_t c) { return (x << c) | (x >> (32 - c)); }
}

static std::string md5_hex(const std::string& msg) {
    uint32_t h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476;
    
    size_t orig_len = msg.size();
    size_t new_len = ((orig_len + 8) / 64 + 1) * 64;
    std::vector<uint8_t> m(new_len, 0);
    std::memcpy(m.data(), msg.data(), orig_len);
    m[orig_len] = 0x80;
    uint64_t bits = orig_len * 8;
    std::memcpy(&m[new_len - 8], &bits, 8);
    
    for (size_t offset = 0; offset < new_len; offset += 64) {
        uint32_t w[16];
        for (int i = 0; i < 16; i++) {
            w[i] = m[offset + i*4] | (m[offset + i*4 + 1] << 8) |
                   (m[offset + i*4 + 2] << 16) | (m[offset + i*4 + 3] << 24);
        }
        
        uint32_t a = h0, b = h1, c = h2, d = h3;
        for (int i = 0; i < 64; i++) {
            uint32_t f, g;
            if (i < 16) { f = (b & c) | (~b & d); g = i; }
            else if (i < 32) { f = (d & b) | (~d & c); g = (5*i + 1) % 16; }
            else if (i < 48) { f = b ^ c ^ d; g = (3*i + 5) % 16; }
            else { f = c ^ (b | ~d); g = (7*i) % 16; }
            f = f + a + K[i] + w[g];
            a = d; d = c; c = b; b = b + leftrotate(f, S[i]);
        }
        h0 += a; h1 += b; h2 += c; h3 += d;
    }
    
    std::ostringstream os;
    os << std::hex << std::setfill('0');
    auto out = [&](uint32_t v) {
        os << std::setw(2) << (v & 0xff) << std::setw(2) << ((v >> 8) & 0xff)
           << std::setw(2) << ((v >> 16) & 0xff) << std::setw(2) << ((v >> 24) & 0xff);
    };
    out(h0); out(h1); out(h2); out(h3);
    return os.str();
}

bool ExtPacketDecoder::decode(const uint8_t* data, size_t len, double ts_epoch, ExtPacketView* out) {
    if (!data || !out) return false;
    
    *out = ExtPacketView{};
    out->ts_epoch = ts_epoch;
    out->raw_data = data;
    out->raw_len = len;
    
    // Handle very small packets - still count them
    if (len < 14) {
        out->l4 = L4Proto::OTHER;
        out->payload = data;
        out->payload_len = len;
        return true;  // Return true to count the packet
    }
    
    size_t offset = 0;
    uint16_t ethertype = 0;
    
    if (!decode_ethernet(data, len, &offset, &ethertype)) {
        // Even if we can't decode ethernet header, count the packet
        out->l4 = L4Proto::OTHER;
        out->payload = data;
        out->payload_len = len;
        return true;
    }
    
    // Handle VLAN tags
    while (ethertype == 0x8100 || ethertype == 0x88a8) {
        if (!decode_vlan(data, len, &offset, &ethertype)) {
            // VLAN decode failed, but still count the packet
            out->l4 = L4Proto::OTHER;
            out->payload = data + offset;
            out->payload_len = (len > offset) ? (len - offset) : 0;
            return true;
        }
    }
    
    bool ok = false;
    switch (ethertype) {
        case 0x0800: // IPv4
            ok = decode_ipv4(data, len, offset, out);
            break;
        case 0x86DD: // IPv6
            ok = decode_ipv6(data, len, offset, out);
            break;
        case 0x0806: // ARP
            ok = decode_arp(data, len, offset, out);
            break;
        case 0x8035: // RARP
            out->is_arp = true;  // Treat RARP similar to ARP
            if (offset + 28 <= len) {
                ok = decode_arp(data, len, offset, out);
            } else {
                out->l4 = L4Proto::OTHER;
                out->payload = data + offset;
                out->payload_len = (len > offset) ? (len - offset) : 0;
                ok = true;
            }
            break;
        case 0x88CC: // LLDP (Link Layer Discovery Protocol)
        case 0x88E5: // 802.1AE MAC security
        case 0x8809: // Slow Protocols (LACP)
        case 0x8808: // Ethernet flow control
        case 0x0842: // Wake-on-LAN
        case 0x22F3: // IETF TRILL
        case 0x22F0: // 802.1Qat SRP
        case 0x6003: // DECnet Phase IV
        case 0x8137: // IPX
        case 0x8138: // IPX
        case 0x809B: // AppleTalk
            // Handle known but unsupported protocols - still count them
            out->l4 = L4Proto::OTHER;
            out->payload = data + offset;
            out->payload_len = (len > offset) ? (len - offset) : 0;
            ok = true;
            break;
        default:
            // Unknown ethertype - still count the packet
            out->l4 = L4Proto::OTHER;
            out->payload = data + offset;
            out->payload_len = (len > offset) ? (len - offset) : 0;
            ok = true;
            break;
    }
    
    // If specific protocol decode failed, still return true to count the packet
    if (!ok) {
        out->l4 = L4Proto::OTHER;
        out->payload = data + offset;
        out->payload_len = (len > offset) ? (len - offset) : 0;
        return true;
    }
    
    return true;
}

bool ExtPacketDecoder::decode_ethernet(const uint8_t* data, size_t len, size_t* offset, uint16_t* ethertype) {
    if (len < 14) return false;
    *ethertype = read_be16(data + 12);
    *offset = 14;
    return true;
}

bool ExtPacketDecoder::decode_vlan(const uint8_t* data, size_t len, size_t* offset, uint16_t* ethertype) {
    if (*offset + 4 > len) return false;
    *ethertype = read_be16(data + *offset + 2);
    *offset += 4;
    return true;
}

bool ExtPacketDecoder::decode_ipv4(const uint8_t* data, size_t len, size_t offset, ExtPacketView* out) {
    if (offset + 20 > len) return false;
    
    const uint8_t* ip = data + offset;
    uint8_t ver_ihl = ip[0];
    uint8_t ver = (ver_ihl >> 4) & 0xF;
    uint8_t ihl = ver_ihl & 0xF;
    
    if (ver != 4) return false;
    size_t ip_hlen = (size_t)ihl * 4;
    if (ip_hlen < 20 || offset + ip_hlen > len) return false;
    
    uint16_t total_len = read_be16(ip + 2);
    if (total_len < ip_hlen) return false;
    size_t ip_total = std::min((size_t)total_len, len - offset);
    
    out->is_ipv4 = true;
    std::memcpy(&out->src_ip4_be, ip + 12, 4);
    std::memcpy(&out->dst_ip4_be, ip + 16, 4);
    
    uint8_t proto = ip[9];
    size_t l4_offset = offset + ip_hlen;
    size_t l4_len = (offset + ip_total > l4_offset) ? (offset + ip_total - l4_offset) : 0;
    
    switch (proto) {
        case 6:  // TCP
            out->l4 = L4Proto::TCP;
            if (!decode_tcp(data, len, l4_offset, out)) {
                // TCP decode failed, set payload and continue
                out->payload = data + l4_offset;
                out->payload_len = l4_len;
            }
            break;
        case 17: // UDP
            out->l4 = L4Proto::UDP;
            if (!decode_udp(data, len, l4_offset, out)) {
                // UDP decode failed, set payload and continue
                out->payload = data + l4_offset;
                out->payload_len = l4_len;
            }
            break;
        case 1:  // ICMP
            out->l4 = L4Proto::ICMP;
            decode_icmp(data, len, l4_offset, out);
            break;
        case 2:  // IGMP
        case 41: // IPv6 encapsulation
        case 47: // GRE
        case 50: // ESP (IPsec Encapsulating Security Payload)
        case 51: // AH (IPsec Authentication Header)
        case 89: // OSPF
        case 103: // PIM
        case 112: // VRRP
        case 132: // SCTP
            // Known but unsupported protocols
            out->l4 = L4Proto::OTHER;
            out->payload = data + l4_offset;
            out->payload_len = l4_len;
            break;
        default:
            out->l4 = L4Proto::OTHER;
            out->payload = data + l4_offset;
            out->payload_len = l4_len;
            break;
    }
    
    return true;
}

bool ExtPacketDecoder::decode_ipv6(const uint8_t* data, size_t len, size_t offset, ExtPacketView* out) {
    if (offset + 40 > len) return false;
    
    const uint8_t* ip6 = data + offset;
    uint8_t ver = (ip6[0] >> 4) & 0xF;
    if (ver != 6) return false;
    
    uint16_t payload_len = read_be16(ip6 + 4);
    uint8_t next_header = ip6[6];
    
    out->is_ipv6 = true;
    std::memcpy(out->src_ip6.data(), ip6 + 8, 16);
    std::memcpy(out->dst_ip6.data(), ip6 + 24, 16);
    
    size_t l4_offset = offset + 40;
    
    // Skip extension headers (simplified) - handle errors gracefully
    int max_ext_headers = 10;  // Prevent infinite loop
    while ((next_header == 0 || next_header == 43 || next_header == 44 || 
            next_header == 60 || next_header == 51) && max_ext_headers > 0) {
        if (l4_offset + 2 > len) {
            // Extension header parsing failed, but we can still count the packet
            out->l4 = L4Proto::OTHER;
            out->payload = data + l4_offset;
            out->payload_len = (len > l4_offset) ? (len - l4_offset) : 0;
            return true;
        }
        uint8_t ext_len = data[l4_offset + 1];
        next_header = data[l4_offset];
        l4_offset += 8 + ext_len * 8;
        if (l4_offset > len) {
            // Extension header extends beyond packet, return what we have
            out->l4 = L4Proto::OTHER;
            out->payload = data + offset + 40;  // Point to start of extension headers
            out->payload_len = (len > offset + 40) ? (len - offset - 40) : 0;
            return true;
        }
        max_ext_headers--;
    }
    
    size_t l4_len = (len > l4_offset) ? (len - l4_offset) : 0;
    
    switch (next_header) {
        case 6:  // TCP
            out->l4 = L4Proto::TCP;
            if (!decode_tcp(data, len, l4_offset, out)) {
                // TCP decode failed, set payload and continue
                out->payload = data + l4_offset;
                out->payload_len = l4_len;
            }
            break;
        case 17: // UDP
            out->l4 = L4Proto::UDP;
            if (!decode_udp(data, len, l4_offset, out)) {
                // UDP decode failed, set payload and continue
                out->payload = data + l4_offset;
                out->payload_len = l4_len;
            }
            break;
        case 58: // ICMPv6
            out->l4 = L4Proto::ICMPV6;
            decode_icmpv6(data, len, l4_offset, out);
            break;
        case 50: // ESP (IPsec)
        case 51: // AH (IPsec)
        case 89: // OSPF
        case 103: // PIM
        case 132: // SCTP
        case 135: // Mobility Header
            // Known but unsupported IPv6 protocols
            out->l4 = L4Proto::OTHER;
            out->payload = data + l4_offset;
            out->payload_len = l4_len;
            break;
        default:
            out->l4 = L4Proto::OTHER;
            out->payload = data + l4_offset;
            out->payload_len = l4_len;
            break;
    }
    
    return true;
}

bool ExtPacketDecoder::decode_arp(const uint8_t* data, size_t len, size_t offset, ExtPacketView* out) {
    if (offset + 28 > len) return false;
    
    const uint8_t* arp = data + offset;
    out->is_arp = true;
    out->arp_op = read_be16(arp + 6);
    std::memcpy(out->arp_sender_mac.data(), arp + 8, 6);
    std::memcpy(&out->arp_sender_ip, arp + 14, 4);
    std::memcpy(out->arp_target_mac.data(), arp + 18, 6);
    std::memcpy(&out->arp_target_ip, arp + 24, 4);
    
    return true;
}

bool ExtPacketDecoder::decode_tcp(const uint8_t* data, size_t len, size_t offset, ExtPacketView* out) {
    if (offset + 20 > len) return false;
    
    const uint8_t* tcp = data + offset;
    out->src_port = read_be16(tcp);
    out->dst_port = read_be16(tcp + 2);
    out->tcp_seq = read_be32(tcp + 4);
    out->tcp_ack_num = read_be32(tcp + 8);
    
    uint8_t data_offset = (tcp[12] >> 4) & 0xF;
    size_t tcp_hlen = (size_t)data_offset * 4;
    if (tcp_hlen < 20 || offset + tcp_hlen > len) return false;
    
    uint8_t flags = tcp[13];
    out->tcp_fin = (flags & 0x01) != 0;
    out->tcp_syn = (flags & 0x02) != 0;
    out->tcp_rst = (flags & 0x04) != 0;
    out->tcp_psh = (flags & 0x08) != 0;
    out->tcp_ack = (flags & 0x10) != 0;
    
    out->payload = data + offset + tcp_hlen;
    out->payload_len = len - offset - tcp_hlen;
    
    // Application layer detection
    if (out->payload_len > 0) {
        uint16_t sport = out->src_port;
        uint16_t dport = out->dst_port;
        
        // DNS (port 53)
        if (sport == 53 || dport == 53) {
            decode_dns(out->payload, out->payload_len, true, out);
        }
        // HTTP (ports 80, 8080, etc.)
        else if (dport == 80 || dport == 8080 || sport == 80 || sport == 8080) {
            decode_http(out->payload, out->payload_len, out);
        }
        // TLS (port 443)
        else if (dport == 443 || sport == 443) {
            decode_tls(out->payload, out->payload_len, out);
        }
        // SMTP (ports 25, 587)
        else if (dport == 25 || dport == 587 || sport == 25 || sport == 587) {
            decode_smtp_ftp(out->payload, out->payload_len, "smtp", out);
        }
        // FTP (port 21)
        else if (dport == 21 || sport == 21) {
            decode_smtp_ftp(out->payload, out->payload_len, "ftp", out);
        }
    }
    
    return true;
}

bool ExtPacketDecoder::decode_udp(const uint8_t* data, size_t len, size_t offset, ExtPacketView* out) {
    if (offset + 8 > len) return false;
    
    const uint8_t* udp = data + offset;
    out->src_port = read_be16(udp);
    out->dst_port = read_be16(udp + 2);
    uint16_t udp_len = read_be16(udp + 4);
    
    if (udp_len < 8) return false;
    size_t payload_len = std::min((size_t)(udp_len - 8), len - offset - 8);
    
    out->payload = data + offset + 8;
    out->payload_len = payload_len;
    
    // Application layer detection
    uint16_t sport = out->src_port;
    uint16_t dport = out->dst_port;
    
    // DNS
    if (sport == 53 || dport == 53) {
        decode_dns(out->payload, out->payload_len, false, out);
    }
    // DHCP (ports 67, 68)
    else if (sport == 67 || sport == 68 || dport == 67 || dport == 68) {
        decode_dhcp(out->payload, out->payload_len, out);
    }
    
    return true;
}

bool ExtPacketDecoder::decode_icmp(const uint8_t* data, size_t len, size_t offset, ExtPacketView* out) {
    if (offset + 4 > len) return false;
    
    out->icmp_type = data[offset];
    out->icmp_code = data[offset + 1];
    out->payload = data + offset;
    out->payload_len = len - offset;
    
    return true;
}

bool ExtPacketDecoder::decode_icmpv6(const uint8_t* data, size_t len, size_t offset, ExtPacketView* out) {
    if (offset + 4 > len) return false;
    
    out->icmp_type = data[offset];
    out->icmp_code = data[offset + 1];
    out->payload = data + offset;
    out->payload_len = len - offset;
    
    return true;
}

std::string parse_dns_name(const uint8_t* packet, size_t pkt_len, size_t* offset, int depth) {
    if (depth > 10 || *offset >= pkt_len) return "";
    
    std::string name;
    while (*offset < pkt_len) {
        uint8_t len = packet[*offset];
        
        if (len == 0) {
            (*offset)++;
            break;
        }
        
        // Compression pointer
        if ((len & 0xC0) == 0xC0) {
            if (*offset + 1 >= pkt_len) return "";
            size_t ptr = ((len & 0x3F) << 8) | packet[*offset + 1];
            *offset += 2;
            name += parse_dns_name(packet, pkt_len, &ptr, depth + 1);
            return name;
        }
        
        if (*offset + 1 + len > pkt_len) return "";
        (*offset)++;
        
        for (size_t i = 0; i < len; i++) {
            name += (char)packet[*offset + i];
        }
        name += '.';
        *offset += len;
    }
    
    if (!name.empty() && name.back() == '.') {
        name.pop_back();
    }
    return util::to_lower(name);
}

void ExtPacketDecoder::decode_dns(const uint8_t* payload, size_t len, bool tcp, ExtPacketView* out) {
    size_t offset = 0;
    
    // TCP DNS has 2-byte length prefix
    if (tcp) {
        if (len < 2) return;
        offset = 2;
    }
    
    if (len < offset + 12) return;
    
    out->is_dns = true;
    out->dns_query_count = read_be16(payload + offset + 4);
    out->dns_answer_count = read_be16(payload + offset + 6);
    
    size_t qoffset = offset + 12;
    
    // Parse questions
    for (uint16_t i = 0; i < out->dns_query_count && qoffset < len; i++) {
        std::string name = parse_dns_name(payload + offset, len - offset, &qoffset, 0);
        qoffset += offset;  // Adjust for DNS message offset
        if (!name.empty()) {
            out->dns_queries.push_back(name);
            if (out->dns_qname_lower.empty()) {
                out->dns_qname_lower = name;
            }
        }
        qoffset += 4; // Skip QTYPE and QCLASS
        if (qoffset > len) break;
    }
    
    // Parse answers (simplified)
    for (uint16_t i = 0; i < out->dns_answer_count && qoffset < len; i++) {
        size_t name_off = qoffset - offset;
        std::string name = parse_dns_name(payload + offset, len - offset, &name_off, 0);
        qoffset = name_off + offset;
        
        if (qoffset + 10 > len) break;
        uint16_t rtype = read_be16(payload + qoffset);
        qoffset += 8; // Skip TYPE, CLASS, TTL
        uint16_t rdlen = read_be16(payload + qoffset);
        qoffset += 2;
        
        if (rtype == 1 && rdlen == 4 && qoffset + 4 <= len) {
            // A record
            char buf[INET_ADDRSTRLEN];
            in_addr addr;
            std::memcpy(&addr, payload + qoffset, 4);
            if (inet_ntop(AF_INET, &addr, buf, sizeof(buf))) {
                out->dns_answers.push_back(buf);
            }
        } else if (rtype == 28 && rdlen == 16 && qoffset + 16 <= len) {
            // AAAA record
            char buf[INET6_ADDRSTRLEN];
            if (inet_ntop(AF_INET6, payload + qoffset, buf, sizeof(buf))) {
                out->dns_answers.push_back(buf);
            }
        }
        
        qoffset += rdlen;
    }
}

void ExtPacketDecoder::decode_http(const uint8_t* payload, size_t len, ExtPacketView* out) {
    if (len < 10) return;
    
    std::string data((const char*)payload, std::min(len, (size_t)4096));
    
    // Check for HTTP request
    if (data.compare(0, 3, "GET") == 0 || data.compare(0, 4, "POST") == 0 ||
        data.compare(0, 4, "HEAD") == 0 || data.compare(0, 3, "PUT") == 0 ||
        data.compare(0, 6, "DELETE") == 0 || data.compare(0, 7, "OPTIONS") == 0) {
        out->is_http = true;
        
        // Parse request line
        size_t line_end = data.find("\r\n");
        if (line_end != std::string::npos) {
            std::string line = data.substr(0, line_end);
            size_t sp1 = line.find(' ');
            size_t sp2 = line.rfind(' ');
            if (sp1 != std::string::npos && sp2 != std::string::npos && sp1 < sp2) {
                out->http_method = line.substr(0, sp1);
                out->http_uri = line.substr(sp1 + 1, sp2 - sp1 - 1);
            }
        }
    }
    // Check for HTTP response
    else if (data.compare(0, 5, "HTTP/") == 0) {
        out->is_http = true;
        
        // Parse status line
        size_t line_end = data.find("\r\n");
        if (line_end != std::string::npos) {
            size_t sp1 = data.find(' ');
            size_t sp2 = data.find(' ', sp1 + 1);
            if (sp1 != std::string::npos && sp2 != std::string::npos) {
                try {
                    out->http_status_code = std::stoi(data.substr(sp1 + 1, sp2 - sp1 - 1));
                } catch (...) {}
            }
        }
    } else {
        return;
    }
    
    // Parse headers
    size_t pos = data.find("\r\n");
    while (pos != std::string::npos && pos + 2 < data.size()) {
        size_t next = data.find("\r\n", pos + 2);
        if (next == std::string::npos) break;
        if (next == pos + 2) {
            // End of headers
            out->http_body_offset = pos + 4;
            if (out->http_body_offset < len) {
                out->http_body_len = len - out->http_body_offset;
            }
            break;
        }
        
        std::string header = data.substr(pos + 2, next - pos - 2);
        size_t colon = header.find(':');
        if (colon != std::string::npos) {
            std::string name = util::to_lower(header.substr(0, colon));
            std::string value = util::trim(header.substr(colon + 1));
            
            if (name == "host") out->http_host = value;
            else if (name == "user-agent") out->http_user_agent = value;
            else if (name == "content-type") out->http_content_type = value;
        }
        
        pos = next;
    }
}

void ExtPacketDecoder::decode_tls(const uint8_t* payload, size_t len, ExtPacketView* out) {
    if (len < 6) return;
    
    // Check for TLS handshake (content type 22)
    if (payload[0] != 0x16) return;
    
    uint16_t record_version = read_be16(payload + 1);
    uint16_t record_len = read_be16(payload + 3);
    
    if (record_len + 5 > len) return;
    if (len < 10) return;
    
    // Check for ClientHello (handshake type 1)
    if (payload[5] != 0x01) return;
    
    out->is_tls = true;
    out->tls_version = read_be16(payload + 9);
    
    size_t offset = 43; // Skip to session ID length
    if (offset >= len) return;
    
    uint8_t session_id_len = payload[offset++];
    offset += session_id_len;
    if (offset + 2 > len) return;
    
    // Cipher suites
    uint16_t cipher_suite_len = read_be16(payload + offset);
    offset += 2;
    if (offset + cipher_suite_len > len) return;
    
    std::vector<uint16_t> ciphers;
    for (size_t i = 0; i + 1 < cipher_suite_len; i += 2) {
        uint16_t cs = read_be16(payload + offset + i);
        // Filter GREASE values
        if ((cs & 0x0F0F) != 0x0A0A) {
            ciphers.push_back(cs);
        }
    }
    out->tls_cipher_suites = ciphers;
    offset += cipher_suite_len;
    
    // Compression methods
    if (offset >= len) return;
    uint8_t comp_len = payload[offset++];
    offset += comp_len;
    
    // Extensions
    if (offset + 2 > len) return;
    uint16_t ext_len = read_be16(payload + offset);
    offset += 2;
    
    std::vector<uint16_t> extensions;
    std::vector<uint16_t> ec_curves;
    std::vector<uint8_t> ec_formats;
    
    size_t ext_end = offset + ext_len;
    while (offset + 4 <= ext_end && offset + 4 <= len) {
        uint16_t ext_type = read_be16(payload + offset);
        uint16_t ext_size = read_be16(payload + offset + 2);
        offset += 4;
        
        if (offset + ext_size > len) break;
        
        // Filter GREASE values
        if ((ext_type & 0x0F0F) != 0x0A0A) {
            extensions.push_back(ext_type);
        }
        
        // SNI extension (type 0)
        if (ext_type == 0 && ext_size >= 5) {
            size_t sni_off = offset + 2;
            if (sni_off + 3 <= len) {
                uint8_t name_type = payload[sni_off];
                uint16_t name_len = read_be16(payload + sni_off + 1);
                sni_off += 3;
                if (name_type == 0 && sni_off + name_len <= len) {
                    out->tls_sni = std::string((const char*)(payload + sni_off), name_len);
                }
            }
        }
        // ALPN extension (type 16)
        else if (ext_type == 16 && ext_size >= 2) {
            size_t alpn_off = offset + 2;
            size_t alpn_end = offset + ext_size;
            while (alpn_off < alpn_end && alpn_off < len) {
                uint8_t proto_len = payload[alpn_off++];
                if (alpn_off + proto_len <= len) {
                    out->tls_alpn.push_back(std::string((const char*)(payload + alpn_off), proto_len));
                }
                alpn_off += proto_len;
            }
        }
        // EC curves (type 10)
        else if (ext_type == 10 && ext_size >= 2) {
            uint16_t curves_len = read_be16(payload + offset);
            for (size_t i = 2; i + 1 < ext_size && i + 1 < curves_len + 2; i += 2) {
                uint16_t curve = read_be16(payload + offset + i);
                if ((curve & 0x0F0F) != 0x0A0A) {
                    ec_curves.push_back(curve);
                }
            }
        }
        // EC point formats (type 11)
        else if (ext_type == 11 && ext_size >= 1) {
            uint8_t formats_len = payload[offset];
            for (size_t i = 1; i < ext_size && i < formats_len + 1u; i++) {
                ec_formats.push_back(payload[offset + i]);
            }
        }
        
        offset += ext_size;
    }
    
    // Compute JA3
    out->tls_ja3 = compute_ja3(ciphers, extensions, ec_curves, ec_formats, out->tls_version);
}

std::string ExtPacketDecoder::compute_ja3(const std::vector<uint16_t>& cipher_suites,
                                         const std::vector<uint16_t>& extensions,
                                         const std::vector<uint16_t>& ec_curves,
                                         const std::vector<uint8_t>& ec_point_formats,
                                         uint16_t version) {
    std::ostringstream ss;
    
    // Version
    ss << version << ",";
    
    // Ciphers
    for (size_t i = 0; i < cipher_suites.size(); i++) {
        if (i > 0) ss << "-";
        ss << cipher_suites[i];
    }
    ss << ",";
    
    // Extensions
    for (size_t i = 0; i < extensions.size(); i++) {
        if (i > 0) ss << "-";
        ss << extensions[i];
    }
    ss << ",";
    
    // Curves
    for (size_t i = 0; i < ec_curves.size(); i++) {
        if (i > 0) ss << "-";
        ss << ec_curves[i];
    }
    ss << ",";
    
    // Point formats
    for (size_t i = 0; i < ec_point_formats.size(); i++) {
        if (i > 0) ss << "-";
        ss << (int)ec_point_formats[i];
    }
    
    return md5_hex(ss.str());
}

void ExtPacketDecoder::decode_dhcp(const uint8_t* payload, size_t len, ExtPacketView* out) {
    if (len < 240) return;
    
    out->is_dhcp = true;
    out->dhcp_op = payload[0];
    std::memcpy(&out->dhcp_client_ip, payload + 12, 4);
    std::memcpy(&out->dhcp_your_ip, payload + 16, 4);
    std::memcpy(out->dhcp_client_mac.data(), payload + 28, 6);
    
    // Parse DHCP options (starting at offset 240)
    size_t opt_off = 240;
    // Check magic cookie
    if (len >= 244 && payload[240] == 99 && payload[241] == 130 &&
        payload[242] == 83 && payload[243] == 99) {
        opt_off = 244;
    }
    
    while (opt_off + 2 <= len) {
        uint8_t opt_type = payload[opt_off];
        if (opt_type == 255) break; // End
        if (opt_type == 0) { opt_off++; continue; } // Padding
        
        uint8_t opt_len = payload[opt_off + 1];
        opt_off += 2;
        
        if (opt_off + opt_len > len) break;
        
        // Hostname option (12)
        if (opt_type == 12 && opt_len > 0) {
            out->dhcp_hostname = std::string((const char*)(payload + opt_off), opt_len);
        }
        
        opt_off += opt_len;
    }
}

void ExtPacketDecoder::decode_smtp_ftp(const uint8_t* payload, size_t len, 
                                       const std::string& proto, ExtPacketView* out) {
    if (len < 4) return;
    
    std::string data((const char*)payload, std::min(len, (size_t)512));
    std::string data_upper = util::to_lower(data);
    
    out->cred_protocol = proto;
    
    // Look for AUTH LOGIN / AUTH PLAIN in SMTP
    // Or USER/PASS in FTP
    size_t pos = 0;
    while (pos < data.size()) {
        size_t line_end = data.find("\r\n", pos);
        if (line_end == std::string::npos) line_end = data.size();
        
        std::string line = data.substr(pos, line_end - pos);
        std::string line_lower = util::to_lower(line);
        
        // FTP USER command
        if (line_lower.compare(0, 5, "user ") == 0 && line.size() > 5) {
            out->cred_username = util::trim(line.substr(5));
        }
        // FTP PASS command
        else if (line_lower.compare(0, 5, "pass ") == 0 && line.size() > 5) {
            out->cred_password = util::trim(line.substr(5));
        }
        // SMTP AUTH LOGIN
        else if (line_lower.find("auth login") != std::string::npos) {
            // Next lines are base64 username and password
            out->cred_protocol = "smtp_auth_login";
        }
        // SMTP AUTH PLAIN
        else if (line_lower.find("auth plain") != std::string::npos) {
            size_t space = line.find(' ', 11);
            if (space != std::string::npos && space + 1 < line.size()) {
                out->cred_password = line.substr(space + 1);
                out->cred_protocol = "smtp_auth_plain";
            }
        }
        
        pos = line_end + 2;
        if (pos >= data.size()) break;
    }
}
