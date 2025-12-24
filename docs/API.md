# MPI PCAP Analyzer - API Documentation

## Overview

This document provides API documentation for the core classes and functions in the MPI PCAP Threat Scanner.

## Core Classes

### ExtPacketDecoder

**Header**: `include/ext_decoder.h`  
**Implementation**: `src/ext_decoder.cpp`

Decodes raw Ethernet frames into structured packet views.

#### Public Methods

```cpp
/**
 * @brief Decode a raw Ethernet frame
 * @param data Pointer to raw packet data
 * @param len Length of packet data in bytes
 * @param ts_epoch Timestamp as Unix epoch with fractional seconds
 * @param out Output packet view structure
 * @return true if packet was successfully decoded at least to L2/L3
 */
bool decode(const uint8_t* data, size_t len, double ts_epoch, ExtPacketView* out);
```

---

### ExtScanner

**Header**: `include/ext_scanner.h`  
**Implementation**: `src/ext_scanner.cpp`

Main analysis engine that processes packets and generates alerts.

#### Constructor

```cpp
/**
 * @brief Construct scanner with configuration and IOC lists
 * @param cfg Scan configuration
 * @param iocs Indicators of Compromise lists
 */
ExtScanner(const ExtScanConfig& cfg, IocLists iocs);
```

#### Public Methods

```cpp
/**
 * @brief Process a single decoded packet
 * @param pv Decoded packet view
 * @param raw_len Original raw packet length
 * @param alerts Alert writer for security alerts
 * @param res Local results accumulator
 * @param proto_logs Optional protocol log writer
 */
void process_packet(const ExtPacketView& pv, size_t raw_len, 
                   ExtAlertWriter& alerts, ExtLocalResults& res,
                   ProtocolLogWriter* proto_logs = nullptr);

/**
 * @brief Extract files from HTTP response bodies
 * @param pv Packet view containing HTTP response
 * @param res Results structure to store carved file info
 */
void carve_file(const ExtPacketView& pv, ExtLocalResults& res);

/**
 * @brief Write scan progress to JSON file
 * @param path Output file path
 * @param progress Progress structure with current stats
 */
void write_progress(const std::string& path, const ScanProgress& progress);
```

---

### ExtAlertWriter

**Header**: `include/ext_scanner.h`

Writes security alerts to NDJSON format files.

#### Public Methods

```cpp
/**
 * @brief Open alert output file
 * @param path Output file path
 * @param err Error message output (if failed)
 * @return true on success
 */
bool open(const std::string& path, std::string* err);

/**
 * @brief Close the output file
 */
void close();

/**
 * @brief Check if alert limit not reached
 * @return true if more alerts can be written
 */
bool can_write_more() const;

/**
 * @brief Write a security alert
 * @param ts Timestamp
 * @param type Alert type enum
 * @param src_ip Source IP address string
 * @param dst_ip Destination IP address string
 * @param proto Protocol string (TCP/UDP/etc)
 * @param src_port Source port
 * @param dst_port Destination port
 * @param detail Human-readable alert details
 * @param extra_json Additional JSON fields (optional)
 */
void write_alert(double ts, AlertType type,
                 const std::string& src_ip, const std::string& dst_ip,
                 const std::string& proto,
                 uint16_t src_port, uint16_t dst_port,
                 const std::string& detail,
                 const std::string& extra_json = "");
```

---

### AhoCorasick

**Header**: `include/aho_corasick.h`

Multi-pattern string matching algorithm for payload scanning.

#### Public Methods

```cpp
/**
 * @brief Build the automaton from keywords
 * @param keywords Vector of patterns to match
 */
void build(const std::vector<std::string>& keywords);

/**
 * @brief Check if automaton has been built
 * @return true if ready for searching
 */
bool built() const;

/**
 * @brief Get the keywords used to build the automaton
 * @return const reference to keywords vector
 */
const std::vector<std::string>& keywords() const;

/**
 * @brief Search for keyword matches in data
 * @tparam BytePtr Pointer type to byte data
 * @param data Input data to search
 * @param n Length of data
 * @param max_matches Maximum matches to return (0 = unlimited)
 * @return Vector of Match structures
 */
template <typename BytePtr>
std::vector<Match> search(BytePtr data, size_t n, size_t max_matches = 0) const;
```

---

### SpaceSaving<Key, Count>

**Header**: `include/space_saving.h`

Space-efficient approximate top-K algorithm.

#### Template Parameters
- `Key`: Type for item keys (e.g., `uint32_t` for IP, `std::string` for domains)
- `Count`: Counter type (default `uint64_t`)

#### Public Methods

```cpp
/**
 * @brief Construct with specified capacity
 * @param capacity Maximum number of items to track
 */
explicit SpaceSaving(size_t capacity = 50);

/**
 * @brief Update capacity (may prune existing items)
 * @param cap New capacity
 */
void set_capacity(size_t cap);

/**
 * @brief Add or increment item count
 * @param k Item key
 * @param w Count to add (default 1)
 */
void add(const Key& k, Count w = 1);

/**
 * @brief Get top items sorted by count descending
 * @return Vector of Item structures with key, count, and error
 */
std::vector<Item> top() const;

/**
 * @brief Get current capacity
 * @return Maximum items tracked
 */
size_t capacity() const;
```

---

## Data Structures

### ExtPacketView

Decoded packet information.

```cpp
struct ExtPacketView {
    double ts_epoch;           // Packet timestamp
    
    // Layer 3
    bool is_ipv4;
    bool is_ipv6;
    bool is_arp;
    uint32_t src_ip4_be;       // IPv4 source (network byte order)
    uint32_t dst_ip4_be;       // IPv4 destination
    std::array<uint8_t, 16> src_ip6;  // IPv6 source
    std::array<uint8_t, 16> dst_ip6;  // IPv6 destination
    
    // Layer 4
    L4Proto l4;                // TCP/UDP/ICMP/OTHER
    uint16_t src_port;
    uint16_t dst_port;
    
    // Application layer
    bool is_dns;
    bool is_http;
    bool is_tls;
    bool is_dhcp;
    
    // Protocol-specific metadata
    std::string dns_qname_lower;
    std::string http_method;
    std::string http_uri;
    std::string http_host;
    std::string tls_sni;
    std::string tls_ja3;
    
    // Payload pointer and length
    const uint8_t* payload;
    size_t payload_len;
};
```

### ExtScanConfig

Scanner configuration options.

```cpp
struct ExtScanConfig {
    std::string pcap_path;         // Input PCAP file
    std::string out_dir;           // Output directory
    
    std::string ip_blocklist_path; // IP blocklist file
    std::string domain_blocklist_path;
    std::string keywords_path;
    std::string bpf_filter;        // BPF filter expression
    
    int top_k = 50;                // Top-K items to track
    int payload_max = 512;         // Max payload bytes to scan
    int portscan_threshold = 64;   // Distinct ports for alert
    int portscan_window_seconds = 10;
    
    bool enable_carving = false;   // File carving from HTTP
    bool redact_secrets = true;    // Redact credentials
};
```

### AlertType

Security alert categories.

```cpp
enum class AlertType {
    BlocklistedIP,      // IP in blocklist
    BlocklistedDomain,  // Domain in blocklist
    KeywordMatch,       // Payload keyword match
    PortScan,           // Port scan detected
    DNSTunnel,          // DNS tunneling suspected
    Beaconing,          // Periodic connection pattern
    Exfiltration,       // Data exfiltration detected
    SensitiveData,      // Credentials/tokens found
    SuspiciousTLS,      // Suspicious TLS behavior
    ARPSpoof            // ARP spoofing detected
};
```

---

## Utility Functions

### util namespace

**Header**: `include/common.h`

```cpp
namespace util {
    // String utilities
    std::string trim(const std::string& s);
    bool starts_with(const std::string& s, const std::string& prefix);
    std::string to_lower(std::string s);
    
    // File utilities
    bool ensure_dir(const std::string& path);
    bool file_exists(const std::string& path);
    
    // IP utilities
    std::string ip_to_string(uint32_t ipv4_be);
    uint32_t parse_ipv4_be(const std::string& s, bool* ok);
    
    // Formatting
    std::string iso8601_utc(double epoch_seconds);
    std::string json_escape(const std::string& s);
    
    // File I/O
    std::vector<std::string> read_lines(const std::string& path, std::string* err);
}
```

---

## MPI Communication Functions

**Header**: `include/mpi_gather.h`

```cpp
/**
 * @brief Serialize IP count data for MPI transfer
 */
std::vector<uint8_t> serialize_ipcounts(const std::vector<IpCount>& v);
std::vector<IpCount> deserialize_ipcounts(const uint8_t* data, size_t n);

/**
 * @brief Serialize string count data for MPI transfer
 */
std::vector<uint8_t> serialize_strcounts(const std::vector<StrCount>& v);
std::vector<StrCount> deserialize_strcounts(const uint8_t* data, size_t n);

/**
 * @brief Gather variable-length buffers from all ranks to root
 * @param local Local buffer from this rank
 * @param root Root rank to gather to
 * @param comm MPI communicator
 * @return Vector of buffers (only populated on root)
 */
std::vector<std::vector<uint8_t>> mpi_gather_buffers(
    const std::vector<uint8_t>& local, int root, MPI_Comm comm);
```

---

## IOC Functions

**Header**: `include/ioc.h`

```cpp
/**
 * @brief Load IOC lists from files
 * @param ip_blocklist_path Path to IP blocklist (IPv4/IPv6, CIDR)
 * @param domain_blocklist_path Path to domain blocklist
 * @param keywords_path Path to keywords file
 * @return Result structure with lists and error info
 */
IocLoadResult load_iocs(const std::string& ip_blocklist_path,
                        const std::string& domain_blocklist_path,
                        const std::string& keywords_path);

/**
 * @brief Check if IP is blocklisted
 */
bool ip_is_blocklisted(uint32_t ip_be, const IocLists& l);

/**
 * @brief Check if domain is blocklisted (includes subdomain matching)
 */
bool domain_is_blocklisted(const std::string& qname_lower, const IocLists& l);
```
