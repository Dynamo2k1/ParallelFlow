# MPI PCAP Threat Scanner (C++17)

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)]()
[![MPI](https://img.shields.io/badge/MPI-OpenMPI%20%7C%20MPICH-orange.svg)]()
[![License](https://img.shields.io/badge/license-Educational-lightgrey.svg)]()

A **production-grade offline PCAP/PCAPNG analyzer** designed for parallel & distributed computing with comprehensive security analysis capabilities. This tool provides network forensics, threat detection, and traffic analysis using MPI for high-performance distributed processing.

---

## Table of Contents

1. [Overview](#overview)
2. [Key Features](#key-features)
3. [Quick Start](#quick-start)
4. [Installation](#installation)
5. [Executables](#executables)
6. [Usage Guide](#usage-guide)
7. [Command Line Reference](#command-line-reference)
8. [Output Files](#output-files)
9. [Protocol Support](#protocol-support)
10. [Security Analytics](#security-analytics)
11. [GUI Interface](#gui-interface)
12. [Architecture](#architecture)
13. [Configuration](#configuration)
14. [Input File Formats](#input-file-formats)
15. [Performance Tuning](#performance-tuning)
16. [Error Handling](#error-handling)
17. [Troubleshooting](#troubleshooting)
18. [API Reference](#api-reference)
19. [Development](#development)
20. [Contributing](#contributing)
21. [License](#license)

---

## Overview

The MPI PCAP Threat Scanner is a high-performance network traffic analyzer that processes PCAP and PCAPNG files using distributed computing. It's designed for:

- **Security Operations Centers (SOC)**: Automated threat detection and IOC matching
- **Incident Response**: Rapid analysis of captured network traffic
- **Network Forensics**: Deep packet inspection and flow analysis
- **Threat Hunting**: Pattern matching and behavioral analysis
- **Research**: Large-scale network traffic analysis

### Why Use This Tool?

| Feature | Benefit |
|---------|---------|
| **MPI Parallelism** | Process large PCAP files quickly using multiple CPU cores or cluster nodes |
| **Comprehensive Protocol Support** | Decode and analyze dozens of network protocols |
| **Security Analytics** | Built-in threat detection algorithms |
| **Flexible Output** | JSON, NDJSON, and CSV output formats |
| **NetworkMiner-like GUI** | Web-based interface for interactive analysis |
| **Production Ready** | Graceful error handling, deterministic results |

---

## Key Features

### 🚀 Parallel/Distributed Processing
- **MPI multi-process scanning** with rank-parallel packet distribution
- **Deterministic results** across runs regardless of process count
- **Scalable** from single-core to cluster deployments
- Uses MPI collectives: `MPI_Bcast`, `MPI_Reduce`, `MPI_Gather/Gatherv`
- Partition strategies: packet-index modulo scheduling

### 🔒 Security Analytics
- **IOC Matching**: IP blocklists, domain blocklists, keyword scanning
- **Port Scan Detection**: Probabilistic distinct port counting per source IP
- **DNS Tunneling Detection**: Entropy-based subdomain analysis
- **Beaconing Detection**: Periodic connection pattern analysis
- **Data Exfiltration Detection**: Bytes-to-external IP tracking
- **Sensitive Data Detection**: Tokens, cookies, auth headers, credentials

### 📊 Protocol Analysis
- **Layer 2**: Ethernet, VLAN (802.1Q, QinQ), ARP/RARP
- **Layer 3**: IPv4, IPv6 (with extension headers), IGMP, GRE, IPsec
- **Layer 4**: TCP, UDP, ICMP, ICMPv6, SCTP
- **Application**: DNS, HTTP/1.x, TLS, DHCP, SMTP, FTP

### 🔍 Forensics Capabilities
- **File Carving**: Extract files from HTTP responses with SHA256 hashing
- **Credential Detection**: FTP/SMTP plaintext credentials (redacted by default)
- **Flow Tracking**: Bidirectional connection statistics
- **Protocol Logging**: Detailed DNS, HTTP, TLS logs

### 🖥️ GUI Interface
- **Web-based NetworkMiner-like interface**
- **Interactive dashboards** with filtering and search
- **Multiple views**: Hosts, Sessions, DNS, HTTP, TLS, Files, Credentials, Alerts

---

## Quick Start

### 1. Install Dependencies (Ubuntu/Debian)
```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake libpcap-dev openmpi-bin libopenmpi-dev
```

### 2. Build
```bash
git clone https://github.com/your-repo/pcap-analyzer.git
cd pcap-analyzer
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

### 3. Run Analysis
```bash
# Single process
./build/pdc_pcap_analyzer --pcap traffic.pcap --out results/

# Multi-process (8 cores)
mpirun -np 8 ./build/pdc_pcap_analyzer --pcap traffic.pcap --out results/

# With threat detection
mpirun -np 8 ./build/pdc_pcap_analyzer \
  --pcap traffic.pcap \
  --out results/ \
  --ip-blocklist bad_ips.txt \
  --domain-blocklist bad_domains.txt \
  --keywords suspicious_terms.txt
```

### 4. View Results
```bash
# View summary
cat results/summary.json | jq .

# View alerts
cat results/alerts.ndjson | head -20

# Start GUI
./build/pdc_gui --port 8888 --analyzer ./build/pdc_pcap_analyzer
# Open http://localhost:8888
```

---

## Installation

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **OS** | Linux (Ubuntu 18.04+, RHEL 7+) | Ubuntu 22.04 LTS |
| **CPU** | 2 cores | 8+ cores |
| **RAM** | 4 GB | 16+ GB |
| **Disk** | 10 GB free | SSD with 100+ GB |
| **Compiler** | GCC 8+ or Clang 7+ | GCC 11+ |
| **CMake** | 3.16+ | 3.20+ |

### Dependencies

#### Ubuntu / Debian
```bash
sudo apt-get update
sudo apt-get install -y \
  build-essential \
  cmake \
  libpcap-dev \
  openmpi-bin \
  libopenmpi-dev \
  pkg-config
```

#### RHEL / CentOS / Fedora
```bash
sudo dnf install -y \
  gcc-c++ \
  cmake \
  libpcap-devel \
  openmpi \
  openmpi-devel

# Load MPI environment
module load mpi/openmpi-x86_64
```

#### macOS (Homebrew)
```bash
brew install cmake open-mpi libpcap
```

### Building from Source

#### Standard Build
```bash
# Clone repository
git clone https://github.com/your-repo/pcap-analyzer.git
cd pcap-analyzer

# Configure
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release

# Build (parallel)
cmake --build build -j$(nproc)

# Verify
./build/pdc_pcap_analyzer --help
```

#### Debug Build
```bash
cmake -S . -B build-debug -DCMAKE_BUILD_TYPE=Debug
cmake --build build-debug -j$(nproc)
```

#### Build with Tests
```bash
# Install GoogleTest first
sudo apt-get install -y libgtest-dev

cmake -S . -B build -DBUILD_TESTING=ON
cmake --build build -j$(nproc)

# Run tests
cd build && ctest --output-on-failure
```

### Build Options

| Option | Default | Description |
|--------|---------|-------------|
| `CMAKE_BUILD_TYPE` | Release | Build type (Release, Debug, RelWithDebInfo) |
| `BUILD_DASHBOARD` | ON | Build lightweight web dashboard |
| `BUILD_PDC_ANALYZER` | ON | Build production MPI analyzer |
| `BUILD_PDC_GUI` | ON | Build NetworkMiner-like GUI |
| `BUILD_TESTING` | OFF | Build unit tests (requires GoogleTest) |

---

## Executables

The build produces four executables:

### pdc_pcap_analyzer (Recommended)
**Production MPI analyzer** - Full-featured distributed scanner with comprehensive protocol support.

```bash
mpirun -np 8 ./build/pdc_pcap_analyzer --pcap capture.pcap --out output/
```

### pcap_scan_mpi (Legacy)
**Original MPI scanner** - Simpler feature set, IPv4-focused.

```bash
mpirun -np 4 ./build/pcap_scan_mpi --pcap capture.pcap --out output/
```

### pdc_gui
**NetworkMiner-like GUI** - Web interface for interactive network forensics.

```bash
./build/pdc_gui --port 8888 --analyzer ./build/pdc_pcap_analyzer
```

### pcap_dashboard
**Simple web dashboard** - Lightweight viewer for scan results.

```bash
./build/pcap_dashboard --dir output/ --port 8080
```

---

## Usage Guide

### Basic Analysis

```bash
# Analyze a PCAP file
mpirun -np 4 ./build/pdc_pcap_analyzer \
  --pcap /path/to/capture.pcap \
  --out /path/to/output
```

### Threat Detection with IOCs

```bash
mpirun -np 8 ./build/pdc_pcap_analyzer \
  --pcap traffic.pcap \
  --out results/ \
  --ip-blocklist blocked_ips.txt \
  --domain-blocklist blocked_domains.txt \
  --keywords suspicious_keywords.txt
```

### File Carving

```bash
mpirun -np 8 ./build/pdc_pcap_analyzer \
  --pcap traffic.pcap \
  --out results/ \
  --enable-carving
# Carved files will be in results/files/
```

### Progress Monitoring

```bash
# In one terminal
mpirun -np 8 ./build/pdc_pcap_analyzer \
  --pcap large_capture.pcap \
  --out results/ \
  --progress-file /tmp/progress.json

# In another terminal
watch -n 1 cat /tmp/progress.json
```

### BPF Filtering

```bash
# Only analyze HTTP traffic
mpirun -np 4 ./build/pdc_pcap_analyzer \
  --pcap traffic.pcap \
  --out results/ \
  --bpf "tcp port 80"

# Only analyze traffic to/from specific subnet
mpirun -np 4 ./build/pdc_pcap_analyzer \
  --pcap traffic.pcap \
  --out results/ \
  --bpf "net 192.168.1.0/24"
```

### Cluster Deployment

```bash
# Using a hostfile
mpirun --hostfile hosts.txt -np 32 ./build/pdc_pcap_analyzer \
  --pcap /shared/storage/large_capture.pcap \
  --out /shared/storage/results/
```

---

## Command Line Reference

### pdc_pcap_analyzer

```
pdc_pcap_analyzer - Production-grade MPI PCAP/PCAPNG Analyzer

Usage:
  mpirun -np <N> ./pdc_pcap_analyzer [options]

Required Arguments:
  --pcap <file>           Input PCAP or PCAPNG file
  --out <directory>       Output directory (created if not exists)

IOC Files (optional):
  --ip-blocklist <file>   IP blocklist file (IPv4/IPv6, CIDR supported)
  --domain-blocklist <file>  Domain blocklist file
  --keywords <file>       Keywords file for payload scanning

Tuning Options:
  --top-k <N>             Number of top items to track (default: 50)
  --payload-max <bytes>   Max payload bytes to scan (default: 512)
  --portscan-threshold <N>   Distinct ports for portscan alert (default: 64)
  --portscan-window <sec>    Time window for portscan detection (default: 10)
  --max-alerts <N>        Max alerts per MPI rank (0=unlimited, default: 0)

Feature Flags:
  --bpf <filter>          BPF filter expression (e.g., "tcp port 80")
  --progress-file <path>  Write progress JSON periodically
  --keylog <path>         TLS key log file (for metadata extraction)
  --enable-carving        Enable file carving from HTTP responses
  --no-redact             Disable credential redaction in output
  --openmp                Enable OpenMP parallelism within each rank

Help:
  --help, -h              Show this help message

Examples:
  # Basic analysis
  mpirun -np 8 ./pdc_pcap_analyzer --pcap traffic.pcap --out out/

  # Full threat detection
  mpirun -np 16 ./pdc_pcap_analyzer \
    --pcap large.pcapng \
    --out results/ \
    --ip-blocklist bad_ips.txt \
    --domain-blocklist bad_domains.txt \
    --keywords suspicious.txt \
    --enable-carving \
    --progress-file /tmp/progress.json
```

### pdc_gui

```
pdc_gui - NetworkMiner-like Web GUI

Usage:
  ./pdc_gui [options]

Options:
  --port <N>              HTTP port (default: 8888)
  --bind <addr>           Bind address (default: 127.0.0.1)
  --workspace <dir>       Workspace directory (default: /tmp/pdc_workspace)
  --analyzer <path>       Path to pdc_pcap_analyzer (default: ./pdc_pcap_analyzer)
  --help, -h              Show this help message

Example:
  ./pdc_gui --port 8080 --bind 0.0.0.0 --analyzer ./build/pdc_pcap_analyzer
```

### pcap_dashboard

```
pcap_dashboard - Simple Web Dashboard

Usage:
  ./pcap_dashboard [options]

Options:
  --dir <path>            Results directory to serve
  --port <N>              HTTP port (default: 8080)
  --help, -h              Show this help message

Example:
  ./pcap_dashboard --dir /path/to/results --port 8080
```

---

## Output Files

### Directory Structure

```
output/
├── summary.json           # Overall statistics and top-k results
├── alerts.ndjson          # Merged alerts from all ranks
├── alerts_rank0.ndjson    # Per-rank alert files
├── alerts_rank1.ndjson
├── ...
├── flows.csv              # Flow records with statistics
├── dns.jsonl              # DNS protocol logs
├── http.jsonl             # HTTP protocol logs
├── tls.jsonl              # TLS protocol logs
├── payload.jsonl          # Payload extraction logs
├── progress.json          # Scan progress (if enabled)
└── files/                 # Carved files (if enabled)
    ├── a1b2c3d4e5f6.jpg
    ├── f7e8d9c0b1a2.pdf
    └── ...
```

### summary.json

Complete statistics and analysis results.

```json
{
  "world_size": 8,
  "packets": 1500000,
  "bytes": 1200000000,
  "ipv4": 1400000,
  "ipv6": 100000,
  "tcp": 1200000,
  "udp": 280000,
  "icmp": 15000,
  "icmpv6": 3000,
  "arp": 2000,
  "other": 0,
  "dns_queries": 50000,
  "http_requests": 75000,
  "tls_handshakes": 30000,
  "dhcp_messages": 500,
  "alerts_total": 150,
  "alerts_blocklisted_ip": 50,
  "alerts_blocklisted_domain": 30,
  "alerts_keyword": 20,
  "alerts_portscan": 10,
  "alerts_dns_tunnel": 5,
  "alerts_beaconing": 15,
  "alerts_exfil": 10,
  "alerts_sensitive": 10,
  "files_carved": 25,
  "credentials_found": 3,
  "top_src_bytes": [
    {"ip": "192.168.1.100", "count": 500000000},
    {"ip": "192.168.1.101", "count": 300000000}
  ],
  "top_dst_bytes": [
    {"ip": "8.8.8.8", "count": 100000000},
    {"ip": "1.1.1.1", "count": 50000000}
  ],
  "top_dns_qnames": [
    {"key": "google.com", "count": 5000},
    {"key": "facebook.com", "count": 3000}
  ],
  "top_http_hosts": [
    {"key": "www.example.com", "count": 10000},
    {"key": "api.service.com", "count": 5000}
  ],
  "top_tls_sni": [
    {"key": "www.google.com", "count": 8000},
    {"key": "api.github.com", "count": 2000}
  ],
  "portscan_suspects": [
    {"ip": "10.0.0.50", "count": 128}
  ],
  "carved_files": [
    {
      "filename": "a1b2c3d4e5f67890.jpg",
      "sha256": "a1b2c3d4e5f67890abcdef1234567890...",
      "content_type": "image/jpeg",
      "size": 45678,
      "src_ip": "93.184.216.34",
      "dst_ip": "192.168.1.100"
    }
  ]
}
```

### alerts.ndjson

Newline-delimited JSON alerts (one per line).

```json
{"ts":1703275200.123456,"time":"2023-12-22T20:00:00.123456Z","type":"blocklisted_ip","src_ip":"192.168.1.100","dst_ip":"185.143.223.47","proto":"TCP","src_port":54321,"dst_port":443,"detail":"Matched IP blocklist (dst: 185.143.223.47)"}
{"ts":1703275201.234567,"time":"2023-12-22T20:00:01.234567Z","type":"dns_tunnel","src_ip":"192.168.1.50","dst_ip":"8.8.8.8","proto":"DNS","src_port":52341,"dst_port":53,"detail":"Potential DNS tunnel: aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q.evil.com","subdomain_len":52,"entropy":4.21}
{"ts":1703275202.345678,"time":"2023-12-22T20:00:02.345678Z","type":"port_scan","src_ip":"10.0.0.99","dst_ip":"192.168.1.1","proto":"TCP","src_port":45678,"dst_port":22,"detail":"Approx distinct dst ports in window >= 64"}
```

### Alert Types

| Type | Description |
|------|-------------|
| `blocklisted_ip` | Connection to/from blocklisted IP address |
| `blocklisted_domain` | DNS query or connection to blocklisted domain |
| `keyword_match` | Suspicious keyword found in payload |
| `port_scan` | Port scanning behavior detected |
| `dns_tunnel` | Potential DNS tunneling detected |
| `beaconing` | Periodic connection pattern (C2 indicator) |
| `exfiltration` | Large data transfer to external IP |
| `sensitive_data` | Credentials or sensitive data in traffic |
| `suspicious_tls` | Suspicious TLS configuration |
| `arp_spoof` | ARP spoofing detected |

### flows.csv

Flow records for network connection analysis.

```csv
src_ip,dst_ip,src_port,dst_port,proto,packets,bytes,first_ts,last_ts,app_proto
192.168.1.100,93.184.216.34,54321,443,TCP,150,125000,1703275200.123456,1703275260.789012,TLS
192.168.1.100,8.8.8.8,52341,53,UDP,2,150,1703275201.234567,1703275201.235000,DNS
10.0.0.50,192.168.1.1,45678,22,TCP,3,180,1703275202.345678,1703275202.400000,
```

### Protocol Logs

#### dns.jsonl
```json
{"ts":1703275201.234567,"src":"192.168.1.100:52341","dst":"8.8.8.8:53","queries":["www.example.com"],"answers":["93.184.216.34"]}
```

#### http.jsonl
```json
{"ts":1703275200.123456,"src":"192.168.1.100:54321","dst":"93.184.216.34:80","method":"GET","uri":"/index.html","host":"www.example.com","status":200,"content_type":"text/html"}
```

#### tls.jsonl
```json
{"ts":1703275200.500000,"src":"192.168.1.100:54322","dst":"93.184.216.34:443","version":771,"sni":"www.example.com","ja3":"e7d705a3286e19ea42f587b344ee6865","alpn":["h2","http/1.1"]}
```

---

## Protocol Support

### Complete Protocol Matrix

#### Layer 2 (Data Link Layer)

| Protocol | EtherType | Status | Features |
|----------|-----------|--------|----------|
| Ethernet II | - | ✅ Full | Frame parsing, MAC extraction |
| IEEE 802.1Q (VLAN) | 0x8100 | ✅ Full | Single and stacked VLAN tags |
| IEEE 802.1ad (QinQ) | 0x88a8 | ✅ Full | Service VLAN tags |
| ARP | 0x0806 | ✅ Full | Request/reply, IP/MAC mapping |
| RARP | 0x8035 | ✅ Basic | Counted, basic parsing |
| LLDP | 0x88CC | ⚠️ Counted | Protocol recognized |
| 802.1AE (MACsec) | 0x88E5 | ⚠️ Counted | Protocol recognized |
| LACP | 0x8809 | ⚠️ Counted | Protocol recognized |
| Wake-on-LAN | 0x0842 | ⚠️ Counted | Protocol recognized |
| IPX | 0x8137/0x8138 | ⚠️ Counted | Protocol recognized |
| AppleTalk | 0x809B | ⚠️ Counted | Protocol recognized |
| Unknown | * | ⚠️ Counted | Gracefully handled |

#### Layer 3 (Network Layer)

| Protocol | IP Protocol # | Status | Features |
|----------|--------------|--------|----------|
| IPv4 | - | ✅ Full | Header parsing, options, fragments |
| IPv6 | - | ✅ Full | Header, extension headers |
| ICMPv4 | 1 | ✅ Full | Type, code, payload extraction |
| IGMP | 2 | ⚠️ Counted | Protocol recognized |
| TCP | 6 | ✅ Full | (See Layer 4) |
| UDP | 17 | ✅ Full | (See Layer 4) |
| IPv6-in-IPv4 | 41 | ⚠️ Counted | Tunnel recognized |
| GRE | 47 | ⚠️ Counted | Tunnel recognized |
| ESP (IPsec) | 50 | ⚠️ Counted | Encrypted, recognized |
| AH (IPsec) | 51 | ⚠️ Counted | Auth header recognized |
| ICMPv6 | 58 | ✅ Full | Type, code, payload extraction |
| OSPF | 89 | ⚠️ Counted | Routing protocol recognized |
| PIM | 103 | ⚠️ Counted | Multicast recognized |
| VRRP | 112 | ⚠️ Counted | Redundancy recognized |
| SCTP | 132 | ⚠️ Counted | Protocol recognized |
| Mobility Header | 135 | ⚠️ Counted | IPv6 mobility recognized |
| Unknown | * | ⚠️ Counted | Gracefully handled |

#### Layer 4 (Transport Layer)

| Protocol | Features |
|----------|----------|
| **TCP** | Port extraction, sequence/ack numbers, flag detection (SYN, ACK, FIN, RST, PSH), payload extraction, application protocol detection |
| **UDP** | Port extraction, length validation, payload extraction, application protocol detection |
| **ICMP** | Type and code extraction, payload capture |
| **ICMPv6** | Type and code extraction, payload capture |

#### Application Layer

| Protocol | Ports | Status | Features |
|----------|-------|--------|----------|
| **DNS** | 53 | ✅ Full | Query/answer parsing, domain extraction, response records (A, AAAA, CNAME, MX, TXT) |
| **HTTP/1.x** | 80, 8080 | ✅ Full | Request/response parsing, method, URI, headers, status codes, body extraction |
| **HTTPS/TLS** | 443 | ✅ Full | ClientHello parsing, SNI, ALPN, cipher suites, JA3 fingerprinting |
| **DHCP** | 67, 68 | ✅ Full | Option parsing, hostname, IP assignments, lease info |
| **FTP** | 21 | ✅ Basic | USER/PASS credential detection |
| **SMTP** | 25, 587 | ✅ Basic | AUTH credential detection |
| **SSH** | 22 | ⚠️ Counted | Encrypted, protocol recognized |
| **RDP** | 3389 | ⚠️ Counted | Protocol recognized |
| **MySQL** | 3306 | ⚠️ Counted | Protocol recognized |
| **PostgreSQL** | 5432 | ⚠️ Counted | Protocol recognized |

### Status Legend
- ✅ **Full**: Complete parsing and analysis
- ⚠️ **Counted**: Protocol recognized, packets counted
- ❌ **Not Supported**: Protocol not recognized

---

## Security Analytics

### IOC Matching

#### IP Blocklist Matching
- Supports IPv4 and IPv6 addresses
- CIDR notation for network ranges
- Matches both source and destination IPs

#### Domain Blocklist Matching
- Exact domain matching
- Suffix matching (e.g., `evil.com` matches `sub.evil.com`)
- Applied to DNS queries, HTTP Host headers, and TLS SNI

#### Keyword Scanning
- Aho-Corasick multi-pattern matching
- Scans TCP/UDP payloads
- Configurable payload scan length

### Behavioral Detection

#### Port Scan Detection
```
Algorithm: Probabilistic distinct port counting using HyperLogLog-style sketching
Parameters:
  - portscan-threshold: Minimum distinct ports to trigger (default: 64)
  - portscan-window: Time window in seconds (default: 10)
Detection: Alert when source IP contacts >= threshold distinct ports within window
```

#### DNS Tunneling Detection
```
Algorithm: Entropy-based subdomain analysis
Parameters:
  - dns_tunnel_entropy_threshold: Minimum entropy (default: 3.5)
  - dns_tunnel_len_threshold: Minimum subdomain length (default: 50)
Detection: Alert on high-entropy, long subdomains (base64/hex encoded data)
```

#### Beaconing Detection
```
Algorithm: Connection interval analysis
Parameters:
  - beaconing_min_count: Minimum connections to analyze (default: 10)
  - beaconing_interval_tolerance: Allowed variance (default: 0.1 = 10%)
Detection: Alert on regular periodic connections (C2 communication pattern)
```

#### Data Exfiltration Detection
```
Algorithm: Cumulative bytes to external IPs
Parameters:
  - exfil_bytes_threshold: Bytes threshold (default: 10MB)
Detection: Alert when bytes sent to single external IP exceeds threshold
```

### Sensitive Data Detection

Scans payloads for:
- `Authorization: Basic` headers
- `Authorization: Bearer` tokens
- API keys (`api_key=`, `apikey=`)
- Passwords in URLs (`password=`, `passwd=`)
- Secrets (`secret=`, `token=`)
- Cookies (`Set-Cookie:`)
- FTP credentials (`USER`, `PASS` commands)
- SMTP credentials (`AUTH LOGIN`, `AUTH PLAIN`)

---

## GUI Interface

### Starting the GUI

```bash
./build/pdc_gui --port 8888 --analyzer ./build/pdc_pcap_analyzer
```

Open http://localhost:8888 in your browser.

### GUI Tabs

| Tab | Description |
|-----|-------------|
| **Scan** | Upload PCAP files, configure analysis options, start scans |
| **Summary** | Overview statistics, protocol distribution charts, top talkers |
| **Hosts** | All detected IP addresses with traffic statistics, filtering |
| **Sessions** | TCP/UDP flows with application protocol detection |
| **DNS** | Domain queries with counts, response records, filtering |
| **HTTP** | HTTP hosts, requests, responses, headers |
| **TLS** | TLS metadata: SNI, cipher suites, JA3 fingerprints |
| **Files** | Carved files with SHA256 hashes, download links |
| **Credentials** | Detected credentials (redacted by default) |
| **Alerts** | Security alerts with severity filtering and search |

### GUI Options

| Option | Default | Description |
|--------|---------|-------------|
| `--port` | 8888 | HTTP server port |
| `--bind` | 127.0.0.1 | Bind address (use 0.0.0.0 for all interfaces) |
| `--workspace` | /tmp/pdc_workspace | Directory for uploads and results |
| `--analyzer` | ./pdc_pcap_analyzer | Path to analyzer executable |

---

## Architecture

### System Design

```
┌─────────────────────────────────────────────────────────────────┐
│                        PCAP File Input                          │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                    MPI Process Distribution                      │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐     ┌──────────┐       │
│  │  Rank 0  │ │  Rank 1  │ │  Rank 2  │ ... │  Rank N  │       │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘     └────┬─────┘       │
│       │            │            │                 │             │
│       ▼            ▼            ▼                 ▼             │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              Packet Processing Pipeline                  │   │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────────────┐│   │
│  │  │ Decode  │→│Protocol │→│Security │→│  Results        ││   │
│  │  │ Packet  │ │ Parse   │ │ Checks  │ │  Aggregation    ││   │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────────────┘│   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                    MPI Collective Operations                     │
│         MPI_Reduce (counters) + MPI_Gatherv (top-k)             │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Result Merging (Rank 0)                       │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐             │
│  │ Merge Top-K  │ │ Merge Alerts │ │ Write Output │             │
│  └──────────────┘ └──────────────┘ └──────────────┘             │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                        Output Files                              │
│   summary.json │ alerts.ndjson │ flows.csv │ protocol logs      │
└─────────────────────────────────────────────────────────────────┘
```

### Packet Processing Pipeline

1. **Packet Distribution**: `packet_index % world_size == rank`
2. **Layer 2 Decode**: Ethernet frame, VLAN tags
3. **Layer 3 Decode**: IPv4/IPv6 headers, ARP
4. **Layer 4 Decode**: TCP/UDP/ICMP headers
5. **Application Decode**: DNS, HTTP, TLS, DHCP, etc.
6. **Security Checks**: IOC matching, behavioral detection
7. **Result Aggregation**: Counters, top-k, alerts, flows

### Data Structures

#### Space-Saving Algorithm
Used for top-k heavy hitters (source IPs, destination IPs, domains, etc.)
- Memory efficient: O(k) space
- Approximate counts with guaranteed error bounds

#### HyperLogLog-style Sketching
Used for port scan detection
- Estimates distinct port counts
- Constant memory regardless of data size

### MPI Communication Patterns

| Operation | Purpose |
|-----------|---------|
| `MPI_Bcast` | Distribute configuration, total packet count |
| `MPI_Barrier` | Synchronization points |
| `MPI_Reduce` | Sum counters across all ranks |
| `MPI_Gatherv` | Collect variable-length top-k lists |

---

## Configuration

### Default Values

| Parameter | Default | Description |
|-----------|---------|-------------|
| `top_k` | 50 | Number of top items to track |
| `payload_max` | 512 | Max payload bytes to scan |
| `portscan_threshold` | 64 | Distinct ports for alert |
| `portscan_window` | 10 | Time window (seconds) |
| `max_alerts_per_rank` | 0 (unlimited) | Alert limit per rank |
| `dns_tunnel_entropy_threshold` | 3.5 | Entropy threshold |
| `dns_tunnel_len_threshold` | 50 | Subdomain length threshold |
| `beaconing_min_count` | 10 | Minimum samples for detection |
| `beaconing_interval_tolerance` | 0.1 | Allowed variance (10%) |
| `exfil_bytes_threshold` | 10000000 | Bytes threshold (10MB) |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `OMPI_MCA_*` | OpenMPI configuration |
| `OMP_NUM_THREADS` | OpenMP threads (if --openmp used) |

---

## Input File Formats

### IP Blocklist

One entry per line. Comments start with `#`.

```
# Known malicious IPs
185.143.223.47
91.195.240.94

# Suspicious ranges
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16

# IPv6
2001:db8::1
2001:db8::/32
```

### Domain Blocklist

One domain per line. Matches exact domain or any subdomain.

```
# Malware domains
malware.example.com
evil-domain.org

# This will match:
# - evil-domain.org
# - sub.evil-domain.org
# - deep.sub.evil-domain.org
```

### Keywords

One keyword per line. Case-sensitive matching.

```
# Suspicious commands
powershell
cmd.exe
/bin/bash
wget
curl

# Sensitive paths
/etc/passwd
/etc/shadow
.htpasswd

# Credentials
password=
api_key=
Authorization:
```

---

## Performance Tuning

### MPI Process Count

| PCAP Size | Recommended Processes |
|-----------|----------------------|
| < 100 MB | 1-2 |
| 100 MB - 1 GB | 2-4 |
| 1 GB - 10 GB | 4-8 |
| > 10 GB | 8-16+ |

### Memory Usage

- Base memory: ~100 MB per process
- Per-flow tracking: ~200 bytes per active flow
- Top-k structures: ~1 KB per tracked item
- Alert buffer: ~500 bytes per alert

### Optimizations

1. **Use BPF filters** to reduce packet processing
2. **Increase `--payload-max`** for better keyword detection (costs memory)
3. **Limit `--max-alerts`** to prevent alert flooding
4. **Use SSD storage** for output files
5. **Place PCAP on fast storage** (NVMe, ramdisk)

---

## Error Handling

### Graceful Handling

The analyzer handles various edge cases without crashing:

| Scenario | Behavior |
|----------|----------|
| Empty PCAP file | Exits cleanly, creates empty output files |
| Unknown protocols | Counted as "other", no error |
| Truncated packets | Partially decoded, still counted |
| Non-Ethernet captures | Warning displayed, processing continues |
| Malformed headers | Gracefully handled, packet counted |
| File I/O errors | Error message, clean exit |
| MPI errors | Coordinated abort with message |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Runtime error |
| 2 | Invalid arguments |

---

## Troubleshooting

### Common Issues

#### "MPI not found" during build
```bash
# Ubuntu/Debian
sudo apt-get install openmpi-bin libopenmpi-dev

# RHEL/Fedora
sudo dnf install openmpi openmpi-devel
module load mpi/openmpi-x86_64
```

#### "libpcap not found" during build
```bash
# Ubuntu/Debian
sudo apt-get install libpcap-dev

# RHEL/Fedora
sudo dnf install libpcap-devel
```

#### "Not enough slots" MPI error
```bash
# Use oversubscribe flag
mpirun --oversubscribe -np 8 ./build/pdc_pcap_analyzer ...

# Or specify slots in hostfile
echo "localhost slots=8" > hostfile
mpirun --hostfile hostfile -np 8 ./build/pdc_pcap_analyzer ...
```

#### Empty output / 0 packets processed
- Verify PCAP file is not empty
- Check file permissions
- Verify PCAP format (use `tcpdump -r file.pcap` to test)

#### High memory usage
- Reduce `--top-k` value
- Reduce `--payload-max` value
- Use BPF filter to reduce packets
- Use fewer MPI processes

---

## API Reference

### Key Classes

#### ExtPacketDecoder
Decodes raw packets into structured `ExtPacketView` objects.

```cpp
class ExtPacketDecoder {
public:
    bool decode(const uint8_t* data, size_t len, double ts_epoch, ExtPacketView* out);
};
```

#### ExtScanner
Performs security analysis on decoded packets.

```cpp
class ExtScanner {
public:
    ExtScanner(const ExtScanConfig& cfg, IocLists iocs);
    void process_packet(const ExtPacketView& pv, size_t raw_len,
                       ExtAlertWriter& alerts, ExtLocalResults& res,
                       ProtocolLogWriter* proto_logs = nullptr);
};
```

#### SpaceSaving
Approximate top-k tracking using Space-Saving algorithm.

```cpp
template<typename K, typename V>
class SpaceSaving {
public:
    SpaceSaving(size_t k);
    void add(const K& key, V count);
    std::vector<Item> top() const;
};
```

### Protocol Types

```cpp
enum class L4Proto : uint8_t {
    TCP = 6,
    UDP = 17,
    ICMP = 1,
    ICMPV6 = 58,
    OTHER = 0
};

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
```

---

## Development

### Project Structure

```
pcap-analyzer/
├── CMakeLists.txt          # Build configuration
├── README.md               # This file
├── Doxyfile                # Doxygen configuration
├── include/                # Header files
│   ├── aho_corasick.h      # Multi-pattern matching
│   ├── args.h              # Argument parsing
│   ├── common.h            # Utility functions
│   ├── ext_decoder.h       # Extended packet decoder
│   ├── ext_scanner.h       # Extended security scanner
│   ├── ioc.h               # IOC loading
│   ├── mpi_gather.h        # MPI serialization
│   ├── pcap_decode.h       # Legacy decoder
│   ├── protocol_types.h    # Type definitions
│   ├── scanner.h           # Legacy scanner
│   └── space_saving.h      # Top-k algorithm
├── src/                    # Source files
│   ├── main_pdc_analyzer.cpp  # Main analyzer
│   ├── main_mpi.cpp        # Legacy analyzer
│   ├── ext_decoder.cpp     # Packet decoding
│   ├── ext_scanner.cpp     # Security scanning
│   ├── pcap_decode.cpp     # Legacy decoding
│   ├── scanner.cpp         # Legacy scanning
│   ├── common.cpp          # Utilities
│   ├── ioc.cpp             # IOC loading
│   ├── mpi_gather.cpp      # MPI helpers
│   └── args.cpp            # Argument parsing
├── tools/                  # Additional tools
│   ├── dashboard/          # Web dashboard
│   └── gui/                # NetworkMiner-like GUI
├── tests/                  # Unit tests
├── examples/               # Example files
└── docs/                   # Documentation
```

### Building Tests

```bash
cmake -S . -B build -DBUILD_TESTING=ON
cmake --build build
cd build && ctest --output-on-failure
```

### Generating Documentation

```bash
doxygen Doxyfile
# Output: docs/doxygen/html/index.html
```

---

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes with tests
4. Run linting and tests
5. Submit pull request

### Code Style
- C++17 standard
- 4-space indentation
- Braces on same line
- Descriptive variable names

---

## 👥 Contributors

A huge thanks to the team that made this project possible:

  * 👨‍💻 **Rana Uzair Ahmad** - [Dynamo2k](https://github.com/Dynamo2k)
  * 👨‍💻 **Muhammad Usman** - [Prof.Paradox](https://github.com/ProfParadox3)

---
## License

This project is for educational and research purposes. See LICENSE file for details.

---

## Acknowledgments

- libpcap developers
- OpenMPI team
- Network forensics community

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2023-12-22 | Initial release with full protocol support |
| 1.0.1 | 2023-12-22 | Fixed MPI abort on empty PCAP files |
| 1.0.2 | 2023-12-22 | Improved protocol handling for all types |

---

*For questions or issues, please open a GitHub issue.*
