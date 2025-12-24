# MPI PCAP Threat Scanner - Architecture Guide

## Overview

This document describes the architecture of the MPI PCAP Threat Scanner, a high-performance C++17 network forensics tool designed for distributed computing environments.

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              PCAP/PCAPNG File                               │
└────────────────────────────────────┬────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           MPI WORK DISTRIBUTION                             │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐        │
│  │   Rank 0     │ │   Rank 1     │ │   Rank 2     │ │   Rank N     │        │
│  │ packets%N==0 │ │ packets%N==1 │ │ packets%N==2 │ │ packets%N==N │        │
│  └──────┬───────┘ └──────┬───────┘ └──────┬───────┘ └──────┬───────┘        │
└─────────┼────────────────┼────────────────┼────────────────┼────────────────┘
          │                │                │                │
          ▼                ▼                ▼                ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         PACKET PROCESSING PIPELINE                          │
│                                                                             │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐      │
│  │ L2 Decode   │──▶│ L3 Decode   │──▶│ L4 Decode   │──▶│ L7 Decode   │      │
│  │ Ethernet    │   │ IPv4/IPv6   │   │ TCP/UDP     │   │ DNS/HTTP/   │      │
│  │ VLAN        │   │ ARP         │   │ ICMP        │   │ TLS/DHCP    │      │
│  └─────────────┘   └─────────────┘   └─────────────┘   └─────────────┘      │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          ANALYSIS MODULES                                    │
│                                                                             │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐      │
│  │ IOC Check   │   │ Port Scan   │   │ DNS Tunnel  │   │ Beaconing   │      │
│  │ IP/Domain   │   │ Detection   │   │ Detection   │   │ Detection   │      │
│  └─────────────┘   └─────────────┘   └─────────────┘   └─────────────┘      │
│                                                                             │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐      │
│  │ Exfil       │   │ Sensitive   │   │ File        │   │ Flow        │      │
│  │ Detection   │   │ Data Check  │   │ Carving     │   │ Tracking    │      │
│  └─────────────┘   └─────────────┘   └─────────────┘   └─────────────┘      │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          MPI RESULT AGGREGATION                              │
│                                                                             │
│        MPI_Reduce              MPI_Gather             MPI_Barrier            │
│       (Counters)            (Top-K Lists)           (Synchronize)            │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           OUTPUT GENERATION                                  │
│                                                                             │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐      │
│  │ summary.json│   │alerts.ndjson│   │  flows.csv  │   │  *.jsonl    │      │
│  │             │   │             │   │             │   │ Protocol    │      │
│  │ Statistics  │   │ Security    │   │ Connection  │   │ Logs        │      │
│  │ Top-K       │   │ Alerts      │   │ Records     │   │             │      │
│  └─────────────┘   └─────────────┘   └─────────────┘   └─────────────┘      │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Core Modules

### 1. Packet Reader Module

**File**: `src/main_pdc_analyzer.cpp`

The packet reader uses libpcap to read PCAP/PCAPNG files:

- Supports both PCAP and PCAPNG formats natively
- BPF filter support for early packet filtering
- Handles large multi-GB capture files efficiently
- Each MPI rank reads the entire file but processes only assigned packets

```cpp
// Work partitioning: packet_index % world_size == rank
if ((int)(pkt_idx % (size_t)world) == rank) {
    process_packet(pv, ...);
}
```

### 2. Protocol Decoder Pipeline

**Files**: `src/ext_decoder.cpp`, `include/ext_decoder.h`

The decoder implements a layered parsing approach:

```
┌─────────────────────────────────────────────────────┐
│ Layer 2: Ethernet                                   │
│  ├─ Source/Destination MAC                          │
│  ├─ EtherType detection                             │
│  └─ VLAN tag handling (802.1Q, 802.1ad)            │
├─────────────────────────────────────────────────────┤
│ Layer 3: Network                                    │
│  ├─ IPv4: Source/Dest IP, Protocol, Flags          │
│  ├─ IPv6: Extended headers, Flow labels            │
│  └─ ARP: Sender/Target MAC and IP                  │
├─────────────────────────────────────────────────────┤
│ Layer 4: Transport                                  │
│  ├─ TCP: Ports, Sequence, Flags (SYN/ACK/FIN/RST)  │
│  ├─ UDP: Ports, Length, Checksum                   │
│  └─ ICMP/ICMPv6: Type, Code                        │
├─────────────────────────────────────────────────────┤
│ Layer 7: Application                                │
│  ├─ DNS: Query/Answer parsing, Domain extraction   │
│  ├─ HTTP: Method, URI, Headers, Body               │
│  ├─ TLS: ClientHello, SNI, JA3 fingerprint         │
│  ├─ DHCP: Options parsing, Hostname                │
│  └─ SMTP/FTP: Plaintext credential extraction      │
└─────────────────────────────────────────────────────┘
```

### 3. Security Analysis Engine

**Files**: `src/ext_scanner.cpp`, `include/ext_scanner.h`

Multiple detection algorithms run in parallel:

| Detection | Algorithm | Description |
|-----------|-----------|-------------|
| IOC Matching | Hash lookup + CIDR | IP and domain blocklist checking |
| Keyword Scan | Aho-Corasick | O(n) multi-pattern payload scanning |
| Port Scan | Probabilistic Counting | Sketch-based distinct port estimation |
| DNS Tunnel | Entropy Analysis | High-entropy subdomain detection |
| Beaconing | Interval Analysis | Periodic connection pattern detection |
| Exfiltration | Volume Tracking | Bytes sent to external IPs |
| Sensitive Data | Pattern Matching | Credentials, tokens, cookies |

### 4. MPI Communication

**Files**: `src/mpi_gather.cpp`, `include/mpi_gather.h`

MPI operations used:

```cpp
// Broadcast packet count to all ranks
MPI_Bcast(&total_packets, 1, MPI_UINT64_T, 0, comm);

// Reduce counters to rank 0
MPI_Reduce(&local, &global, sizeof(Counters)/sizeof(uint64_t), 
           MPI_UINT64_T, MPI_SUM, 0, comm);

// Gather variable-length data from all ranks
std::vector<std::vector<uint8_t>> gathered = 
    mpi_gather_buffers(local_buffer, 0, comm);

// Synchronize before output
MPI_Barrier(comm);
```

### 5. Top-K Heavy Hitters

**File**: `include/space_saving.h`

Uses the Space-Saving algorithm for memory-efficient top-K tracking:

- O(1) update per element
- O(k) memory usage for top-k items
- Guaranteed to find items with frequency > n/k
- Used for: source/dest IPs, DNS domains, HTTP hosts, TLS SNI

### 6. File Carving

**File**: `src/ext_scanner.cpp` (carve_file method)

Extracts files from HTTP responses:
- Magic byte detection for file type
- SHA256 hashing of carved content
- Content-Type based extension mapping
- Metadata tracking (source, destination, timestamp)

## Data Flow

### Input Processing

1. **PCAP Reading**: Each rank opens the PCAP file
2. **BPF Filtering**: Optional packet pre-filtering
3. **Index Distribution**: Packets assigned by `index % world_size`
4. **Decoding**: Multi-layer protocol parsing
5. **Analysis**: Security checks and feature extraction

### Result Aggregation

1. **Local Results**: Each rank accumulates local statistics
2. **MPI Reduce**: Counters summed across all ranks
3. **MPI Gather**: Top-K lists collected on rank 0
4. **Merging**: Rank 0 merges and deduplicates results
5. **Output**: JSON/CSV/NDJSON files written

## Output Format

### summary.json
```json
{
  "world_size": 4,
  "packets": 1000000,
  "bytes": 500000000,
  "ipv4": 950000,
  "ipv6": 50000,
  "tcp": 800000,
  "udp": 180000,
  "alerts_total": 150,
  "top_src_bytes": [{"ip": "192.168.1.10", "count": 10000000}],
  "top_dns_qnames": [{"key": "example.com", "count": 1000}]
}
```

### alerts.ndjson (Newline-delimited JSON)
```json
{"ts":1704067200.123,"type":"blocklisted_ip","src_ip":"10.0.0.1","dst_ip":"1.2.3.4","proto":"TCP","detail":"Matched IP blocklist"}
{"ts":1704067201.456,"type":"port_scan","src_ip":"192.168.1.100","detail":"Approx distinct dst ports >= 64"}
```

### flows.csv
```csv
src_ip,dst_ip,src_port,dst_port,proto,packets,bytes,first_ts,last_ts,app_proto
192.168.1.1,93.184.216.34,54321,443,TCP,100,150000,1704067200.000,1704067210.000,TLS
```

## Performance Considerations

### Scaling
- Linear scaling with MPI rank count (up to file I/O limits)
- Deterministic results regardless of rank count
- Memory usage: O(top_k + alerts + flows) per rank

### Optimization Techniques
- Zero-copy packet views (pointers into mmap'd buffer)
- Batch I/O for alert writing
- Lazy string conversion
- Efficient hash functions for flow keys

## Security Considerations

1. **Credential Redaction**: Enabled by default (`--no-redact` to disable)
2. **No Raw Payloads**: Alerts contain metadata only
3. **Progress Tracking**: No sensitive data in progress files
4. **File Carving**: SHA256 integrity verification

## GUI Architecture

The web-based GUI (`pdc_gui`) provides a NetworkMiner-like interface:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Web Browser (Client)                         │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                  Single Page App (SPA)                   │   │
│  │  Tabs: Scan | Summary | Hosts | Sessions | DNS | HTTP   │   │
│  │        TLS | Files | Credentials | Alerts               │   │
│  └─────────────────────────────────────────────────────────┘   │
└────────────────────────────────────┬────────────────────────────┘
                                     │ HTTP REST API
                                     ▼
┌─────────────────────────────────────────────────────────────────┐
│                    pdc_gui HTTP Server                          │
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │ /api/start  │  │ /api/status │  │ /api/results│             │
│  │ Start scan  │  │ Poll status │  │ Fetch data  │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
│                          │                                      │
│                          ▼                                      │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              Subprocess Management                       │   │
│  │  mpirun -np N pdc_pcap_analyzer --pcap ... --out ...    │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```
