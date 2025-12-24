# Example Commands for MPI PCAP Threat Scanner

## Basic Usage

### Simple scan with default settings
```bash
# Single rank (no MPI)
./pdc_pcap_analyzer --pcap traffic.pcap --out results

# With MPI (4 ranks)
mpirun -np 4 ./pdc_pcap_analyzer --pcap traffic.pcap --out results
```

### Full featured scan
```bash
mpirun -np 8 ./pdc_pcap_analyzer \
  --pcap /path/to/large_capture.pcapng \
  --out /path/to/output \
  --ip-blocklist blocklists/malicious_ips.txt \
  --domain-blocklist blocklists/malicious_domains.txt \
  --keywords blocklists/suspicious_keywords.txt \
  --enable-carving \
  --progress-file /tmp/scan_progress.json
```

## IOC Matching Examples

### IP blocklist only
```bash
mpirun -np 4 ./pdc_pcap_analyzer \
  --pcap capture.pcap \
  --out results \
  --ip-blocklist known_bad_ips.txt
```

### Domain blocklist with keyword scanning
```bash
mpirun -np 4 ./pdc_pcap_analyzer \
  --pcap capture.pcap \
  --out results \
  --domain-blocklist c2_domains.txt \
  --keywords malware_indicators.txt
```

## Filtering Examples

### BPF filter - HTTP traffic only
```bash
mpirun -np 4 ./pdc_pcap_analyzer \
  --pcap capture.pcap \
  --out results \
  --bpf "tcp port 80"
```

### BPF filter - Specific host
```bash
mpirun -np 4 ./pdc_pcap_analyzer \
  --pcap capture.pcap \
  --out results \
  --bpf "host 192.168.1.100"
```

### BPF filter - DNS traffic
```bash
mpirun -np 4 ./pdc_pcap_analyzer \
  --pcap capture.pcap \
  --out results \
  --bpf "port 53"
```

## Tuning Examples

### High sensitivity port scan detection
```bash
mpirun -np 4 ./pdc_pcap_analyzer \
  --pcap capture.pcap \
  --out results \
  --portscan-threshold 32 \
  --portscan-window 5
```

### Increased payload inspection
```bash
mpirun -np 4 ./pdc_pcap_analyzer \
  --pcap capture.pcap \
  --out results \
  --payload-max 2048 \
  --keywords deep_inspection_keywords.txt
```

### Track top 100 items
```bash
mpirun -np 4 ./pdc_pcap_analyzer \
  --pcap capture.pcap \
  --out results \
  --top-k 100
```

## File Carving

### Enable file carving from HTTP
```bash
mpirun -np 4 ./pdc_pcap_analyzer \
  --pcap capture.pcap \
  --out results \
  --enable-carving
```

Carved files will be saved to `results/files/` with SHA256 hashes.

## Credential Extraction

### With credential redaction (default)
```bash
mpirun -np 4 ./pdc_pcap_analyzer \
  --pcap capture.pcap \
  --out results
```

### Without redaction (for incident response)
```bash
mpirun -np 4 ./pdc_pcap_analyzer \
  --pcap capture.pcap \
  --out results \
  --no-redact
```

## Progress Monitoring

### Enable progress tracking
```bash
mpirun -np 4 ./pdc_pcap_analyzer \
  --pcap large_capture.pcap \
  --out results \
  --progress-file /tmp/progress.json
```

Monitor progress:
```bash
watch -n 1 cat /tmp/progress.json
```

## GUI Usage

### Start the web GUI
```bash
./pdc_gui --port 8888 --analyzer ./pdc_pcap_analyzer
```

Then open http://localhost:8888 in your browser.

### GUI with custom settings
```bash
./pdc_gui \
  --port 8080 \
  --bind 0.0.0.0 \
  --workspace /data/pcap_analysis \
  --analyzer /opt/pcap-analyzer/pdc_pcap_analyzer
```

## Dashboard (Lightweight)

### View results in browser
```bash
# First run a scan
mpirun -np 4 ./pdc_pcap_analyzer --pcap capture.pcap --out results

# Then start dashboard
./pcap_dashboard --dir results --port 8080
```

## High Performance Examples

### Maximum parallelism
```bash
# Use all available CPU cores
mpirun -np $(nproc) ./pdc_pcap_analyzer \
  --pcap huge_capture.pcapng \
  --out results \
  --progress-file /tmp/progress.json
```

### Processing multiple files
```bash
# Use a loop (each file processed separately)
for pcap in /data/captures/*.pcap; do
  name=$(basename "$pcap" .pcap)
  mpirun -np 8 ./pdc_pcap_analyzer \
    --pcap "$pcap" \
    --out "/data/results/$name" \
    --ip-blocklist threat_intel.txt
done
```

## Output Processing Examples

### Query alerts with jq
```bash
# Count alerts by type
jq -s 'group_by(.type) | map({type: .[0].type, count: length})' results/alerts.ndjson

# Get all port scan alerts
jq 'select(.type == "port_scan")' results/alerts.ndjson

# Get unique source IPs from alerts
jq -s '[.[].src_ip] | unique' results/alerts.ndjson
```

### Query flows with csvkit
```bash
# Top talkers by bytes
csvstat results/flows.csv --column bytes

# Filter TCP flows
csvgrep -c proto -m TCP results/flows.csv

# Sort by bytes descending
csvsort -c bytes -r results/flows.csv | head -20
```

### Export to other formats
```bash
# Convert alerts to CSV
jq -r '[.ts, .type, .src_ip, .dst_ip, .proto, .detail] | @csv' \
  results/alerts.ndjson > alerts.csv

# Merge protocol logs
cat results/dns.jsonl results/http.jsonl results/tls.jsonl > all_protocols.jsonl
```
