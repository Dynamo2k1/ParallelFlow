#include <mpi.h>
#include <pcap.h>

#include "ext_decoder.h"
#include "ext_scanner.h"
#include "common.h"
#include "ioc.h"
#include "mpi_gather.h"

#include <chrono>
#include <fstream>
#include <iostream>
#include <map>
#include <unordered_map>
#include <vector>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <csignal>
#include <atomic>

static std::atomic<bool> g_stop{false};

static void on_signal(int) { g_stop.store(true); }

static void mpi_abort(MPI_Comm comm, const std::string& msg, int code=1) {
    int rank = 0;
    MPI_Comm_rank(comm, &rank);
    if (rank == 0) std::cerr << msg << "\n";
    MPI_Abort(comm, code);
}

static std::string join_path(const std::string& a, const std::string& b) {
    if (a.empty()) return b;
    if (a.back() == '/' || a.back() == '\\') return a + b;
    return a + "/" + b;
}

static std::string usage() {
    return R"(pdc_pcap_analyzer - Production-grade MPI PCAP/PCAPNG Analyzer

Usage:
  mpirun -np <N> ./pdc_pcap_analyzer [options]

Required:
  --pcap <file.pcap|file.pcapng>    Input capture file
  --out  <output_dir>               Output directory

IOC Files (optional):
  --ip-blocklist     <ips.txt>      IP blocklist (IPv4/IPv6, CIDR supported)
  --domain-blocklist <domains.txt>  Domain blocklist
  --keywords         <keywords.txt> Keywords for payload scanning

Tuning:
  --top-k <N>                       Top-K items to track (default: 50)
  --payload-max <bytes>             Max payload bytes to scan (default: 512)
  --portscan-threshold <N>          Distinct ports for portscan alert (default: 64)
  --portscan-window <seconds>       Time window for portscan (default: 10)
  --max-alerts <N>                  Max alerts per rank (0=unlimited, default: 0)

Features:
  --bpf <filter>                    BPF filter expression
  --progress-file <path>            Write progress JSON periodically
  --keylog <path>                   TLS key log file (for metadata extraction)
  --enable-carving                  Enable file carving from HTTP
  --no-redact                       Disable secret redaction
  --openmp                          Enable OpenMP parallelism

Output:
  summary.json                      Overall statistics
  alerts.ndjson                     Merged alerts
  alerts_rank<N>.ndjson             Per-rank alerts
  flows.csv                         Flow records
  dns.jsonl                         DNS protocol logs
  http.jsonl                        HTTP protocol logs
  tls.jsonl                         TLS protocol logs
  files/                            Carved files (if enabled)

Examples:
  mpirun -np 8 ./pdc_pcap_analyzer --pcap traffic.pcap --out out
  mpirun -np 4 ./pdc_pcap_analyzer --pcap large.pcapng --out results \
    --ip-blocklist bad_ips.txt --keywords suspicious.txt --enable-carving
)";
}

static bool is_flag(const std::string& s) {
    return s.size() >= 2 && s[0] == '-' && s[1] == '-';
}

static bool parse_int(const std::string& s, int* out) {
    try {
        size_t idx = 0;
        long v = std::stol(s, &idx, 10);
        if (idx != s.size()) return false;
        if (v < -2147483648L || v > 2147483647L) return false;
        *out = (int)v;
        return true;
    } catch (...) {
        return false;
    }
}

struct ArgParseResult {
    bool ok = false;
    std::string error;
    ExtScanConfig cfg;
};

static ArgParseResult parse_args(int argc, char** argv) {
    ArgParseResult r;
    ExtScanConfig cfg;
    
    std::vector<std::string> a;
    for (int i = 1; i < argc; i++) a.emplace_back(argv[i]);
    
    for (size_t i = 0; i < a.size(); i++) {
        const std::string& k = a[i];
        if (!is_flag(k)) {
            r.ok = false;
            r.error = "Unexpected argument: " + k;
            return r;
        }
        
        auto need_value = [&](std::string* out) -> bool {
            if (i + 1 >= a.size() || is_flag(a[i + 1])) {
                r.ok = false;
                r.error = "Missing value for " + k;
                return false;
            }
            *out = a[++i];
            return true;
        };
        
        if (k == "--pcap") {
            if (!need_value(&cfg.pcap_path)) return r;
        } else if (k == "--out") {
            if (!need_value(&cfg.out_dir)) return r;
        } else if (k == "--ip-blocklist") {
            if (!need_value(&cfg.ip_blocklist_path)) return r;
        } else if (k == "--domain-blocklist") {
            if (!need_value(&cfg.domain_blocklist_path)) return r;
        } else if (k == "--keywords") {
            if (!need_value(&cfg.keywords_path)) return r;
        } else if (k == "--bpf") {
            if (!need_value(&cfg.bpf_filter)) return r;
        } else if (k == "--progress-file") {
            if (!need_value(&cfg.progress_file)) return r;
        } else if (k == "--keylog") {
            if (!need_value(&cfg.keylog_path)) return r;
        } else if (k == "--top-k") {
            std::string v; if (!need_value(&v)) return r;
            if (!parse_int(v, &cfg.top_k) || cfg.top_k <= 0) {
                r.ok = false; r.error = "Invalid --top-k"; return r;
            }
        } else if (k == "--payload-max") {
            std::string v; if (!need_value(&v)) return r;
            if (!parse_int(v, &cfg.payload_max) || cfg.payload_max < 0) {
                r.ok = false; r.error = "Invalid --payload-max"; return r;
            }
        } else if (k == "--portscan-threshold") {
            std::string v; if (!need_value(&v)) return r;
            if (!parse_int(v, &cfg.portscan_threshold) || cfg.portscan_threshold < 1) {
                r.ok = false; r.error = "Invalid --portscan-threshold"; return r;
            }
        } else if (k == "--portscan-window") {
            std::string v; if (!need_value(&v)) return r;
            if (!parse_int(v, &cfg.portscan_window_seconds) || cfg.portscan_window_seconds < 1) {
                r.ok = false; r.error = "Invalid --portscan-window"; return r;
            }
        } else if (k == "--max-alerts") {
            std::string v; if (!need_value(&v)) return r;
            if (!parse_int(v, &cfg.max_alerts_per_rank) || cfg.max_alerts_per_rank < 0) {
                r.ok = false; r.error = "Invalid --max-alerts"; return r;
            }
        } else if (k == "--enable-carving") {
            cfg.enable_carving = true;
        } else if (k == "--no-redact") {
            cfg.redact_secrets = false;
        } else if (k == "--openmp") {
            cfg.enable_openmp = true;
        } else if (k == "--help" || k == "-h") {
            r.ok = false;
            r.error = usage();
            return r;
        } else {
            r.ok = false;
            r.error = "Unknown flag: " + k;
            return r;
        }
    }
    
    if (cfg.pcap_path.empty() || cfg.out_dir.empty()) {
        r.ok = false;
        r.error = "Missing required args.\n\n" + usage();
        return r;
    }
    
    r.ok = true;
    r.cfg = cfg;
    return r;
}

static void write_summary_json(const std::string& path,
                               int world_size,
                               const ExtCounters& global,
                               const std::vector<IpCount>& top_src,
                               const std::vector<IpCount>& top_dst,
                               const std::vector<StrCount>& top_domains,
                               const std::vector<StrCount>& top_http_hosts,
                               const std::vector<StrCount>& top_tls_sni,
                               const std::vector<IpCount>& portscan_suspects,
                               const std::vector<CarvedFile>& carved_files) {
    std::ofstream out(path, std::ios::out | std::ios::binary | std::ios::trunc);
    if (!out) throw std::runtime_error("Failed to write summary.json: " + path);
    
    auto write_ipcounts = [&](const std::vector<IpCount>& v) {
        out << "[";
        for (size_t i = 0; i < v.size(); i++) {
            if (i) out << ",";
            out << "{\"ip\":\"" << util::ip_to_string(v[i].ip_be) << "\",\"count\":" << v[i].count << "}";
        }
        out << "]";
    };
    
    auto write_strcounts = [&](const std::vector<StrCount>& v) {
        out << "[";
        for (size_t i = 0; i < v.size(); i++) {
            if (i) out << ",";
            out << "{\"key\":\"" << util::json_escape(v[i].key) << "\",\"count\":" << v[i].count << "}";
        }
        out << "]";
    };
    
    out << "{\n";
    out << "  \"world_size\": " << world_size << ",\n";
    out << "  \"packets\": " << global.packets << ",\n";
    out << "  \"bytes\": " << global.bytes << ",\n";
    out << "  \"ipv4\": " << global.ipv4 << ",\n";
    out << "  \"ipv6\": " << global.ipv6 << ",\n";
    out << "  \"tcp\": " << global.tcp << ",\n";
    out << "  \"udp\": " << global.udp << ",\n";
    out << "  \"icmp\": " << global.icmp << ",\n";
    out << "  \"icmpv6\": " << global.icmpv6 << ",\n";
    out << "  \"arp\": " << global.arp << ",\n";
    out << "  \"other\": " << global.other << ",\n";
    out << "  \"dns_queries\": " << global.dns_queries << ",\n";
    out << "  \"http_requests\": " << global.http_requests << ",\n";
    out << "  \"tls_handshakes\": " << global.tls_handshakes << ",\n";
    out << "  \"dhcp_messages\": " << global.dhcp_messages << ",\n";
    out << "  \"alerts_total\": " << global.alerts << ",\n";
    out << "  \"alerts_blocklisted_ip\": " << global.alerts_ip << ",\n";
    out << "  \"alerts_blocklisted_domain\": " << global.alerts_domain << ",\n";
    out << "  \"alerts_keyword\": " << global.alerts_keyword << ",\n";
    out << "  \"alerts_portscan\": " << global.alerts_portscan << ",\n";
    out << "  \"alerts_dns_tunnel\": " << global.alerts_dns_tunnel << ",\n";
    out << "  \"alerts_beaconing\": " << global.alerts_beaconing << ",\n";
    out << "  \"alerts_exfil\": " << global.alerts_exfil << ",\n";
    out << "  \"alerts_sensitive\": " << global.alerts_sensitive << ",\n";
    out << "  \"files_carved\": " << global.files_carved << ",\n";
    out << "  \"credentials_found\": " << global.credentials_found << ",\n";
    
    out << "  \"top_src_bytes\": "; write_ipcounts(top_src); out << ",\n";
    out << "  \"top_dst_bytes\": "; write_ipcounts(top_dst); out << ",\n";
    out << "  \"top_dns_qnames\": "; write_strcounts(top_domains); out << ",\n";
    out << "  \"top_http_hosts\": "; write_strcounts(top_http_hosts); out << ",\n";
    out << "  \"top_tls_sni\": "; write_strcounts(top_tls_sni); out << ",\n";
    out << "  \"portscan_suspects\": "; write_ipcounts(portscan_suspects);
    
    if (!carved_files.empty()) {
        out << ",\n  \"carved_files\": [";
        for (size_t i = 0; i < carved_files.size(); i++) {
            if (i) out << ",";
            const auto& cf = carved_files[i];
            out << "\n    {\"filename\":\"" << util::json_escape(cf.filename)
                << "\",\"sha256\":\"" << cf.sha256
                << "\",\"content_type\":\"" << util::json_escape(cf.content_type)
                << "\",\"size\":" << cf.size
                << ",\"src_ip\":\"" << cf.src_ip
                << "\",\"dst_ip\":\"" << cf.dst_ip << "\"}";
        }
        out << "\n  ]";
    }
    
    out << "\n}\n";
}

static std::vector<IpCount> merge_ipcounts_topk(const std::vector<std::vector<IpCount>>& all, int k) {
    std::unordered_map<uint32_t, uint64_t> m;
    for (const auto& vec : all) {
        for (const auto& it : vec) {
            m[it.ip_be] += it.count;
        }
    }
    std::vector<IpCount> out;
    out.reserve(m.size());
    for (auto& kv : m) out.push_back(IpCount{kv.first, kv.second});
    std::sort(out.begin(), out.end(), [](const IpCount& a, const IpCount& b){ return a.count > b.count; });
    if ((int)out.size() > k) out.resize((size_t)k);
    return out;
}

static std::vector<StrCount> merge_strcounts_topk(const std::vector<std::vector<StrCount>>& all, int k) {
    std::unordered_map<std::string, uint64_t> m;
    for (const auto& vec : all) {
        for (const auto& it : vec) {
            m[it.key] += it.count;
        }
    }
    std::vector<StrCount> out;
    out.reserve(m.size());
    for (auto& kv : m) out.push_back(StrCount{kv.first, kv.second});
    std::sort(out.begin(), out.end(), [](const StrCount& a, const StrCount& b){ return a.count > b.count; });
    if ((int)out.size() > k) out.resize((size_t)k);
    return out;
}

static void merge_alert_files(const std::string& outdir, int world_size) {
    const std::string merged = join_path(outdir, "alerts.ndjson");
    std::ofstream out(merged, std::ios::out | std::ios::binary | std::ios::trunc);
    if (!out) throw std::runtime_error("Failed to open merged alerts: " + merged);
    
    for (int r = 0; r < world_size; r++) {
        const std::string path = join_path(outdir, "alerts_rank" + std::to_string(r) + ".ndjson");
        std::ifstream in(path, std::ios::in | std::ios::binary);
        if (!in) continue;
        out << in.rdbuf();
    }
}

// Count total packets in PCAP for progress tracking
static size_t count_pcap_packets(const std::string& path) {
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_t* p = pcap_open_offline(path.c_str(), errbuf);
    if (!p) return 0;
    
    size_t count = 0;
    struct pcap_pkthdr* hdr = nullptr;
    const u_char* data = nullptr;
    
    while (pcap_next_ex(p, &hdr, &data) == 1) {
        count++;
    }
    
    pcap_close(p);
    return count;
}

int main(int argc, char** argv) {
    MPI_Init(&argc, &argv);
    
    MPI_Comm comm = MPI_COMM_WORLD;
    int rank = 0, world = 1;
    MPI_Comm_rank(comm, &rank);
    MPI_Comm_size(comm, &world);
    
    // Signal handling
    std::signal(SIGTERM, on_signal);
    std::signal(SIGINT, on_signal);
    
    auto ap = parse_args(argc, argv);
    if (!ap.ok) {
        if (rank == 0) std::cerr << ap.error << "\n";
        MPI_Finalize();
        return 2;
    }
    ExtScanConfig cfg = ap.cfg;
    
    // Create output directory
    if (rank == 0) {
        if (!util::ensure_dir(cfg.out_dir)) {
            mpi_abort(comm, "Failed to create output directory: " + cfg.out_dir);
        }
        if (cfg.enable_carving) {
            util::ensure_dir(cfg.out_dir + "/files");
        }
    }
    MPI_Barrier(comm);
    
    // Load IOCs
    auto iocres = load_iocs(cfg.ip_blocklist_path, cfg.domain_blocklist_path, cfg.keywords_path);
    if (!iocres.ok) mpi_abort(comm, iocres.error);
    
    // Count packets for progress (rank 0 only, then broadcast)
    size_t total_packets = 0;
    if (rank == 0) {
        total_packets = count_pcap_packets(cfg.pcap_path);
        if (!cfg.progress_file.empty()) {
            std::cerr << "Total packets in capture: " << total_packets << "\n";
        }
    }
    MPI_Bcast(&total_packets, 1, MPI_UINT64_T, 0, comm);
    
    // Handle empty PCAP files gracefully
    if (total_packets == 0) {
        if (rank == 0) {
            std::cerr << "Warning: PCAP file contains no packets. Nothing to process.\n";
            
            // Create empty output files for consistency
            try {
                ExtCounters empty_counters{};
                std::vector<IpCount> empty_ip;
                std::vector<StrCount> empty_str;
                std::vector<CarvedFile> empty_files;
                
                write_summary_json(join_path(cfg.out_dir, "summary.json"),
                                  world, empty_counters, empty_ip, empty_ip, empty_str,
                                  empty_str, empty_str, empty_ip, empty_files);
                
                // Create empty alerts file
                std::ofstream alerts_out(join_path(cfg.out_dir, "alerts.ndjson"));
                alerts_out.close();
                
                // Create empty flows file
                std::ofstream flows_out(join_path(cfg.out_dir, "flows.csv"));
                flows_out << "src_ip,dst_ip,src_port,dst_port,proto,packets,bytes,first_ts,last_ts,app_proto\n";
                flows_out.close();
                
                std::cerr << "\n=== Scan Complete ===\n";
                std::cerr << "Output directory: " << cfg.out_dir << "\n";
                std::cerr << "Packets processed: 0\n";
                std::cerr << "Total alerts: 0\n";
            } catch (const std::exception& ex) {
                std::cerr << "Warning: Failed to create output files: " << ex.what() << "\n";
            }
        }
        MPI_Finalize();
        return 0;
    }
    
    // Open PCAP
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_t* p = pcap_open_offline(cfg.pcap_path.c_str(), errbuf);
    if (!p) {
        mpi_abort(comm, std::string("pcap_open_offline failed: ") + errbuf);
    }
    
    // Apply BPF filter if provided
    if (!cfg.bpf_filter.empty()) {
        struct bpf_program fp;
        if (pcap_compile(p, &fp, cfg.bpf_filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) == -1) {
            pcap_close(p);
            mpi_abort(comm, std::string("BPF compile failed: ") + pcap_geterr(p));
        }
        if (pcap_setfilter(p, &fp) == -1) {
            pcap_freecode(&fp);
            pcap_close(p);
            mpi_abort(comm, std::string("BPF filter failed: ") + pcap_geterr(p));
        }
        pcap_freecode(&fp);
    }
    
    // DLT check - handle non-Ethernet gracefully
    int dlt = pcap_datalink(p);
    if (dlt != DLT_EN10MB) {
        if (rank == 0) {
            std::cerr << "Warning: Non-Ethernet datalink type (" << dlt << "). Processing may be limited.\n";
        }
        // Continue processing - the decoder will handle unknown formats gracefully
    }
    
    // Alert writer
    ExtAlertWriter aw;
    aw.max_alerts = cfg.max_alerts_per_rank;
    {
        std::string err;
        std::string apath = join_path(cfg.out_dir, "alerts_rank" + std::to_string(rank) + ".ndjson");
        if (!aw.open(apath, &err)) {
            pcap_close(p);
            mpi_abort(comm, err);
        }
    }
    
    // Protocol log writer
    ProtocolLogWriter proto_logs;
    if (rank == 0) {
        proto_logs.open(cfg.out_dir);
    }
    
    // Scanner and results
    ExtScanner scanner(cfg, std::move(iocres.lists));
    ExtLocalResults res(cfg.top_k);
    ExtPacketDecoder decoder;
    
    auto t0 = std::chrono::steady_clock::now();
    auto last_progress = t0;
    
    // Main loop
    size_t pkt_idx = 0;
    struct pcap_pkthdr* hdr = nullptr;
    const u_char* data = nullptr;
    
    while (!g_stop.load()) {
        int rc = pcap_next_ex(p, &hdr, &data);
        if (rc == 1) {
            // Partition by index
            if ((int)(pkt_idx % (size_t)world) == rank) {
                double ts = (double)hdr->ts.tv_sec + (double)hdr->ts.tv_usec / 1e6;
                ExtPacketView pv;
                if (decoder.decode((const uint8_t*)data, hdr->caplen, ts, &pv)) {
                    scanner.process_packet(pv, hdr->caplen, aw, res, 
                                          rank == 0 ? &proto_logs : nullptr);
                }
            }
            pkt_idx++;
            
            // Progress update
            if (!cfg.progress_file.empty() && pkt_idx % 10000 == 0) {
                auto now = std::chrono::steady_clock::now();
                double elapsed = std::chrono::duration<double>(now - t0).count();
                
                ScanProgress progress;
                progress.packets_processed = res.ctr.packets;
                progress.bytes_processed = res.ctr.bytes;
                progress.time_elapsed = elapsed;
                progress.rank = rank;
                progress.world_size = world;
                progress.percentage = total_packets > 0 ? 
                    (100.0 * pkt_idx / total_packets) : 0.0;
                
                std::string prog_path = cfg.progress_file;
                if (world > 1) {
                    prog_path += "_rank" + std::to_string(rank);
                }
                scanner.write_progress(prog_path, progress);
            }
            
            continue;
        } else if (rc == -2) { // EOF
            break;
        } else if (rc == 0) { // timeout
            continue;
        } else { // error
            std::string e = pcap_geterr(p);
            pcap_close(p);
            mpi_abort(comm, "pcap_next_ex error: " + e);
        }
    }
    
    aw.close();
    proto_logs.close();
    pcap_close(p);
    
    auto t1 = std::chrono::steady_clock::now();
    double sec = std::chrono::duration<double>(t1 - t0).count();
    
    // Reduce counters
    ExtCounters local = res.ctr;
    ExtCounters global{};
    MPI_Reduce(&local, &global, (int)(sizeof(ExtCounters) / sizeof(uint64_t)), 
               MPI_UINT64_T, MPI_SUM, 0, comm);
    
    // Gather top-k from each rank
    auto extract_ipcounts = [](const SpaceSaving<uint32_t, uint64_t>& ss) {
        std::vector<IpCount> out;
        for (auto& it : ss.top()) out.push_back(IpCount{it.key, it.count});
        return out;
    };
    
    auto extract_strcounts = [](const SpaceSaving<std::string, uint64_t>& ss) {
        std::vector<StrCount> out;
        for (auto& it : ss.top()) out.push_back(StrCount{it.key, it.count});
        return out;
    };
    
    auto top_src_local = extract_ipcounts(res.top_src_bytes);
    auto top_dst_local = extract_ipcounts(res.top_dst_bytes);
    auto top_dns_local = extract_strcounts(res.top_dns_qnames);
    auto top_http_local = extract_strcounts(res.top_http_hosts);
    auto top_tls_local = extract_strcounts(res.top_tls_sni);
    
    std::vector<IpCount> portscan_local;
    for (auto& kv : res.portscan_suspects) {
        portscan_local.push_back(IpCount{kv.first, (uint64_t)kv.second});
    }
    std::sort(portscan_local.begin(), portscan_local.end(), 
              [](const IpCount& a, const IpCount& b){ return a.count > b.count; });
    if ((int)portscan_local.size() > cfg.top_k) portscan_local.resize((size_t)cfg.top_k);
    
    // Serialize and gather
    auto src_buf = serialize_ipcounts(top_src_local);
    auto dst_buf = serialize_ipcounts(top_dst_local);
    auto dns_buf = serialize_strcounts(top_dns_local);
    auto http_buf = serialize_strcounts(top_http_local);
    auto tls_buf = serialize_strcounts(top_tls_local);
    auto ps_buf = serialize_ipcounts(portscan_local);
    
    auto gathered_src = mpi_gather_buffers(src_buf, 0, comm);
    auto gathered_dst = mpi_gather_buffers(dst_buf, 0, comm);
    auto gathered_dns = mpi_gather_buffers(dns_buf, 0, comm);
    auto gathered_http = mpi_gather_buffers(http_buf, 0, comm);
    auto gathered_tls = mpi_gather_buffers(tls_buf, 0, comm);
    auto gathered_ps = mpi_gather_buffers(ps_buf, 0, comm);
    
    // Write flows.csv per rank, then merge at rank 0
    write_flows_csv(join_path(cfg.out_dir, "flows_rank" + std::to_string(rank) + ".csv"), res.flows);
    
    MPI_Barrier(comm);
    
    if (rank == 0) {
        // Deserialize and merge
        std::vector<std::vector<IpCount>> all_src(world), all_dst(world), all_ps(world);
        std::vector<std::vector<StrCount>> all_dns(world), all_http(world), all_tls(world);
        
        for (int r = 0; r < world; r++) {
            all_src[r] = deserialize_ipcounts(gathered_src[r].data(), gathered_src[r].size());
            all_dst[r] = deserialize_ipcounts(gathered_dst[r].data(), gathered_dst[r].size());
            all_dns[r] = deserialize_strcounts(gathered_dns[r].data(), gathered_dns[r].size());
            all_http[r] = deserialize_strcounts(gathered_http[r].data(), gathered_http[r].size());
            all_tls[r] = deserialize_strcounts(gathered_tls[r].data(), gathered_tls[r].size());
            all_ps[r] = deserialize_ipcounts(gathered_ps[r].data(), gathered_ps[r].size());
        }
        
        auto top_src = merge_ipcounts_topk(all_src, cfg.top_k);
        auto top_dst = merge_ipcounts_topk(all_dst, cfg.top_k);
        auto top_dns = merge_strcounts_topk(all_dns, cfg.top_k);
        auto top_http = merge_strcounts_topk(all_http, cfg.top_k);
        auto top_tls = merge_strcounts_topk(all_tls, cfg.top_k);
        auto top_ps = merge_ipcounts_topk(all_ps, cfg.top_k);
        
        try {
            write_summary_json(join_path(cfg.out_dir, "summary.json"),
                              world, global, top_src, top_dst, top_dns, 
                              top_http, top_tls, top_ps, res.carved_files);
            merge_alert_files(cfg.out_dir, world);
            
            // Merge flow files
            std::ofstream flows_out(join_path(cfg.out_dir, "flows.csv"));
            flows_out << "src_ip,dst_ip,src_port,dst_port,proto,packets,bytes,first_ts,last_ts,app_proto\n";
            for (int r = 0; r < world; r++) {
                std::string fpath = join_path(cfg.out_dir, "flows_rank" + std::to_string(r) + ".csv");
                std::ifstream in(fpath);
                std::string line;
                std::getline(in, line); // Skip header
                while (std::getline(in, line)) {
                    flows_out << line << "\n";
                }
                std::remove(fpath.c_str()); // Clean up per-rank file
            }
            
        } catch (const std::exception& ex) {
            mpi_abort(comm, ex.what());
        }
        
        std::cerr << "\n=== Scan Complete ===\n";
        std::cerr << "Output directory: " << cfg.out_dir << "\n";
        std::cerr << "Packets processed: " << global.packets << "\n";
        std::cerr << "Bytes processed: " << global.bytes << "\n";
        std::cerr << "Total alerts: " << global.alerts << "\n";
        std::cerr << "  - Blocklisted IP: " << global.alerts_ip << "\n";
        std::cerr << "  - Blocklisted domain: " << global.alerts_domain << "\n";
        std::cerr << "  - Keyword match: " << global.alerts_keyword << "\n";
        std::cerr << "  - Port scan: " << global.alerts_portscan << "\n";
        std::cerr << "  - DNS tunnel: " << global.alerts_dns_tunnel << "\n";
        std::cerr << "  - Beaconing: " << global.alerts_beaconing << "\n";
        std::cerr << "  - Exfiltration: " << global.alerts_exfil << "\n";
        std::cerr << "  - Sensitive data: " << global.alerts_sensitive << "\n";
        std::cerr << "Files carved: " << global.files_carved << "\n";
        std::cerr << "Elapsed time: " << std::fixed << std::setprecision(2) << sec << " seconds\n";
    }
    
    MPI_Finalize();
    return 0;
}
