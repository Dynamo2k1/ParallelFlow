#include <mpi.h>
#include <pcap.h>

#include "args.h"
#include "common.h"
#include "ioc.h"
#include "pcap_decode.h"
#include "scanner.h"
#include "mpi_gather.h"

#include <chrono>
#include <fstream>
#include <iostream>
#include <map>
#include <unordered_map>
#include <vector>
#include <algorithm>

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

// Count total packets in PCAP file
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

static void write_summary_json(const std::string& path,
                               int world_size,
                               const LocalCounters& global,
                               const std::vector<IpCount>& top_src,
                               const std::vector<IpCount>& top_dst,
                               const std::vector<StrCount>& top_domains,
                               const std::vector<IpCount>& portscan_suspects) {
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

  out << "{";
  out << "\"world_size\":" << world_size << ",";
  out << "\"packets\":" << global.packets << ",";
  out << "\"bytes\":" << global.bytes << ",";
  out << "\"ipv4\":" << global.ipv4 << ",";
  out << "\"tcp\":" << global.tcp << ",";
  out << "\"udp\":" << global.udp << ",";
  out << "\"icmp\":" << global.icmp << ",";
  out << "\"other\":" << global.other << ",";
  out << "\"alerts_total\":" << global.alerts << ",";
  out << "\"alerts_blocklisted_ip\":" << global.alerts_ip << ",";
  out << "\"alerts_blocklisted_domain\":" << global.alerts_domain << ",";
  out << "\"alerts_keyword\":" << global.alerts_keyword << ",";
  out << "\"alerts_portscan\":" << global.alerts_portscan << ",";

  out << "\"top_src_bytes\":"; write_ipcounts(top_src); out << ",";
  out << "\"top_dst_bytes\":"; write_ipcounts(top_dst); out << ",";
  out << "\"top_dns_qnames\":"; write_strcounts(top_domains); out << ",";
  out << "\"portscan_suspects\":"; write_ipcounts(portscan_suspects);

  out << "}\n";
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
    if (!in) continue; // allow empty/missing (e.g., permissions)
    out << in.rdbuf();
  }
}

int main(int argc, char** argv) {
  MPI_Init(&argc, &argv);

  MPI_Comm comm = MPI_COMM_WORLD;
  int rank = 0, world = 1;
  MPI_Comm_rank(comm, &rank);
  MPI_Comm_size(comm, &world);

  auto ap = parse_args(argc, argv);
  if (!ap.ok) {
    if (rank == 0) std::cerr << ap.error << "\n";
    MPI_Finalize();
    return 2;
  }
  ScanConfig cfg = ap.cfg;

  if (rank == 0) {
    if (!util::ensure_dir(cfg.out_dir)) {
      mpi_abort(comm, "Failed to create output directory: " + cfg.out_dir);
    }
  }
  MPI_Barrier(comm);

  // Load IOCs (all ranks) so matching is consistent
  auto iocres = load_iocs(cfg.ip_blocklist_path, cfg.domain_blocklist_path, cfg.keywords_path);
  if (!iocres.ok) mpi_abort(comm, iocres.error);

  // Count packets and handle empty PCAP files
  size_t total_packets = 0;
  if (rank == 0) {
    total_packets = count_pcap_packets(cfg.pcap_path);
  }
  MPI_Bcast(&total_packets, 1, MPI_UINT64_T, 0, comm);

  // Handle empty PCAP files gracefully
  if (total_packets == 0) {
    if (rank == 0) {
      std::cerr << "Warning: PCAP file contains no packets. Nothing to process.\n";

      // Create empty output files for consistency
      try {
        LocalCounters empty_counters{};
        std::vector<IpCount> empty_ip;
        std::vector<StrCount> empty_str;

        write_summary_json(join_path(cfg.out_dir, "summary.json"),
                          1, empty_counters, empty_ip, empty_ip, empty_str, empty_ip);

        // Create empty alerts file
        std::ofstream alerts_out(join_path(cfg.out_dir, "alerts.ndjson"));
        alerts_out.close();

        std::cerr << "Scan complete.\n";
        std::cerr << "Output dir: " << cfg.out_dir << "\n";
        std::cerr << "Packets (processed): 0\n";
        std::cerr << "Alerts total: 0\n";
      } catch (const std::exception& ex) {
        std::cerr << "Warning: Failed to create output files: " << ex.what() << "\n";
      }
    }
    MPI_Finalize();
    return 0;
  }

  // Open pcap
  char errbuf[PCAP_ERRBUF_SIZE] = {0};
  pcap_t* p = pcap_open_offline(cfg.pcap_path.c_str(), errbuf);
  if (!p) {
    mpi_abort(comm, std::string("pcap_open_offline failed: ") + errbuf);
  }

  // DLT check - handle non-Ethernet gracefully
  int dlt = pcap_datalink(p);
  if (dlt != DLT_EN10MB) {
    if (rank == 0) {
      std::cerr << "Warning: Non-Ethernet datalink type (" << dlt << "). Processing may be limited.\n";
    }
    // Continue processing instead of aborting - the decoder will handle unknown formats
  }

  // Alert writer per rank
  AlertWriter aw;
  aw.max_alerts = cfg.max_alerts_per_rank;
  {
    std::string err;
    std::string apath = join_path(cfg.out_dir, "alerts_rank" + std::to_string(rank) + ".ndjson");
    if (!aw.open(apath, &err)) {
      pcap_close(p);
      mpi_abort(comm, err);
    }
  }

  Scanner scanner(cfg, std::move(iocres.lists));
  LocalResults res(cfg.top_k);

  auto t0 = std::chrono::steady_clock::now();

  // Loop packets
  size_t pkt_idx = 0;
  struct pcap_pkthdr* hdr = nullptr;
  const u_char* data = nullptr;

  while (true) {
    int rc = pcap_next_ex(p, &hdr, &data);
    if (rc == 1) {
      // partition by index
      if ((int)(pkt_idx % (size_t)world) == rank) {
        double ts = (double)hdr->ts.tv_sec + (double)hdr->ts.tv_usec / 1e6;
        PacketView pv;
        if (decode_packet_ipv4((const uint8_t*)data, hdr->caplen, ts, &pv)) {
          scanner.process_packet(pv, hdr->caplen, aw, res);
        } else {
          // still count raw packet/bytes even if unparsed? Production choice: count only parsed.
          // Here we count only parsed IPv4 Ethernet frames for protocol stats; raw PCAP size is still in bytes via caplen when processed.
        }
      }
      pkt_idx++;
      continue;
    } else if (rc == -2) { // EOF
      break;
    } else if (rc == 0) { // timeout (offline shouldn't)
      continue;
    } else { // error
      std::string e = pcap_geterr(p);
      pcap_close(p);
      mpi_abort(comm, "pcap_next_ex error: " + e);
    }
  }

  aw.close();
  pcap_close(p);

  auto t1 = std::chrono::steady_clock::now();
  double sec = std::chrono::duration<double>(t1 - t0).count();

  // Reduce counters (sum)
  LocalCounters local = res.ctr;
  LocalCounters global{};
  MPI_Reduce(&local, &global, (int)(sizeof(LocalCounters) / sizeof(uint64_t)), MPI_UINT64_T, MPI_SUM, 0, comm);

  // Gather top-k src/dst from each rank (as IpCount lists)
  auto top_src_items = res.top_src_bytes.top();
  auto top_dst_items = res.top_dst_bytes.top();
  std::vector<IpCount> top_src_local, top_dst_local;
  top_src_local.reserve(top_src_items.size());
  top_dst_local.reserve(top_dst_items.size());
  for (auto& it : top_src_items) top_src_local.push_back(IpCount{it.key, it.count});
  for (auto& it : top_dst_items) top_dst_local.push_back(IpCount{it.key, it.count});

  auto top_dns_items = res.top_dns_qnames.top();
  std::vector<StrCount> top_dns_local;
  top_dns_local.reserve(top_dns_items.size());
  for (auto& it : top_dns_items) top_dns_local.push_back(StrCount{it.key, it.count});

  // Portscan suspects: take top-k by score
  std::vector<IpCount> portscan_local;
  portscan_local.reserve(res.portscan_suspects.size());
  for (auto& kv : res.portscan_suspects) portscan_local.push_back(IpCount{kv.first, (uint64_t)kv.second});
  std::sort(portscan_local.begin(), portscan_local.end(), [](const IpCount& a, const IpCount& b){ return a.count > b.count; });
  if ((int)portscan_local.size() > cfg.top_k) portscan_local.resize((size_t)cfg.top_k);

  // serialize and gather
  auto src_buf = serialize_ipcounts(top_src_local);
  auto dst_buf = serialize_ipcounts(top_dst_local);
  auto dns_buf = serialize_strcounts(top_dns_local);
  auto ps_buf  = serialize_ipcounts(portscan_local);

  auto gathered_src = mpi_gather_buffers(src_buf, 0, comm);
  auto gathered_dst = mpi_gather_buffers(dst_buf, 0, comm);
  auto gathered_dns = mpi_gather_buffers(dns_buf, 0, comm);
  auto gathered_ps  = mpi_gather_buffers(ps_buf, 0, comm);

  if (rank == 0) {
    // Deserialize all and merge
    std::vector<std::vector<IpCount>> all_src, all_dst, all_ps;
    std::vector<std::vector<StrCount>> all_dns;
    all_src.resize(world);
    all_dst.resize(world);
    all_dns.resize(world);
    all_ps.resize(world);

    for (int r = 0; r < world; r++) {
      all_src[r] = deserialize_ipcounts(gathered_src[r].data(), gathered_src[r].size());
      all_dst[r] = deserialize_ipcounts(gathered_dst[r].data(), gathered_dst[r].size());
      all_dns[r] = deserialize_strcounts(gathered_dns[r].data(), gathered_dns[r].size());
      all_ps[r]  = deserialize_ipcounts(gathered_ps[r].data(), gathered_ps[r].size());
    }

    auto top_src = merge_ipcounts_topk(all_src, cfg.top_k);
    auto top_dst = merge_ipcounts_topk(all_dst, cfg.top_k);
    auto top_dns = merge_strcounts_topk(all_dns, cfg.top_k);
    auto top_ps  = merge_ipcounts_topk(all_ps, cfg.top_k);

    try {
      write_summary_json(join_path(cfg.out_dir, "summary.json"), world, global, top_src, top_dst, top_dns, top_ps);
      merge_alert_files(cfg.out_dir, world);
    } catch (const std::exception& ex) {
      mpi_abort(comm, ex.what());
    }

    std::cerr << "Scan complete.\n";
    std::cerr << "Output dir: " << cfg.out_dir << "\n";
    std::cerr << "Packets (processed IPv4 Ethernet frames): " << global.packets << "\n";
    std::cerr << "Alerts total: " << global.alerts << "\n";
    std::cerr << "Elapsed (rank0 wall): " << sec << " seconds\n";
  }

  MPI_Finalize();
  return 0;
}
