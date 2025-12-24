#include "args.h"
#include "common.h"
#include <sstream>

static bool is_flag(const std::string& s) {
  return util::starts_with(s, "--");
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

std::string usage() {
  return R"(pcap_scan_mpi (MPI Offline PCAP Threat Scanner)

Required:
  --pcap <file.pcap|file.pcapng>
  --out  <output_dir>

Optional IOC files:
  --ip-blocklist     <ips.txt>
  --domain-blocklist <domains.txt>
  --keywords         <keywords.txt>

Tuning:
  --top-k <N>                  (default 50)
  --payload-max <bytes>        (default 512)
  --portscan-threshold <N>     (default 64)
  --portscan-window <seconds>  (default 10)
  --max-alerts <N>             (0 unlimited; default 0)
  --openmp                     (enable OpenMP inside each rank if compiled with -fopenmp)

Examples:
  mpirun -np 8 ./pcap_scan_mpi --pcap traffic.pcap --out out --keywords keywords.txt
)";
}

ArgParseResult parse_args(int argc, char** argv) {
  ArgParseResult r;
  ScanConfig cfg;

  std::vector<std::string> a;
  a.reserve(argc);
  for (int i = 1; i < argc; i++) a.emplace_back(argv[i]);

  for (size_t i = 0; i < a.size(); i++) {
    const std::string& k = a[i];
    if (!is_flag(k)) {
      r.ok = false;
      r.error = "Unexpected argument (expected flag): " + k;
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
    } else if (k == "--top-k") {
      std::string v; if (!need_value(&v)) return r;
      if (!parse_int(v, &cfg.top_k) || cfg.top_k <= 0) { r.ok=false; r.error="Invalid --top-k"; return r; }
    } else if (k == "--payload-max") {
      std::string v; if (!need_value(&v)) return r;
      if (!parse_int(v, &cfg.payload_max) || cfg.payload_max < 0) { r.ok=false; r.error="Invalid --payload-max"; return r; }
    } else if (k == "--portscan-threshold") {
      std::string v; if (!need_value(&v)) return r;
      if (!parse_int(v, &cfg.portscan_threshold) || cfg.portscan_threshold < 1) { r.ok=false; r.error="Invalid --portscan-threshold"; return r; }
    } else if (k == "--portscan-window") {
      std::string v; if (!need_value(&v)) return r;
      if (!parse_int(v, &cfg.portscan_window_seconds) || cfg.portscan_window_seconds < 1) { r.ok=false; r.error="Invalid --portscan-window"; return r; }
    } else if (k == "--max-alerts") {
      std::string v; if (!need_value(&v)) return r;
      if (!parse_int(v, &cfg.max_alerts_per_rank) || cfg.max_alerts_per_rank < 0) { r.ok=false; r.error="Invalid --max-alerts"; return r; }
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
