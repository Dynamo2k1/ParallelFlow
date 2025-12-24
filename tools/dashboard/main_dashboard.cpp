#include "common.h"
#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "Ws2_32.lib")
#else
  #include <netinet/in.h>
  #include <sys/socket.h>
  #include <unistd.h>
#endif

static std::atomic<bool> g_stop{false};

static void on_sigint(int) { g_stop.store(true); }

static std::string join_path(const std::string& a, const std::string& b) {
  if (a.empty()) return b;
  if (a.back() == '/' || a.back() == '\\') return a + b;
  return a + "/" + b;
}

static bool read_file(const std::string& path, std::string* out) {
  std::ifstream in(path, std::ios::in | std::ios::binary);
  if (!in) return false;
  std::ostringstream ss;
  ss << in.rdbuf();
  *out = ss.str();
  return true;
}

static std::string http_response(const std::string& body,
                                 const std::string& content_type = "text/html; charset=utf-8",
                                 int code = 200) {
  std::ostringstream o;
  if (code == 200) o << "HTTP/1.1 200 OK\r\n";
  else if (code == 404) o << "HTTP/1.1 404 Not Found\r\n";
  else o << "HTTP/1.1 500 Internal Server Error\r\n";
  o << "Connection: close\r\n";
  o << "Content-Type: " << content_type << "\r\n";
  o << "Content-Length: " << body.size() << "\r\n";
  o << "Access-Control-Allow-Origin: *\r\n";
  o << "\r\n";
  o << body;
  return o.str();
}

static std::string html_page() {
  // Minimal “GUI”: a single-page dashboard that fetches summary + alerts.
  return R"HTML(
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>PCAP Threat Scanner Dashboard</title>
  <style>
    body { font-family: system-ui, sans-serif; margin: 20px; }
    .row { display:flex; gap: 16px; flex-wrap: wrap; }
    .card { border: 1px solid #ddd; border-radius: 12px; padding: 14px; min-width: 280px; flex: 1; }
    pre { background: #f7f7f7; padding: 10px; border-radius: 10px; overflow:auto; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border-bottom: 1px solid #eee; padding: 6px 8px; text-align:left; }
    input { padding: 8px; border-radius: 10px; border: 1px solid #ddd; width: 340px; }
    .muted { color:#666; }
  </style>
</head>
<body>
  <h2>PCAP Threat Scanner Dashboard</h2>
  <p class="muted">This dashboard reads <code>summary.json</code> and <code>alerts.ndjson</code> from the scan output directory.</p>

  <div class="row">
    <div class="card">
      <h3>Summary</h3>
      <pre id="summary">Loading...</pre>
    </div>
    <div class="card">
      <h3>Top talkers</h3>
      <div id="tops">Loading...</div>
    </div>
  </div>

  <div class="card" style="margin-top:16px;">
    <h3>Alerts</h3>
    <div style="display:flex; gap:10px; align-items:center; flex-wrap:wrap;">
      <input id="q" placeholder="Filter (type, ip, keyword, domain...)">
      <button onclick="reload()">Reload</button>
      <span class="muted" id="count"></span>
    </div>
    <pre id="alerts" style="height:420px;"></pre>
  </div>

<script>
async function getJSON(url){ const r = await fetch(url); if(!r.ok) throw new Error(r.status); return await r.json(); }
async function getText(url){ const r = await fetch(url); if(!r.ok) throw new Error(r.status); return await r.text(); }

function tableFrom(list, col1, col2){
  let html = `<table><thead><tr><th>${col1}</th><th>${col2}</th></tr></thead><tbody>`;
  for(const it of list){
    html += `<tr><td>${it.ip || it.key}</td><td>${it.count}</td></tr>`;
  }
  html += "</tbody></table>";
  return html;
}

let allAlerts = [];

async function reload(){
  const s = await getJSON('/summary');
  document.getElementById('summary').textContent = JSON.stringify(s, null, 2);

  document.getElementById('tops').innerHTML =
    `<h4>Top SRC bytes</h4>${tableFrom(s.top_src_bytes || [], 'IP', 'Bytes')}` +
    `<h4>Top DST bytes</h4>${tableFrom(s.top_dst_bytes || [], 'IP', 'Bytes')}` +
    `<h4>Top DNS qnames</h4>${tableFrom(s.top_dns_qnames || [], 'Domain', 'Count')}` +
    `<h4>Portscan suspects</h4>${tableFrom(s.portscan_suspects || [], 'IP', 'Score')}`;

  const nd = await getText('/alerts');
  allAlerts = nd.trim().split('\n').filter(Boolean).map(x => { try { return JSON.parse(x); } catch(e){ return null; } }).filter(Boolean);
  renderAlerts();
}

function renderAlerts(){
  const q = (document.getElementById('q').value || '').toLowerCase().trim();
  let filtered = allAlerts;
  if(q){
    filtered = allAlerts.filter(a => JSON.stringify(a).toLowerCase().includes(q));
  }
  document.getElementById('count').textContent = `${filtered.length} alerts`;
  document.getElementById('alerts').textContent = filtered.slice(0, 2000).map(a => JSON.stringify(a)).join('\n');
}

document.getElementById('q').addEventListener('input', renderAlerts);
reload().catch(e => { document.getElementById('summary').textContent = "Error: " + e; });
</script>
</body>
</html>
)HTML";
}

static void usage() {
  std::cerr << "pcap_dashboard --dir <outdir> [--port 8080]\n";
}

static bool parse_args(int argc, char** argv, std::string* dir, int* port) {
  *port = 8080;
  for (int i = 1; i < argc; i++) {
    std::string k = argv[i];
    auto need = [&](std::string* v)->bool{
      if (i + 1 >= argc) return false;
      *v = argv[++i];
      return true;
    };
    if (k == "--dir") {
      if (!need(dir)) return false;
    } else if (k == "--port") {
      std::string v; if (!need(&v)) return false;
      try { *port = std::stoi(v); } catch (...) { return false; }
    } else if (k == "--help" || k == "-h") {
      return false;
    } else {
      return false;
    }
  }
  return !dir->empty();
}

static void handle_client(int fd, const std::string& outdir) {
  // very small HTTP parser: reads first line only
  char buf[4096];
#if defined(_WIN32)
  int n = recv(fd, buf, (int)sizeof(buf), 0);
#else
  int n = (int)recv(fd, buf, sizeof(buf), 0);
#endif
  if (n <= 0) return;
  std::string req(buf, buf + n);
  auto pos = req.find("\r\n");
  std::string line = (pos == std::string::npos) ? req : req.substr(0, pos);
  std::istringstream iss(line);
  std::string method, path, ver;
  iss >> method >> path >> ver;

  std::string body, ct;
  int code = 200;

  if (method != "GET") {
    code = 404;
    body = "Not Found";
    ct = "text/plain; charset=utf-8";
  } else if (path == "/" || path == "/index.html") {
    body = html_page();
    ct = "text/html; charset=utf-8";
  } else if (path == "/summary") {
    const std::string p = join_path(outdir, "summary.json");
    if (!read_file(p, &body)) {
      code = 404; body = "Missing summary.json"; ct = "text/plain; charset=utf-8";
    } else {
      ct = "application/json; charset=utf-8";
    }
  } else if (path == "/alerts") {
    const std::string p = join_path(outdir, "alerts.ndjson");
    if (!read_file(p, &body)) {
      code = 404; body = "Missing alerts.ndjson"; ct = "text/plain; charset=utf-8";
    } else {
      ct = "application/x-ndjson; charset=utf-8";
    }
  } else {
    code = 404;
    body = "Not Found";
    ct = "text/plain; charset=utf-8";
  }

  std::string resp = http_response(body, ct, code);
#if defined(_WIN32)
  send(fd, resp.c_str(), (int)resp.size(), 0);
  closesocket(fd);
#else
  send(fd, resp.c_str(), resp.size(), 0);
  close(fd);
#endif
}

int main(int argc, char** argv) {
  std::string dir;
  int port = 8080;
  if (!parse_args(argc, argv, &dir, &port)) {
    usage();
    return 2;
  }

  if (!util::file_exists(join_path(dir, "summary.json"))) {
    std::cerr << "Warning: summary.json not found yet in " << dir << "\n";
  }

  std::signal(SIGINT, on_sigint);
#if defined(_WIN32)
  WSADATA wsa;
  WSAStartup(MAKEWORD(2,2), &wsa);
#endif

  int server_fd = (int)socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd < 0) {
    std::cerr << "socket() failed\n";
    return 1;
  }

  int opt = 1;
#if !defined(_WIN32)
  setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons((uint16_t)port);

  if (bind(server_fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
    std::cerr << "bind() failed: " << std::strerror(errno) << "\n";
    return 1;
  }
  if (listen(server_fd, 64) < 0) {
    std::cerr << "listen() failed\n";
    return 1;
  }

  std::cerr << "Dashboard running: http://localhost:" << port << "\n";
  std::cerr << "Reading dir: " << dir << "\n";
  std::cerr << "Press Ctrl+C to stop.\n";

  while (!g_stop.load()) {
#if defined(_WIN32)
    SOCKET client = accept(server_fd, nullptr, nullptr);
    if (client == INVALID_SOCKET) continue;
    std::thread([client, dir](){ handle_client((int)client, dir); }).detach();
#else
    int client = (int)accept(server_fd, nullptr, nullptr);
    if (client < 0) continue;
    std::thread([client, dir](){ handle_client(client, dir); }).detach();
#endif
  }

#if defined(_WIN32)
  closesocket(server_fd);
  WSACleanup();
#else
  close(server_fd);
#endif
  return 0;
}
