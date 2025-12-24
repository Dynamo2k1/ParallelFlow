// pdc_gui - NetworkMiner-like GUI for PDC PCAP Analyzer
// Web-based network forensics interface using MPI-accelerated backend

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <cstring>
#include <cstdlib>
#include <filesystem>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <poll.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>

namespace fs = std::filesystem;

static std::string g_bind = "127.0.0.1";
static int g_port = 8888;
static std::string g_workspace = "/tmp/pdc_workspace";
static std::string g_analyzer = "./pdc_pcap_analyzer";
static std::atomic<bool> g_running{false};
static std::atomic<pid_t> g_pid{-1};
static std::atomic<uint64_t> g_packets{0}, g_bytes{0};
static std::atomic<double> g_percent{0.0};
static std::mutex g_log_mtx;
static std::string g_log, g_err, g_outdir, g_pcap_file;

static std::string html_escape(const std::string& s) {
    std::string o; 
    o.reserve(s.size() * 1.1);
    for (char c : s) {
        switch(c) {
            case '&': o += "&amp;"; break; 
            case '<': o += "&lt;"; break;
            case '>': o += "&gt;"; break; 
            case '"': o += "&quot;"; break;
            case '\'': o += "&#39;"; break;
            default: o += c;
        }
    } 
    return o;
}

static std::string json_escape(const std::string& s) {
    std::string o; 
    o.reserve(s.size() * 1.1);
    for (unsigned char c : s) {
        switch(c) {
            case '"': o += "\\\""; break; 
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n"; break; 
            case '\r': o += "\\r"; break;
            case '\t': o += "\\t"; break; 
            case '\b': o += "\\b"; break;
            case '\f': o += "\\f"; break;
            default: 
                if (c < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", c);
                    o += buf;
                } else {
                    o += c;
                }
        }
    } 
    return o;
}

static std::string url_decode(const std::string& s) {
    std::string o;
    o.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i + 2 < s.size()) {
            char c1 = s[i+1], c2 = s[i+2];
            // Validate hex digits
            bool valid = ((c1 >= '0' && c1 <= '9') || (c1 >= 'a' && c1 <= 'f') || (c1 >= 'A' && c1 <= 'F')) &&
                         ((c2 >= '0' && c2 <= '9') || (c2 >= 'a' && c2 <= 'f') || (c2 >= 'A' && c2 <= 'F'));
            if (valid) {
                int v = 0;
                char hex[3] = {c1, c2, 0};
                if (sscanf(hex, "%x", &v) == 1) {
                    o += (char)v;
                    i += 2;
                    continue;
                }
            }
            o += s[i];
        } else if (s[i] == '+') {
            o += ' ';
        } else {
            o += s[i];
        }
    }
    return o;
}

// Sanitize filename for use in HTTP Content-Disposition header
// Removes or replaces characters that could cause header injection
static std::string sanitize_filename_for_header(const std::string& filename) {
    std::string safe;
    safe.reserve(filename.size());
    for (unsigned char c : filename) {
        // Only allow safe ASCII printable characters (excluding control chars and special HTTP chars)
        if (c >= 0x20 && c < 0x7F && c != '"' && c != '\\' && c != '\r' && c != '\n') {
            safe += c;
        } else if (c == '"' || c == '\\') {
            // Escape quotes and backslashes
            safe += '_';
        }
        // Skip control characters and non-ASCII
    }
    return safe.empty() ? "download" : safe;
}

// Validate filename to prevent directory traversal attacks
static bool is_safe_filename(const std::string& filename) {
    // Reject empty filenames
    if (filename.empty()) return false;
    
    // Reject filenames starting with dot (hidden files, parent directory references)
    if (filename[0] == '.') return false;
    
    // Reject filenames containing path separators or parent directory references
    if (filename.find('/') != std::string::npos) return false;
    if (filename.find('\\') != std::string::npos) return false;
    if (filename.find("..") != std::string::npos) return false;
    
    // Reject filenames with null bytes
    if (filename.find('\0') != std::string::npos) return false;
    
    // Reject filenames that are just dots
    if (filename == "." || filename == "..") return false;
    
    // Check for suspicious characters that might indicate encoding attacks
    // After URL decoding, we shouldn't see % characters in normal filenames
    for (char c : filename) {
        if (c < 0x20) return false;  // Control characters
    }
    
    return true;
}

static void send_resp(int fd, int code, const std::string& ct, const std::string& body) {
    std::ostringstream oss;
    const char* status = (code == 200) ? "OK" : (code == 404) ? "Not Found" : "Internal Server Error";
    oss << "HTTP/1.1 " << code << " " << status << "\r\n"
        << "Content-Type: " << ct << "\r\n"
        << "Content-Length: " << body.size() << "\r\n"
        << "Access-Control-Allow-Origin: *\r\n"
        << "Cache-Control: no-cache\r\n"
        << "Connection: close\r\n\r\n" << body;
    std::string r = oss.str(); 
    send(fd, r.c_str(), r.size(), 0);
}

static void stop_scan() {
    pid_t p = g_pid.load();
    if (p > 0) { 
        killpg(p, SIGTERM); 
        usleep(500000); 
        killpg(p, SIGKILL); 
        waitpid(p, nullptr, 0); 
    }
    g_running = false; 
    g_pid = -1;
}

static void scan_thread(const std::string& pcap, const std::string& out, int ranks,
    const std::string& ipb, const std::string& domb, const std::string& kw,
    const std::string& bpf, bool carve, bool noredact, int topk, int pmax, int psth, int pswin) {
    g_running = true; 
    g_packets = 0; 
    g_bytes = 0; 
    g_percent = 0.0;
    g_outdir = out;
    g_pcap_file = pcap;
    { std::lock_guard<std::mutex> lk(g_log_mtx); g_log.clear(); g_err.clear(); }
    fs::create_directories(out);
    
    std::vector<std::string> args = {"mpirun", "--oversubscribe", "-np", std::to_string(ranks),
        g_analyzer, "--pcap", pcap, "--out", out, "--progress-file", out + "/progress.json"};
    if (!ipb.empty()) { args.push_back("--ip-blocklist"); args.push_back(ipb); }
    if (!domb.empty()) { args.push_back("--domain-blocklist"); args.push_back(domb); }
    if (!kw.empty()) { args.push_back("--keywords"); args.push_back(kw); }
    if (!bpf.empty()) { args.push_back("--bpf"); args.push_back(bpf); }
    if (carve) args.push_back("--enable-carving");
    if (noredact) args.push_back("--no-redact");
    if (topk > 0) { args.push_back("--top-k"); args.push_back(std::to_string(topk)); }
    if (pmax > 0) { args.push_back("--payload-max"); args.push_back(std::to_string(pmax)); }
    if (psth > 0) { args.push_back("--portscan-threshold"); args.push_back(std::to_string(psth)); }
    if (pswin > 0) { args.push_back("--portscan-window"); args.push_back(std::to_string(pswin)); }
    
    int op[2], ep[2]; 
    if (pipe(op) < 0 || pipe(ep) < 0) {
        std::lock_guard<std::mutex> lk(g_log_mtx);
        g_err += "Failed to create pipes\n";
        g_running = false;
        return;
    }
    pid_t pid = fork();
    if (pid == 0) {
        setsid(); 
        close(op[0]); 
        close(ep[0]);
        dup2(op[1], 1); 
        dup2(ep[1], 2); 
        close(op[1]); 
        close(ep[1]);
        std::vector<char*> av; 
        for (auto& a : args) av.push_back(const_cast<char*>(a.c_str()));
        av.push_back(nullptr); 
        execvp(av[0], av.data()); 
        _exit(127);
    }
    g_pid = pid; 
    close(op[1]); 
    close(ep[1]);
    fcntl(op[0], F_SETFL, O_NONBLOCK); 
    fcntl(ep[0], F_SETFL, O_NONBLOCK);
    char buf[4096];
    
    while (g_running) {
        pollfd fds[2] = {{op[0], POLLIN, 0}, {ep[0], POLLIN, 0}};
        if (poll(fds, 2, 100) > 0) {
            if (fds[0].revents & POLLIN) { 
                ssize_t n = read(op[0], buf, sizeof(buf)-1);
                if (n > 0) { 
                    buf[n] = 0; 
                    std::lock_guard<std::mutex> lk(g_log_mtx); 
                    g_log += buf; 
                }
            }
            if (fds[1].revents & POLLIN) { 
                ssize_t n = read(ep[0], buf, sizeof(buf)-1);
                if (n > 0) { 
                    buf[n] = 0; 
                    std::lock_guard<std::mutex> lk(g_log_mtx); 
                    g_err += buf; 
                }
            }
        }
        std::ifstream pf(out + "/progress.json");
        if (pf) { 
            std::string ln; 
            while (std::getline(pf, ln)) {
                auto p1 = ln.find("\"packets_processed\":"); 
                if (p1 != std::string::npos) {
                    auto s = p1 + 20, e = ln.find_first_of(",}", s); 
                    if (e != std::string::npos)
                        try { g_packets = std::stoull(ln.substr(s, e-s)); } catch(...) {} 
                }
                auto p2 = ln.find("\"bytes_processed\":"); 
                if (p2 != std::string::npos) {
                    auto s = p2 + 18, e = ln.find_first_of(",}", s); 
                    if (e != std::string::npos)
                        try { g_bytes = std::stoull(ln.substr(s, e-s)); } catch(...) {} 
                }
                auto p3 = ln.find("\"percentage\":"); 
                if (p3 != std::string::npos) {
                    auto s = p3 + 13, e = ln.find_first_of(",}", s); 
                    if (e != std::string::npos)
                        try { g_percent = std::stod(ln.substr(s, e-s)); } catch(...) {} 
                }
            }
        }
        int st; 
        if (waitpid(pid, &st, WNOHANG) == pid) break;
    }
    close(op[0]); 
    close(ep[0]); 
    g_running = false; 
    g_pid = -1;
}

// List files in directory (for carved files)
static std::vector<std::pair<std::string, size_t>> list_files_in_dir(const std::string& dir) {
    std::vector<std::pair<std::string, size_t>> files;
    DIR* d = opendir(dir.c_str());
    if (!d) return files;
    struct dirent* ent;
    while ((ent = readdir(d)) != nullptr) {
        if (ent->d_name[0] == '.') continue;
        std::string path = dir + "/" + ent->d_name;
        struct stat st;
        if (stat(path.c_str(), &st) == 0 && S_ISREG(st.st_mode)) {
            files.push_back({ent->d_name, (size_t)st.st_size});
        }
    }
    closedir(d);
    return files;
}

// Get file MIME type based on extension
static std::string get_mime_type(const std::string& filename) {
    auto pos = filename.rfind('.');
    if (pos == std::string::npos) return "application/octet-stream";
    std::string ext = filename.substr(pos);
    if (ext == ".html" || ext == ".htm") return "text/html";
    if (ext == ".css") return "text/css";
    if (ext == ".js") return "application/javascript";
    if (ext == ".json") return "application/json";
    if (ext == ".png") return "image/png";
    if (ext == ".jpg" || ext == ".jpeg") return "image/jpeg";
    if (ext == ".gif") return "image/gif";
    if (ext == ".svg") return "image/svg+xml";
    if (ext == ".ico") return "image/x-icon";
    if (ext == ".pdf") return "application/pdf";
    if (ext == ".txt") return "text/plain";
    if (ext == ".csv") return "text/csv";
    if (ext == ".xml") return "application/xml";
    if (ext == ".zip") return "application/zip";
    if (ext == ".exe") return "application/x-msdownload";
    if (ext == ".dll") return "application/x-msdownload";
    return "application/octet-stream";
}

static std::string get_page() {
    return R"HTML(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PDC Network Forensics Analyzer</title>
<style>
:root {
    --bg-dark: #0d1117;
    --bg-card: #161b22;
    --bg-input: #21262d;
    --border: #30363d;
    --text: #c9d1d9;
    --text-muted: #8b949e;
    --accent: #58a6ff;
    --accent-hover: #79c0ff;
    --success: #3fb950;
    --warning: #d29922;
    --danger: #f85149;
    --purple: #a371f7;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { 
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
    background: var(--bg-dark); 
    color: var(--text); 
    line-height: 1.5;
}
.app { display: flex; flex-direction: column; height: 100vh; }
header { 
    background: var(--bg-card); 
    border-bottom: 1px solid var(--border);
    padding: 12px 20px;
    display: flex;
    align-items: center;
    gap: 20px;
}
.logo { 
    font-size: 1.4em; 
    font-weight: 600; 
    color: var(--accent);
    display: flex;
    align-items: center;
    gap: 10px;
}
.logo svg { width: 28px; height: 28px; }
.status-bar {
    flex: 1;
    display: flex;
    align-items: center;
    gap: 20px;
}
.stat-pill {
    background: var(--bg-input);
    padding: 6px 14px;
    border-radius: 20px;
    font-size: 0.85em;
    display: flex;
    align-items: center;
    gap: 8px;
}
.stat-pill .val { color: var(--accent); font-weight: 600; }
.progress-wrap {
    flex: 1;
    max-width: 300px;
    height: 6px;
    background: var(--bg-input);
    border-radius: 3px;
    overflow: hidden;
}
.progress-bar {
    height: 100%;
    background: var(--accent);
    width: 0%;
    transition: width 0.3s;
}
.btn { 
    padding: 8px 16px; 
    border: none; 
    border-radius: 6px; 
    cursor: pointer;
    font-size: 0.9em;
    font-weight: 500;
    transition: all 0.2s;
}
.btn-primary { background: var(--accent); color: #000; }
.btn-primary:hover { background: var(--accent-hover); }
.btn-danger { background: var(--danger); color: #fff; }
.btn-danger:hover { opacity: 0.9; }
.btn-secondary { background: var(--bg-input); color: var(--text); border: 1px solid var(--border); }
.btn-secondary:hover { background: var(--border); }

.main { display: flex; flex: 1; overflow: hidden; }
.sidebar { 
    width: 220px; 
    background: var(--bg-card);
    border-right: 1px solid var(--border);
    display: flex;
    flex-direction: column;
}
.nav-section { padding: 16px 0; }
.nav-section-title {
    padding: 8px 16px;
    font-size: 0.75em;
    text-transform: uppercase;
    color: var(--text-muted);
    letter-spacing: 0.5px;
}
.nav-item {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 10px 16px;
    cursor: pointer;
    transition: all 0.2s;
    border-left: 3px solid transparent;
}
.nav-item:hover { background: var(--bg-input); }
.nav-item.active { 
    background: rgba(88, 166, 255, 0.1);
    border-left-color: var(--accent);
    color: var(--accent);
}
.nav-item svg { width: 18px; height: 18px; opacity: 0.7; }
.nav-item.active svg { opacity: 1; }
.nav-item .badge {
    margin-left: auto;
    background: var(--bg-input);
    padding: 2px 8px;
    border-radius: 10px;
    font-size: 0.75em;
}

.content { flex: 1; overflow: auto; padding: 20px; }
.panel { display: none; }
.panel.active { display: block; }

.card { 
    background: var(--bg-card); 
    border: 1px solid var(--border);
    border-radius: 8px; 
    margin-bottom: 20px;
}
.card-header {
    padding: 16px;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    gap: 12px;
}
.card-header h3 { font-size: 1em; font-weight: 600; }
.card-body { padding: 16px; }

.form-group { margin-bottom: 16px; }
.form-group label { 
    display: block; 
    margin-bottom: 6px; 
    font-size: 0.9em;
    color: var(--text-muted);
}
.form-control { 
    width: 100%; 
    padding: 10px 12px; 
    background: var(--bg-input); 
    border: 1px solid var(--border); 
    color: var(--text); 
    border-radius: 6px;
    font-size: 0.9em;
}
.form-control:focus { outline: none; border-color: var(--accent); }
.form-row { display: flex; gap: 16px; }
.form-row .form-group { flex: 1; }
.form-check {
    display: flex;
    align-items: center;
    gap: 8px;
    cursor: pointer;
}
.form-check input { width: 16px; height: 16px; }

.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: 0.9em; }
th, td { 
    padding: 10px 12px; 
    text-align: left; 
    border-bottom: 1px solid var(--border);
}
th { 
    background: var(--bg-input);
    font-weight: 600;
    position: sticky;
    top: 0;
}
tr:hover { background: rgba(88, 166, 255, 0.05); }
.text-success { color: var(--success); }
.text-warning { color: var(--warning); }
.text-danger { color: var(--danger); }
.text-muted { color: var(--text-muted); }

.search-bar {
    display: flex;
    gap: 10px;
    margin-bottom: 16px;
}
.search-bar input { flex: 1; }

.log-output {
    background: var(--bg-dark);
    padding: 12px;
    border-radius: 6px;
    font-family: 'Monaco', 'Menlo', monospace;
    font-size: 0.85em;
    max-height: 300px;
    overflow: auto;
    white-space: pre-wrap;
    word-break: break-all;
}

.stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 16px;
    margin-bottom: 20px;
}
.stats-card {
    background: var(--bg-input);
    padding: 16px;
    border-radius: 8px;
    text-align: center;
}
.stats-card .value { font-size: 1.8em; font-weight: 600; color: var(--accent); }
.stats-card .label { font-size: 0.85em; color: var(--text-muted); margin-top: 4px; }

.alert-badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 0.8em;
    font-weight: 500;
}
.alert-badge.critical { background: var(--danger); color: #fff; }
.alert-badge.high { background: var(--warning); color: #000; }
.alert-badge.medium { background: var(--purple); color: #fff; }
.alert-badge.low { background: var(--bg-input); }

.file-icon { width: 32px; text-align: center; font-size: 1.2em; }
.file-link { color: var(--accent); text-decoration: none; }
.file-link:hover { text-decoration: underline; }

.tabs { display: flex; gap: 4px; margin-bottom: 16px; }
.tab {
    padding: 8px 16px;
    background: transparent;
    border: none;
    color: var(--text-muted);
    cursor: pointer;
    border-radius: 6px;
    transition: all 0.2s;
}
.tab:hover { background: var(--bg-input); }
.tab.active { background: var(--accent); color: #000; }

.empty-state {
    text-align: center;
    padding: 60px 20px;
    color: var(--text-muted);
}
.empty-state svg { width: 64px; height: 64px; opacity: 0.3; margin-bottom: 16px; }
.empty-state h3 { margin-bottom: 8px; }

.json-view { 
    background: var(--bg-dark);
    padding: 12px;
    border-radius: 6px;
    font-family: monospace;
    font-size: 0.85em;
    max-height: 400px;
    overflow: auto;
}

.upload-zone {
    border: 2px dashed var(--border);
    border-radius: 8px;
    padding: 40px 20px;
    text-align: center;
    cursor: pointer;
    transition: all 0.2s;
    background: var(--bg-input);
}
.upload-zone:hover, .upload-zone.dragover {
    border-color: var(--accent);
    background: rgba(88, 166, 255, 0.1);
}
.upload-zone .upload-icon { font-size: 3em; margin-bottom: 10px; }
.upload-zone .upload-text { font-size: 1.1em; margin-bottom: 8px; }
.upload-zone .upload-hint { font-size: 0.85em; color: var(--text-muted); }

.uploaded-file {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 16px;
    background: var(--bg-input);
    border: 1px solid var(--success);
    border-radius: 8px;
    margin-top: 10px;
}
.uploaded-file .file-name { font-weight: 500; color: var(--success); }
.uploaded-file .file-size { color: var(--text-muted); font-size: 0.9em; flex: 1; }
.btn-sm { padding: 4px 10px; font-size: 0.8em; }

.advanced-options {
    margin-top: 20px;
    border: 1px solid var(--border);
    border-radius: 8px;
}
.advanced-options summary {
    padding: 12px 16px;
    cursor: pointer;
    background: var(--bg-input);
    border-radius: 8px;
    font-weight: 500;
}
.advanced-options[open] summary {
    border-bottom: 1px solid var(--border);
    border-radius: 8px 8px 0 0;
}
.advanced-content {
    padding: 16px;
}

.upload-progress {
    margin-top: 10px;
    display: none;
}
.upload-progress.active { display: block; }
.upload-progress-bar {
    height: 6px;
    background: var(--bg-input);
    border-radius: 3px;
    overflow: hidden;
}
.upload-progress-fill {
    height: 100%;
    background: var(--accent);
    width: 0%;
    transition: width 0.3s;
}
.upload-progress-text {
    font-size: 0.85em;
    color: var(--text-muted);
    margin-top: 6px;
    text-align: center;
}
</style>
</head>
<body>
<div class="app">
    <header>
        <div class="logo">
            <svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z"/></svg>
            PDC Network Forensics
        </div>
        <div class="status-bar">
            <div class="stat-pill"><span>Packets:</span><span class="val" id="hdrPackets">0</span></div>
            <div class="stat-pill"><span>Bytes:</span><span class="val" id="hdrBytes">0 B</span></div>
            <div class="stat-pill"><span>Status:</span><span class="val" id="hdrStatus">Idle</span></div>
            <div class="progress-wrap"><div class="progress-bar" id="progressBar"></div></div>
        </div>
        <button class="btn btn-primary" id="btnStart" onclick="startScan()">Start Scan</button>
        <button class="btn btn-danger" id="btnStop" onclick="stopScan()" style="display:none">Stop Scan</button>
    </header>
    
    <div class="main">
        <nav class="sidebar">
            <div class="nav-section">
                <div class="nav-section-title">Analysis</div>
                <div class="nav-item active" data-panel="scan"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M3 13h2v-2H3v2zm0 4h2v-2H3v2zm0-8h2V7H3v2zm4 4h14v-2H7v2zm0 4h14v-2H7v2zM7 7v2h14V7H7z"/></svg>Scan</div>
                <div class="nav-item" data-panel="summary"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zM9 17H7v-7h2v7zm4 0h-2V7h2v10zm4 0h-2v-4h2v4z"/></svg>Summary<span class="badge" id="badgeAlerts">0</span></div>
            </div>
            <div class="nav-section">
                <div class="nav-section-title">Network</div>
                <div class="nav-item" data-panel="hosts"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M4 6h16v2H4zm2 6h12v2H6zm4 6h4v2h-4z"/></svg>Hosts<span class="badge" id="badgeHosts">0</span></div>
                <div class="nav-item" data-panel="sessions"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z"/></svg>Sessions<span class="badge" id="badgeSessions">0</span></div>
                <div class="nav-item" data-panel="dns"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93z"/></svg>DNS<span class="badge" id="badgeDns">0</span></div>
            </div>
            <div class="nav-section">
                <div class="nav-section-title">Protocols</div>
                <div class="nav-item" data-panel="http"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M4.5 11h-2V9H1v6h1.5v-2.5h2V15H6V9H4.5v2zm2.5-.5h1.5V15H10v-4.5h1.5V9H7v1.5zm5.5 0H14V15h1.5v-4.5H17V9h-4.5v1.5zm9-1.5H18v6h1.5v-2h2c.8 0 1.5-.7 1.5-1.5v-1c0-.8-.7-1.5-1.5-1.5zm0 2.5h-2v-1h2v1z"/></svg>HTTP<span class="badge" id="badgeHttp">0</span></div>
                <div class="nav-item" data-panel="tls"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z"/></svg>TLS<span class="badge" id="badgeTls">0</span></div>
                <div class="nav-item" data-panel="payload"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M9.4 16.6L4.8 12l4.6-4.6L8 6l-6 6 6 6 1.4-1.4zm5.2 0l4.6-4.6-4.6-4.6L16 6l6 6-6 6-1.4-1.4z"/></svg>Payload Data<span class="badge" id="badgePayload">0</span></div>
            </div>
            <div class="nav-section">
                <div class="nav-section-title">Forensics</div>
                <div class="nav-item" data-panel="files"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M14 2H6c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 1.99 2H18c1.1 0 2-.9 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z"/></svg>Files<span class="badge" id="badgeFiles">0</span></div>
                <div class="nav-item" data-panel="credentials"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M21 3H3c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h18c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm0 16H3V5h18v14zM9 8h2v8H9zm4 0h2v8h-2z"/></svg>Credentials<span class="badge" id="badgeCreds">0</span></div>
                <div class="nav-item" data-panel="alerts"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"/></svg>Alerts<span class="badge" id="badgeAlertsNav">0</span></div>
            </div>
        </nav>
        
        <main class="content">
            <!-- Scan Panel -->
            <div class="panel active" id="panel-scan">
                <div class="card">
                    <div class="card-header"><h3>🔍 Scan Configuration</h3></div>
                    <div class="card-body">
                        <div class="form-group">
                            <label>PCAP/PCAPNG File</label>
                            <div class="upload-zone" id="uploadZone" onclick="document.getElementById('fileInput').click()">
                                <input type="file" id="fileInput" accept=".pcap,.pcapng,.cap" style="display:none" onchange="handleFileSelect(this)">
                                <div class="upload-icon">📁</div>
                                <div class="upload-text">Click to select or drag & drop PCAP file here</div>
                                <div class="upload-hint">Supports .pcap, .pcapng, .cap files</div>
                            </div>
                            <div class="upload-progress" id="uploadProgress">
                                <div class="upload-progress-bar"><div class="upload-progress-fill" id="uploadProgressFill"></div></div>
                                <div class="upload-progress-text" id="uploadProgressText">Uploading...</div>
                            </div>
                            <div id="uploadedFile" style="display:none" class="uploaded-file">
                                <span class="file-name" id="uploadedFileName"></span>
                                <span class="file-size" id="uploadedFileSize"></span>
                                <button class="btn btn-secondary btn-sm" onclick="clearFile()">✕ Remove</button>
                            </div>
                            <div style="margin-top:10px; text-align:center; color:var(--text-muted)">— or —</div>
                            <input type="text" class="form-control" id="pcap" placeholder="Enter server path: /path/to/capture.pcap" style="margin-top:10px">
                        </div>
                        <div class="form-row">
                            <div class="form-group">
                                <label>MPI Ranks</label>
                                <input type="number" class="form-control" id="ranks" value="4" min="1" max="64">
                            </div>
                            <div class="form-group">
                                <label class="form-check" style="margin-top:28px"><input type="checkbox" id="carve" checked> Enable File Carving</label>
                            </div>
                        </div>
                        
                        <details class="advanced-options">
                            <summary>Advanced Options</summary>
                            <div class="advanced-content">
                                <div class="form-row">
                                    <div class="form-group">
                                        <label>Top-K Results</label>
                                        <input type="number" class="form-control" id="topk" value="50" min="10" max="1000">
                                    </div>
                                    <div class="form-group">
                                        <label>Payload Max (bytes)</label>
                                        <input type="number" class="form-control" id="pmax" value="512" min="64" max="65535">
                                    </div>
                                </div>
                                <div class="form-row">
                                    <div class="form-group">
                                        <label>Port Scan Threshold</label>
                                        <input type="number" class="form-control" id="psth" value="64" min="1">
                                    </div>
                                    <div class="form-group">
                                        <label>Port Scan Window (sec)</label>
                                        <input type="number" class="form-control" id="pswin" value="10" min="1">
                                    </div>
                                </div>
                                <div class="form-group">
                                    <label>BPF Filter (optional)</label>
                                    <input type="text" class="form-control" id="bpf" placeholder="e.g., tcp port 80 or tcp port 443">
                                </div>
                                <div class="form-group">
                                    <label class="form-check"><input type="checkbox" id="noredact"> Disable Credential Redaction</label>
                                </div>
                                
                                <h4 style="margin:20px 0 10px; color:var(--text-muted)">IOC Matching (Optional)</h4>
                                <p class="text-muted" style="font-size:0.85em;margin-bottom:12px">Leave blank to analyze without IOC matching. The tool will still extract all network data.</p>
                                <div class="form-group">
                                    <label>IP Blocklist</label>
                                    <input type="text" class="form-control" id="ipb" placeholder="/path/to/blocked_ips.txt">
                                </div>
                                <div class="form-group">
                                    <label>Domain Blocklist</label>
                                    <input type="text" class="form-control" id="domb" placeholder="/path/to/blocked_domains.txt">
                                </div>
                                <div class="form-group">
                                    <label>Keywords File</label>
                                    <input type="text" class="form-control" id="kw" placeholder="/path/to/keywords.txt">
                                </div>
                            </div>
                        </details>
                    </div>
                </div>
                <div class="card">
                    <div class="card-header"><h3>📋 Output Log</h3></div>
                    <div class="card-body">
                        <div class="log-output" id="logOutput">Waiting for scan to start...</div>
                    </div>
                </div>
            </div>
            
            <!-- Summary Panel -->
            <div class="panel" id="panel-summary">
                <div class="stats-grid" id="summaryStats"></div>
                <div class="card">
                    <div class="card-header"><h3>📊 Traffic Distribution</h3></div>
                    <div class="card-body">
                        <div class="form-row">
                            <div>
                                <h4 style="margin-bottom:10px">Top Source IPs by Bytes</h4>
                                <table id="topSrcTable"><thead><tr><th>IP</th><th>Bytes</th></tr></thead><tbody></tbody></table>
                            </div>
                            <div>
                                <h4 style="margin-bottom:10px">Top Destination IPs by Bytes</h4>
                                <table id="topDstTable"><thead><tr><th>IP</th><th>Bytes</th></tr></thead><tbody></tbody></table>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="card">
                    <div class="card-header"><h3>🔍 Port Scan Suspects</h3></div>
                    <div class="card-body">
                        <table id="portscanTable"><thead><tr><th>IP</th><th>Distinct Ports</th></tr></thead><tbody></tbody></table>
                    </div>
                </div>
            </div>
            
            <!-- Hosts Panel -->
            <div class="panel" id="panel-hosts">
                <div class="card">
                    <div class="card-header"><h3>🖥️ Detected Hosts</h3></div>
                    <div class="card-body">
                        <div class="search-bar">
                            <input type="text" class="form-control" id="hostsSearch" placeholder="Search hosts...">
                        </div>
                        <div class="table-wrap">
                            <table id="hostsTable">
                                <thead><tr><th>IP Address</th><th>Total Bytes (Src)</th><th>Total Bytes (Dst)</th><th>Role</th></tr></thead>
                                <tbody></tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Sessions Panel -->
            <div class="panel" id="panel-sessions">
                <div class="card">
                    <div class="card-header"><h3>🔗 Network Sessions / Flows</h3></div>
                    <div class="card-body">
                        <div class="search-bar">
                            <input type="text" class="form-control" id="sessionsSearch" placeholder="Search sessions...">
                            <select class="form-control" id="sessionsProto" style="width:auto">
                                <option value="">All Protocols</option>
                                <option value="tcp">TCP</option>
                                <option value="udp">UDP</option>
                                <option value="icmp">ICMP</option>
                            </select>
                        </div>
                        <div class="table-wrap">
                            <table id="sessionsTable">
                                <thead><tr><th>Source</th><th>Destination</th><th>Protocol</th><th>Packets</th><th>Bytes</th><th>App Proto</th><th>First Seen</th></tr></thead>
                                <tbody></tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- DNS Panel -->
            <div class="panel" id="panel-dns">
                <div class="card">
                    <div class="card-header"><h3>🌐 DNS Queries</h3></div>
                    <div class="card-body">
                        <div class="search-bar">
                            <input type="text" class="form-control" id="dnsSearch" placeholder="Search domain names...">
                        </div>
                        <div class="table-wrap">
                            <table id="dnsTable">
                                <thead><tr><th>Domain</th><th>Query Count</th></tr></thead>
                                <tbody></tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- HTTP Panel -->
            <div class="panel" id="panel-http">
                <div class="card">
                    <div class="card-header"><h3>📡 HTTP Requests</h3></div>
                    <div class="card-body">
                        <div class="search-bar">
                            <input type="text" class="form-control" id="httpSearch" placeholder="Search HTTP data...">
                        </div>
                        <div class="table-wrap">
                            <table id="httpTable">
                                <thead><tr><th>Host</th><th>Request Count</th></tr></thead>
                                <tbody></tbody>
                            </table>
                        </div>
                        <h4 style="margin:20px 0 10px">HTTP Protocol Log</h4>
                        <div class="json-view" id="httpLog">No HTTP data available yet.</div>
                    </div>
                </div>
            </div>
            
            <!-- TLS Panel -->
            <div class="panel" id="panel-tls">
                <div class="card">
                    <div class="card-header"><h3>🔐 TLS/SSL Connections</h3></div>
                    <div class="card-body">
                        <div class="search-bar">
                            <input type="text" class="form-control" id="tlsSearch" placeholder="Search TLS data (SNI, JA3)...">
                        </div>
                        <div class="table-wrap">
                            <table id="tlsTable">
                                <thead><tr><th>Server Name (SNI)</th><th>Count</th></tr></thead>
                                <tbody></tbody>
                            </table>
                        </div>
                        <h4 style="margin:20px 0 10px">TLS Protocol Log</h4>
                        <div class="json-view" id="tlsLog">No TLS data available yet.</div>
                    </div>
                </div>
            </div>
            
            <!-- Payload Data Panel -->
            <div class="panel" id="panel-payload">
                <div class="card">
                    <div class="card-header"><h3>📊 Payload Data Extraction</h3></div>
                    <div class="card-body">
                        <p class="text-muted" style="margin-bottom:16px">Extracted strings from ICMP, raw TCP/UDP, and other protocol payloads. Useful for finding hidden data, covert channels, or exfiltration.</p>
                        <div class="search-bar">
                            <input type="text" class="form-control" id="payloadSearch" placeholder="Search payload data...">
                            <select class="form-control" id="payloadProto" style="width:auto">
                                <option value="">All Protocols</option>
                                <option value="ICMP">ICMP</option>
                                <option value="ICMPv6">ICMPv6</option>
                                <option value="TCP">TCP</option>
                                <option value="UDP">UDP</option>
                                <option value="OTHER">OTHER</option>
                            </select>
                        </div>
                        <div class="table-wrap">
                            <table id="payloadTable">
                                <thead><tr><th>Time</th><th>Source</th><th>Destination</th><th>Protocol</th><th>ICMP Type</th><th>Payload Size</th><th>Extracted Strings</th></tr></thead>
                                <tbody></tbody>
                            </table>
                        </div>
                        <h4 style="margin:20px 0 10px">Raw Payload Log</h4>
                        <div class="json-view" id="payloadLog">No payload data available yet.</div>
                    </div>
                </div>
            </div>
            
            <!-- Files Panel -->
            <div class="panel" id="panel-files">
                <div class="card">
                    <div class="card-header"><h3>📁 Extracted Files</h3></div>
                    <div class="card-body">
                        <p class="text-muted" style="margin-bottom:16px">Files carved from HTTP responses (enable "File Carving" in scan options)</p>
                        <div class="table-wrap">
                            <table id="filesTable">
                                <thead><tr><th></th><th>Filename</th><th>Content Type</th><th>Size</th><th>SHA256</th><th>Source → Dest</th><th>Action</th></tr></thead>
                                <tbody></tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Credentials Panel -->
            <div class="panel" id="panel-credentials">
                <div class="card">
                    <div class="card-header"><h3>🔑 Detected Credentials</h3></div>
                    <div class="card-body">
                        <p class="text-muted" style="margin-bottom:16px">Credentials extracted from plaintext protocols (FTP, SMTP, HTTP Basic). Redacted by default unless disabled.</p>
                        <div class="table-wrap">
                            <table id="credsTable">
                                <thead><tr><th>Protocol</th><th>Source IP</th><th>Username</th><th>Password</th><th>Timestamp</th></tr></thead>
                                <tbody></tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Alerts Panel -->
            <div class="panel" id="panel-alerts">
                <div class="card">
                    <div class="card-header"><h3>⚠️ Security Alerts</h3></div>
                    <div class="card-body">
                        <div class="search-bar">
                            <input type="text" class="form-control" id="alertsSearch" placeholder="Search alerts...">
                            <select class="form-control" id="alertsType" style="width:auto">
                                <option value="">All Types</option>
                                <option value="blocklisted_ip">Blocklisted IP</option>
                                <option value="blocklisted_domain">Blocklisted Domain</option>
                                <option value="keyword_match">Keyword Match</option>
                                <option value="port_scan">Port Scan</option>
                                <option value="dns_tunnel">DNS Tunnel</option>
                                <option value="beaconing">Beaconing</option>
                                <option value="exfiltration">Exfiltration</option>
                                <option value="sensitive_data">Sensitive Data</option>
                            </select>
                        </div>
                        <div class="table-wrap">
                            <table id="alertsTable">
                                <thead><tr><th>Type</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Detail</th><th>Timestamp</th></tr></thead>
                                <tbody></tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </main>
    </div>
</div>

<script>
// State
let pollTimer = null;
let summary = null;
let alerts = [];
let flows = [];
let dnsLog = [];
let httpLog = [];
let tlsLog = [];
let payloadLog = [];
let files = [];
let uploadedFilePath = '';

// DOM helpers
const el = id => document.getElementById(id);
const fmt = n => n.toLocaleString();
const fmtBytes = b => {
    if (b < 1024) return b + ' B';
    if (b < 1048576) return (b/1024).toFixed(1) + ' KB';
    if (b < 1073741824) return (b/1048576).toFixed(1) + ' MB';
    return (b/1073741824).toFixed(2) + ' GB';
};
const fmtTs = ts => ts > 0 ? new Date(ts * 1000).toLocaleString() : '-';
const esc = s => {
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
};

// File upload handling
const uploadZone = el('uploadZone');

uploadZone.addEventListener('dragover', e => {
    e.preventDefault();
    uploadZone.classList.add('dragover');
});

uploadZone.addEventListener('dragleave', e => {
    e.preventDefault();
    uploadZone.classList.remove('dragover');
});

uploadZone.addEventListener('drop', e => {
    e.preventDefault();
    uploadZone.classList.remove('dragover');
    const files = e.dataTransfer.files;
    if (files.length > 0) {
        uploadFile(files[0]);
    }
});

function handleFileSelect(input) {
    if (input.files.length > 0) {
        uploadFile(input.files[0]);
    }
}

async function uploadFile(file) {
    const validExts = ['.pcap', '.pcapng', '.cap'];
    const ext = file.name.substring(file.name.lastIndexOf('.')).toLowerCase();
    if (!validExts.includes(ext)) {
        alert('Invalid file type. Please select a .pcap, .pcapng, or .cap file.');
        return;
    }
    
    el('uploadZone').style.display = 'none';
    el('uploadProgress').classList.add('active');
    el('uploadProgressFill').style.width = '0%';
    el('uploadProgressText').textContent = 'Uploading ' + file.name + '...';
    
    const formData = new FormData();
    formData.append('file', file);
    
    try {
        const xhr = new XMLHttpRequest();
        xhr.upload.addEventListener('progress', e => {
            if (e.lengthComputable) {
                const pct = Math.round((e.loaded / e.total) * 100);
                el('uploadProgressFill').style.width = pct + '%';
                el('uploadProgressText').textContent = 'Uploading ' + file.name + '... ' + pct + '%';
            }
        });
        
        xhr.onload = function() {
            el('uploadProgress').classList.remove('active');
            if (xhr.status === 200) {
                const resp = JSON.parse(xhr.responseText);
                if (resp.path) {
                    uploadedFilePath = resp.path;
                    el('uploadedFileName').textContent = file.name;
                    el('uploadedFileSize').textContent = fmtBytes(file.size);
                    el('uploadedFile').style.display = 'flex';
                    el('pcap').value = ''; // Clear manual path input
                } else if (resp.error) {
                    alert('Upload failed: ' + resp.error);
                    el('uploadZone').style.display = 'block';
                }
            } else {
                alert('Upload failed: ' + xhr.statusText);
                el('uploadZone').style.display = 'block';
            }
        };
        
        xhr.onerror = function() {
            el('uploadProgress').classList.remove('active');
            el('uploadZone').style.display = 'block';
            alert('Upload failed. Please try again.');
        };
        
        xhr.open('POST', '/api/upload');
        xhr.send(formData);
    } catch (err) {
        el('uploadProgress').classList.remove('active');
        el('uploadZone').style.display = 'block';
        alert('Upload error: ' + err.message);
    }
}

function clearFile() {
    uploadedFilePath = '';
    el('uploadedFile').style.display = 'none';
    el('uploadZone').style.display = 'block';
    el('fileInput').value = '';
}

// Navigation
document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', () => {
        document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
        document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
        item.classList.add('active');
        el('panel-' + item.dataset.panel).classList.add('active');
    });
});

// API calls
async function api(path, method = 'GET') {
    const r = await fetch('/api/' + path, { method });
    if (!r.ok) throw new Error(r.status);
    return r.text();
}

async function apiJson(path) {
    const t = await api(path);
    return JSON.parse(t);
}

// Start scan
async function startScan() {
    // Use uploaded file path if available, otherwise use manual path input
    const pcapPath = uploadedFilePath || el('pcap').value;
    
    if (!pcapPath) {
        alert('Please upload a PCAP file or enter a file path.');
        return;
    }
    
    const params = new URLSearchParams({
        pcap: pcapPath,
        ranks: el('ranks').value,
        topk: el('topk').value,
        pmax: el('pmax').value,
        psth: el('psth').value,
        pswin: el('pswin').value,
        ipb: el('ipb').value,
        domb: el('domb').value,
        kw: el('kw').value,
        bpf: el('bpf').value,
        carve: el('carve').checked ? 1 : 0,
        noredact: el('noredact').checked ? 1 : 0
    });
    await fetch('/api/start?' + params, { method: 'POST' });
    el('btnStart').style.display = 'none';
    el('btnStop').style.display = 'inline-block';
    pollTimer = setInterval(pollStatus, 500);
}

// Stop scan
async function stopScan() {
    await fetch('/api/stop', { method: 'POST' });
}

// Poll status
async function pollStatus() {
    try {
        const d = await apiJson('status');
        el('hdrPackets').textContent = fmt(d.packets);
        el('hdrBytes').textContent = fmtBytes(d.bytes);
        el('hdrStatus').textContent = d.running ? 'Running' : 'Complete';
        el('progressBar').style.width = (d.percent || 0) + '%';
        el('logOutput').textContent = d.log || 'No output yet...';
        
        if (!d.running && pollTimer) {
            clearInterval(pollTimer);
            pollTimer = null;
            el('btnStart').style.display = 'inline-block';
            el('btnStop').style.display = 'none';
            await loadResults();
        }
    } catch (e) {
        console.error('Poll error:', e);
    }
}

// Load results
async function loadResults() {
    try {
        // Summary
        summary = await apiJson('results/summary');
        renderSummary();
        
        // Alerts
        const alertsText = await api('results/alerts');
        alerts = alertsText.trim().split('\n').filter(Boolean).map(l => {
            try { return JSON.parse(l); } catch { return null; }
        }).filter(Boolean);
        renderAlerts();
        el('badgeAlerts').textContent = summary.alerts_total || 0;
        el('badgeAlertsNav').textContent = alerts.length;
        
        // Flows
        const flowsText = await api('results/flows');
        flows = parseCSV(flowsText);
        renderSessions();
        el('badgeSessions').textContent = flows.length;
        
        // DNS log
        try {
            const dnsText = await api('results/dns');
            dnsLog = dnsText.trim().split('\n').filter(Boolean).map(l => {
                try { return JSON.parse(l); } catch { return null; }
            }).filter(Boolean);
            el('badgeDns').textContent = dnsLog.length;
        } catch { dnsLog = []; }
        
        // HTTP log
        try {
            const httpText = await api('results/http');
            httpLog = httpText.trim().split('\n').filter(Boolean).map(l => {
                try { return JSON.parse(l); } catch { return null; }
            }).filter(Boolean);
            el('badgeHttp').textContent = httpLog.length;
            renderHttp();
        } catch { httpLog = []; }
        
        // TLS log
        try {
            const tlsText = await api('results/tls');
            tlsLog = tlsText.trim().split('\n').filter(Boolean).map(l => {
                try { return JSON.parse(l); } catch { return null; }
            }).filter(Boolean);
            el('badgeTls').textContent = tlsLog.length;
            renderTls();
        } catch { tlsLog = []; }
        
        // Payload data
        try {
            const payloadText = await api('results/payload');
            payloadLog = payloadText.trim().split('\n').filter(Boolean).map(l => {
                try { return JSON.parse(l); } catch { return null; }
            }).filter(Boolean);
            el('badgePayload').textContent = payloadLog.length;
            renderPayload();
        } catch { payloadLog = []; }
        
        // Files
        try {
            files = await apiJson('results/files');
            el('badgeFiles').textContent = files.length;
            renderFiles();
        } catch { files = []; }
        
        // Render all
        renderHosts();
        renderDns();
        
    } catch (e) {
        console.error('Load results error:', e);
    }
}

function parseCSV(text) {
    const lines = text.trim().split('\n');
    if (lines.length < 2) return [];
    const headers = lines[0].split(',');
    return lines.slice(1).map(line => {
        const vals = line.split(',');
        const obj = {};
        headers.forEach((h, i) => obj[h] = vals[i] || '');
        return obj;
    });
}

function renderSummary() {
    if (!summary) return;
    const s = summary;
    el('summaryStats').innerHTML = `
        <div class="stats-card"><div class="value">${fmt(s.packets||0)}</div><div class="label">Packets</div></div>
        <div class="stats-card"><div class="value">${fmtBytes(s.bytes||0)}</div><div class="label">Bytes</div></div>
        <div class="stats-card"><div class="value">${fmt(s.ipv4||0)}</div><div class="label">IPv4</div></div>
        <div class="stats-card"><div class="value">${fmt(s.ipv6||0)}</div><div class="label">IPv6</div></div>
        <div class="stats-card"><div class="value">${fmt(s.tcp||0)}</div><div class="label">TCP</div></div>
        <div class="stats-card"><div class="value">${fmt(s.udp||0)}</div><div class="label">UDP</div></div>
        <div class="stats-card"><div class="value">${fmt(s.icmp||0)}</div><div class="label">ICMP</div></div>
        <div class="stats-card"><div class="value">${fmt(s.dns_queries||0)}</div><div class="label">DNS Queries</div></div>
        <div class="stats-card"><div class="value">${fmt(s.http_requests||0)}</div><div class="label">HTTP Requests</div></div>
        <div class="stats-card"><div class="value">${fmt(s.tls_handshakes||0)}</div><div class="label">TLS Handshakes</div></div>
        <div class="stats-card"><div class="value">${fmt(s.alerts_total||0)}</div><div class="label">Alerts</div></div>
        <div class="stats-card"><div class="value">${fmt(s.files_carved||0)}</div><div class="label">Files Carved</div></div>
    `;
    
    // Top sources
    el('topSrcTable').querySelector('tbody').innerHTML = (s.top_src_bytes||[]).slice(0,10).map(x => 
        `<tr><td>${esc(x.ip)}</td><td>${fmtBytes(x.count)}</td></tr>`
    ).join('') || '<tr><td colspan="2" class="text-muted">No data</td></tr>';
    
    // Top destinations
    el('topDstTable').querySelector('tbody').innerHTML = (s.top_dst_bytes||[]).slice(0,10).map(x => 
        `<tr><td>${esc(x.ip)}</td><td>${fmtBytes(x.count)}</td></tr>`
    ).join('') || '<tr><td colspan="2" class="text-muted">No data</td></tr>';
    
    // Port scan suspects
    el('portscanTable').querySelector('tbody').innerHTML = (s.portscan_suspects||[]).map(x => 
        `<tr><td>${esc(x.ip)}</td><td>${x.count}</td></tr>`
    ).join('') || '<tr><td colspan="2" class="text-muted">No suspects detected</td></tr>';
}

function renderHosts() {
    if (!summary) return;
    const hosts = new Map();
    (summary.top_src_bytes||[]).forEach(x => {
        const h = hosts.get(x.ip) || { ip: x.ip, srcBytes: 0, dstBytes: 0 };
        h.srcBytes = x.count;
        hosts.set(x.ip, h);
    });
    (summary.top_dst_bytes||[]).forEach(x => {
        const h = hosts.get(x.ip) || { ip: x.ip, srcBytes: 0, dstBytes: 0 };
        h.dstBytes = x.count;
        hosts.set(x.ip, h);
    });
    const arr = Array.from(hosts.values());
    el('badgeHosts').textContent = arr.length;
    
    const search = el('hostsSearch').value.toLowerCase();
    const filtered = arr.filter(h => !search || h.ip.toLowerCase().includes(search));
    
    el('hostsTable').querySelector('tbody').innerHTML = filtered.map(h => {
        const role = h.srcBytes > h.dstBytes ? 'Client' : 'Server';
        return `<tr><td>${esc(h.ip)}</td><td>${fmtBytes(h.srcBytes)}</td><td>${fmtBytes(h.dstBytes)}</td><td>${role}</td></tr>`;
    }).join('') || '<tr><td colspan="4" class="text-muted">No hosts found</td></tr>';
}

function renderSessions() {
    const search = el('sessionsSearch').value.toLowerCase();
    const proto = el('sessionsProto').value;
    
    const filtered = flows.filter(f => {
        if (proto && f.proto?.toLowerCase() !== proto) return false;
        if (search) {
            const str = JSON.stringify(f).toLowerCase();
            if (!str.includes(search)) return false;
        }
        return true;
    });
    
    el('sessionsTable').querySelector('tbody').innerHTML = filtered.slice(0, 500).map(f => `
        <tr>
            <td>${esc(f.src_ip||'')}:${f.src_port||''}</td>
            <td>${esc(f.dst_ip||'')}:${f.dst_port||''}</td>
            <td>${esc(f.proto||'')}</td>
            <td>${fmt(parseInt(f.packets)||0)}</td>
            <td>${fmtBytes(parseInt(f.bytes)||0)}</td>
            <td>${esc(f.app_proto||'-')}</td>
            <td>${fmtTs(parseFloat(f.first_ts)||0)}</td>
        </tr>
    `).join('') || '<tr><td colspan="7" class="text-muted">No sessions found</td></tr>';
}

function renderDns() {
    if (!summary) return;
    const search = el('dnsSearch').value.toLowerCase();
    const data = (summary.top_dns_qnames||[]).filter(x => !search || x.key.toLowerCase().includes(search));
    
    el('dnsTable').querySelector('tbody').innerHTML = data.map(x => 
        `<tr><td>${esc(x.key)}</td><td>${fmt(x.count)}</td></tr>`
    ).join('') || '<tr><td colspan="2" class="text-muted">No DNS queries found</td></tr>';
}

function renderHttp() {
    if (!summary) return;
    const search = el('httpSearch').value.toLowerCase();
    const data = (summary.top_http_hosts||[]).filter(x => !search || x.key.toLowerCase().includes(search));
    
    el('httpTable').querySelector('tbody').innerHTML = data.map(x => 
        `<tr><td>${esc(x.key)}</td><td>${fmt(x.count)}</td></tr>`
    ).join('') || '<tr><td colspan="2" class="text-muted">No HTTP data</td></tr>';
    
    el('httpLog').textContent = httpLog.slice(0, 100).map(x => JSON.stringify(x, null, 2)).join('\n\n') || 'No HTTP protocol logs available.';
}

function renderTls() {
    if (!summary) return;
    const search = el('tlsSearch').value.toLowerCase();
    const data = (summary.top_tls_sni||[]).filter(x => !search || x.key.toLowerCase().includes(search));
    
    el('tlsTable').querySelector('tbody').innerHTML = data.map(x => 
        `<tr><td>${esc(x.key)}</td><td>${fmt(x.count)}</td></tr>`
    ).join('') || '<tr><td colspan="2" class="text-muted">No TLS data</td></tr>';
    
    el('tlsLog').textContent = tlsLog.slice(0, 100).map(x => JSON.stringify(x, null, 2)).join('\n\n') || 'No TLS protocol logs available.';
}

function renderPayload() {
    const search = el('payloadSearch').value.toLowerCase();
    const proto = el('payloadProto').value;
    
    const filtered = payloadLog.filter(p => {
        if (proto && p.proto !== proto) return false;
        if (search) {
            const str = JSON.stringify(p).toLowerCase();
            if (!str.includes(search)) return false;
        }
        return true;
    });
    
    el('payloadTable').querySelector('tbody').innerHTML = filtered.slice(0, 500).map(p => {
        const strings = (p.strings || []).slice(0, 5).join(', ');
        const icmpType = (p.icmp_type !== undefined) ? `${p.icmp_type}/${p.icmp_code || 0}` : '-';
        return `<tr>
            <td>${fmtTs(p.ts||0)}</td>
            <td>${esc(p.src||'')}</td>
            <td>${esc(p.dst||'')}</td>
            <td>${esc(p.proto||'')}</td>
            <td>${icmpType}</td>
            <td>${fmtBytes(p.payload_len||0)}</td>
            <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(strings)}">${esc(strings) || '-'}</td>
        </tr>`;
    }).join('') || '<tr><td colspan="7" class="text-muted">No payload data extracted. Data is collected from ICMP, raw TCP/UDP and other protocols.</td></tr>';
    
    el('payloadLog').textContent = filtered.slice(0, 50).map(x => JSON.stringify(x, null, 2)).join('\n\n') || 'No payload data available.';
}

function renderFiles() {
    const carved = summary?.carved_files || files || [];
    el('filesTable').querySelector('tbody').innerHTML = carved.map(f => {
        const icon = getFileIcon(f.content_type || f.filename);
        return `<tr>
            <td class="file-icon">${icon}</td>
            <td>${esc(f.filename)}</td>
            <td>${esc(f.content_type||'-')}</td>
            <td>${fmtBytes(f.size||0)}</td>
            <td style="font-family:monospace;font-size:0.8em">${esc((f.sha256||'').substring(0,16))}...</td>
            <td>${esc(f.src_ip||'')} → ${esc(f.dst_ip||'')}</td>
            <td><a class="file-link" href="/api/results/file/${encodeURIComponent(f.filename)}" download>Download</a></td>
        </tr>`;
    }).join('') || '<tr><td colspan="7" class="text-muted">No files extracted. Enable "File Carving" to extract files.</td></tr>';
}

function getFileIcon(type) {
    if (!type) return '📄';
    if (type.includes('image')) return '🖼️';
    if (type.includes('video')) return '🎬';
    if (type.includes('audio')) return '🎵';
    if (type.includes('pdf')) return '📕';
    if (type.includes('zip') || type.includes('archive')) return '📦';
    if (type.includes('text') || type.includes('html')) return '📝';
    if (type.includes('javascript') || type.includes('json')) return '📜';
    if (type.includes('executable') || type.includes('msdownload')) return '⚙️';
    return '📄';
}

function renderAlerts() {
    const search = el('alertsSearch').value.toLowerCase();
    const type = el('alertsType').value;
    
    const filtered = alerts.filter(a => {
        if (type && a.type !== type) return false;
        if (search) {
            const str = JSON.stringify(a).toLowerCase();
            if (!str.includes(search)) return false;
        }
        return true;
    });
    
    el('alertsTable').querySelector('tbody').innerHTML = filtered.slice(0, 500).map(a => {
        const sev = getAlertSeverity(a.type);
        return `<tr>
            <td><span class="alert-badge ${sev}">${esc(a.type||'unknown')}</span></td>
            <td>${esc(a.src_ip||'')}:${a.src_port||''}</td>
            <td>${esc(a.dst_ip||'')}:${a.dst_port||''}</td>
            <td>${esc(a.proto||'')}</td>
            <td>${esc(a.detail||'')}</td>
            <td>${fmtTs(a.ts||0)}</td>
        </tr>`;
    }).join('') || '<tr><td colspan="6" class="text-muted">No alerts found</td></tr>';
}

function getAlertSeverity(type) {
    if (['blocklisted_ip', 'blocklisted_domain', 'exfiltration'].includes(type)) return 'critical';
    if (['port_scan', 'dns_tunnel', 'beaconing'].includes(type)) return 'high';
    if (['keyword_match', 'sensitive_data'].includes(type)) return 'medium';
    return 'low';
}

// Search handlers
el('hostsSearch').addEventListener('input', renderHosts);
el('sessionsSearch').addEventListener('input', renderSessions);
el('sessionsProto').addEventListener('change', renderSessions);
el('dnsSearch').addEventListener('input', renderDns);
el('httpSearch').addEventListener('input', renderHttp);
el('tlsSearch').addEventListener('input', renderTls);
el('payloadSearch').addEventListener('input', renderPayload);
el('payloadProto').addEventListener('change', renderPayload);
el('alertsSearch').addEventListener('input', renderAlerts);
el('alertsType').addEventListener('change', renderAlerts);

// Initial status poll
pollStatus();
</script>
</body>
</html>)HTML";
}

static std::map<std::string,std::string> parse_qs(const std::string& q) {
    std::map<std::string,std::string> m; 
    std::istringstream iss(q); 
    std::string p;
    while (std::getline(iss, p, '&')) { 
        auto e = p.find('=');
        if (e != std::string::npos) {
            m[url_decode(p.substr(0,e))] = url_decode(p.substr(e+1)); 
        }
    } 
    return m;
}

static std::string read_file_content(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return "";
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

// Parse HTTP headers from request string
static std::map<std::string, std::string> parse_headers(const std::string& req) {
    std::map<std::string, std::string> headers;
    auto pos = req.find("\r\n");
    if (pos == std::string::npos) return headers;
    
    size_t start = pos + 2;
    while (start < req.size()) {
        auto end = req.find("\r\n", start);
        if (end == std::string::npos || end == start) break;
        
        std::string line = req.substr(start, end - start);
        auto colon = line.find(':');
        if (colon != std::string::npos) {
            std::string key = line.substr(0, colon);
            std::string val = line.substr(colon + 1);
            // Trim leading whitespace from value
            while (!val.empty() && (val[0] == ' ' || val[0] == '\t')) val = val.substr(1);
            // Lowercase key for easier matching
            for (auto& c : key) c = std::tolower(c);
            headers[key] = val;
        }
        start = end + 2;
    }
    return headers;
}

// Get Content-Length from headers
static size_t get_content_length(const std::map<std::string, std::string>& headers) {
    auto it = headers.find("content-length");
    if (it == headers.end()) return 0;
    try {
        return std::stoull(it->second);
    } catch (...) {
        return 0;
    }
}

// Extract boundary from Content-Type header
static std::string get_multipart_boundary(const std::map<std::string, std::string>& headers) {
    auto it = headers.find("content-type");
    if (it == headers.end()) return "";
    
    auto pos = it->second.find("boundary=");
    if (pos == std::string::npos) return "";
    
    std::string boundary = it->second.substr(pos + 9);
    // Remove quotes if present
    if (!boundary.empty() && boundary[0] == '"') {
        auto end = boundary.find('"', 1);
        if (end != std::string::npos) {
            boundary = boundary.substr(1, end - 1);
        }
    }
    // Handle semicolon delimiter
    auto semi = boundary.find(';');
    if (semi != std::string::npos) {
        boundary = boundary.substr(0, semi);
    }
    return boundary;
}

// Upload size limits and buffer sizes
static constexpr size_t MAX_UPLOAD_SIZE = 2ULL * 1024 * 1024 * 1024; // 2GB max file size
static constexpr size_t RECV_BUFFER_SIZE = 65536;
static constexpr int UPLOAD_TIMEOUT_SECONDS = 300;  // 5 minute timeout for uploads
static constexpr size_t MAX_HTTP_HEADER_SIZE = 65536;  // Maximum HTTP header size
static constexpr int HEADER_READ_TIMEOUT_SECONDS = 30;  // Timeout for header read

// Set socket timeout for recv operations
static bool set_recv_timeout(int fd, int seconds) {
    struct timeval tv;
    tv.tv_sec = seconds;
    tv.tv_usec = 0;
    return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0;
}

// Receive full body from socket with proper handling
static std::string recv_body(int fd, size_t total_content_length, const std::string& already_read) {
    std::string body = already_read;
    
    // Calculate remaining bytes to read
    size_t remaining = total_content_length > body.size() ? total_content_length - body.size() : 0;
    if (remaining == 0) return body;
    
    body.reserve(total_content_length);
    
    // Set timeout to prevent blocking forever
    set_recv_timeout(fd, UPLOAD_TIMEOUT_SECONDS);
    
    char buf[RECV_BUFFER_SIZE];
    while (body.size() < total_content_length) {
        size_t to_read = std::min(sizeof(buf), total_content_length - body.size());
        ssize_t n = recv(fd, buf, to_read, 0);
        if (n <= 0) {
            // Connection closed, error, or timeout - return what we have
            break;
        }
        body.append(buf, (size_t)n);
    }
    return body;
}

// Extract filename from Content-Disposition header in multipart
static std::string extract_filename_from_part(const std::string& part_header) {
    auto pos = part_header.find("filename=\"");
    if (pos == std::string::npos) return "";
    
    auto start = pos + 10;
    auto end = part_header.find('"', start);
    if (end == std::string::npos) return "";
    
    return part_header.substr(start, end - start);
}

// Generate unique filename to avoid collisions
static std::string generate_unique_filename() {
    auto now = std::chrono::system_clock::now();
    auto time_since_epoch = now.time_since_epoch();
    auto micros = std::chrono::duration_cast<std::chrono::microseconds>(time_since_epoch).count();
    return "upload_" + std::to_string(micros) + ".pcap";
}

// Handle file upload - returns path on success, empty string on failure
static std::string handle_file_upload(int fd, const std::string& initial_data, 
                                       const std::map<std::string, std::string>& headers) {
    std::string boundary = get_multipart_boundary(headers);
    if (boundary.empty()) return "";
    
    size_t content_length = get_content_length(headers);
    if (content_length == 0 || content_length > MAX_UPLOAD_SIZE) {
        return "";
    }
    
    // Find where body starts in initial data
    auto body_start = initial_data.find("\r\n\r\n");
    if (body_start == std::string::npos) return "";
    body_start += 4;
    
    std::string body_portion = initial_data.substr(body_start);
    
    // Receive the rest of the body
    std::string body = recv_body(fd, content_length, body_portion);
    
    // Parse multipart - look for the file content
    std::string delim = "--" + boundary;
    auto part_start = body.find(delim);
    if (part_start == std::string::npos) return "";
    
    part_start += delim.length();
    if (body.substr(part_start, 2) == "\r\n") part_start += 2;
    
    // Find part header end
    auto header_end = body.find("\r\n\r\n", part_start);
    if (header_end == std::string::npos) return "";
    
    std::string part_header = body.substr(part_start, header_end - part_start);
    std::string filename = extract_filename_from_part(part_header);
    
    // Validate filename or generate unique one
    if (filename.empty() || !is_safe_filename(filename)) {
        filename = generate_unique_filename();
    }
    
    // Find the actual file content
    auto content_start = header_end + 4;
    auto content_end = body.find("\r\n--" + boundary, content_start);
    if (content_end == std::string::npos) {
        content_end = body.size();
    }
    
    // Extract file content
    std::string file_content = body.substr(content_start, content_end - content_start);
    
    // Create upload directory
    std::string upload_dir = g_workspace + "/uploads";
    fs::create_directories(upload_dir);
    
    // Save file
    std::string filepath = upload_dir + "/" + filename;
    std::ofstream out(filepath, std::ios::binary);
    if (!out) return "";
    
    out.write(file_content.data(), file_content.size());
    
    // Check if write succeeded
    if (!out.good()) {
        out.close();
        std::remove(filepath.c_str()); // Clean up incomplete file
        return "";
    }
    
    out.close();
    return filepath;
}

// Read HTTP headers completely (until \r\n\r\n is found)
static std::string read_http_headers(int fd) {
    std::string data;
    data.reserve(8192);
    char buf[4096];
    
    // Set a short timeout for initial header read
    set_recv_timeout(fd, HEADER_READ_TIMEOUT_SECONDS);
    
    while (data.size() < MAX_HTTP_HEADER_SIZE) {
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        data.append(buf, (size_t)n);
        
        // Check if we have complete headers
        if (data.find("\r\n\r\n") != std::string::npos) {
            break;
        }
    }
    return data;
}

static void handle_client(int fd) {
    // Read initial request with headers
    std::string req = read_http_headers(fd);
    if (req.empty()) { close(fd); return; }
    
    auto sp1 = req.find(' '), sp2 = req.find(' ', sp1+1);
    if (sp1 == std::string::npos || sp2 == std::string::npos) {
        close(fd);
        return;
    }
    std::string method = req.substr(0, sp1), path = req.substr(sp1+1, sp2-sp1-1);
    auto qpos = path.find('?'); 
    std::string query = qpos != std::string::npos ? path.substr(qpos+1) : "";
    if (qpos != std::string::npos) path = path.substr(0, qpos);
    
    // Main page
    if (path == "/" || path == "/index.html") { 
        send_resp(fd, 200, "text/html; charset=utf-8", get_page()); 
    }
    // Status API
    else if (path == "/api/status") {
        std::lock_guard<std::mutex> lk(g_log_mtx);
        std::ostringstream j; 
        j << "{\"running\":" << (g_running ? "true" : "false")
          << ",\"packets\":" << g_packets 
          << ",\"bytes\":" << g_bytes
          << ",\"percent\":" << g_percent
          << ",\"log\":\"" << json_escape(g_log + g_err) << "\"}";
        send_resp(fd, 200, "application/json", j.str());
    }
    // Start scan API
    else if (path == "/api/start" && method == "POST") {
        auto p = parse_qs(query);
        if (g_running) { 
            send_resp(fd, 200, "application/json", "{\"error\":\"already running\"}"); 
        }
        else {
            std::string out = g_workspace + "/scan_" + std::to_string(time(nullptr));
            int ranks = 4, topk = 50, pmax = 512, psth = 64, pswin = 10;
            try { if (p.count("ranks")) ranks = std::stoi(p["ranks"]); } catch(...) {}
            try { if (p.count("topk")) topk = std::stoi(p["topk"]); } catch(...) {}
            try { if (p.count("pmax")) pmax = std::stoi(p["pmax"]); } catch(...) {}
            try { if (p.count("psth")) psth = std::stoi(p["psth"]); } catch(...) {}
            try { if (p.count("pswin")) pswin = std::stoi(p["pswin"]); } catch(...) {}
            
            std::thread(scan_thread, p["pcap"], out, ranks,
                p["ipb"], p["domb"], p["kw"], p["bpf"], 
                p["carve"]=="1", p["noredact"]=="1",
                topk, pmax, psth, pswin).detach();
            send_resp(fd, 200, "application/json", "{\"success\":true}");
        }
    }
    // Stop scan API
    else if (path == "/api/stop" && method == "POST") { 
        stop_scan(); 
        send_resp(fd, 200, "application/json", "{\"success\":true}"); 
    }
    // Upload PCAP file API
    else if (path == "/api/upload" && method == "POST") {
        auto headers = parse_headers(req);
        std::string filepath = handle_file_upload(fd, req, headers);
        if (filepath.empty()) {
            send_resp(fd, 400, "application/json", "{\"error\":\"Upload failed\"}");
        } else {
            std::ostringstream json;
            json << "{\"success\":true,\"path\":\"" << json_escape(filepath) << "\"}";
            send_resp(fd, 200, "application/json", json.str());
        }
    }
    // Results: Summary
    else if (path == "/api/results/summary") {
        std::string content = read_file_content(g_outdir + "/summary.json");
        if (!content.empty()) {
            send_resp(fd, 200, "application/json", content);
        } else {
            send_resp(fd, 404, "application/json", "{\"error\":\"not found\"}");
        }
    }
    // Results: Alerts
    else if (path == "/api/results/alerts") {
        std::string content = read_file_content(g_outdir + "/alerts.ndjson");
        send_resp(fd, 200, "application/x-ndjson", content);
    }
    // Results: Flows
    else if (path == "/api/results/flows") {
        std::string content = read_file_content(g_outdir + "/flows.csv");
        send_resp(fd, 200, "text/csv", content);
    }
    // Results: DNS log
    else if (path == "/api/results/dns") {
        std::string content = read_file_content(g_outdir + "/dns.jsonl");
        send_resp(fd, 200, "application/x-ndjson", content);
    }
    // Results: HTTP log
    else if (path == "/api/results/http") {
        std::string content = read_file_content(g_outdir + "/http.jsonl");
        send_resp(fd, 200, "application/x-ndjson", content);
    }
    // Results: TLS log
    else if (path == "/api/results/tls") {
        std::string content = read_file_content(g_outdir + "/tls.jsonl");
        send_resp(fd, 200, "application/x-ndjson", content);
    }
    // Results: Payload data log
    else if (path == "/api/results/payload") {
        std::string content = read_file_content(g_outdir + "/payload.jsonl");
        send_resp(fd, 200, "application/x-ndjson", content);
    }
    // Results: Files list
    else if (path == "/api/results/files") {
        std::string filesDir = g_outdir + "/files";
        auto fileList = list_files_in_dir(filesDir);
        std::ostringstream json;
        json << "[";
        bool first = true;
        for (const auto& f : fileList) {
            if (!first) json << ",";
            first = false;
            json << "{\"filename\":\"" << json_escape(f.first) 
                 << "\",\"size\":" << f.second << "}";
        }
        json << "]";
        send_resp(fd, 200, "application/json", json.str());
    }
    // Results: Download carved file
    else if (path.rfind("/api/results/file/", 0) == 0) {
        std::string filename = url_decode(path.substr(18));
        // Security: comprehensive directory traversal and header injection protection
        if (!is_safe_filename(filename)) {
            send_resp(fd, 403, "text/plain", "Forbidden: Invalid filename");
        } else {
            std::string filepath = g_outdir + "/files/" + filename;
            std::string content = read_file_content(filepath);
            if (!content.empty()) {
                std::string mime = get_mime_type(filename);
                std::string safe_filename = sanitize_filename_for_header(filename);
                // Add Content-Disposition header for download
                std::ostringstream oss;
                oss << "HTTP/1.1 200 OK\r\n"
                    << "Content-Type: " << mime << "\r\n"
                    << "Content-Length: " << content.size() << "\r\n"
                    << "Content-Disposition: attachment; filename=\"" << safe_filename << "\"\r\n"
                    << "Connection: close\r\n\r\n";
                std::string header = oss.str();
                send(fd, header.c_str(), header.size(), 0);
                send(fd, content.c_str(), content.size(), 0);
            } else {
                send_resp(fd, 404, "text/plain", "File not found");
            }
        }
    }
    // 404
    else { 
        send_resp(fd, 404, "text/plain", "Not Found"); 
    }
    close(fd);
}

int main(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--port" && i+1 < argc) g_port = std::stoi(argv[++i]);
        else if (a == "--bind" && i+1 < argc) g_bind = argv[++i];
        else if (a == "--workspace" && i+1 < argc) g_workspace = argv[++i];
        else if (a == "--analyzer" && i+1 < argc) g_analyzer = argv[++i];
        else if (a == "--help" || a == "-h") {
            std::cout << "pdc_gui - NetworkMiner-like GUI for PDC PCAP Analyzer\n\n"
                << "A web-based network forensics interface similar to NetworkMiner,\n"
                << "providing comprehensive PCAP analysis with MPI acceleration.\n\n"
                << "Usage: pdc_gui [options]\n\n"
                << "Options:\n"
                << "  --port <N>         HTTP port (default: 8888)\n"
                << "  --bind <addr>      Bind address (default: 127.0.0.1)\n"
                << "  --workspace <dir>  Workspace directory (default: /tmp/pdc_workspace)\n"
                << "  --analyzer <path>  Path to pdc_pcap_analyzer (default: ./pdc_pcap_analyzer)\n"
                << "  --help, -h         Show this help\n\n"
                << "Features:\n"
                << "  - Hosts view: All detected IP addresses with traffic stats\n"
                << "  - Sessions: TCP/UDP flows with application protocol detection\n"
                << "  - DNS: Query names and response statistics\n"
                << "  - HTTP: Request hosts and detailed protocol logs\n"
                << "  - TLS/SSL: SNI, cipher suites, JA3 fingerprints\n"
                << "  - Files: Carved files from HTTP with SHA256 hashing\n"
                << "  - Credentials: Detected plaintext credentials (redacted by default)\n"
                << "  - Alerts: Security alerts for IOC matches, scans, tunneling, etc.\n\n"
                << "Example:\n"
                << "  ./pdc_gui --port 8080 --analyzer ./build/pdc_pcap_analyzer\n"
                << "  Then open http://localhost:8080 in your browser.\n";
            return 0;
        }
    }
    fs::create_directories(g_workspace);
    
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) {
        std::cerr << "Error: Failed to create socket\n";
        return 1;
    }
    
    int opt = 1; 
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    sockaddr_in addr{}; 
    addr.sin_family = AF_INET; 
    addr.sin_port = htons(g_port);
    inet_pton(AF_INET, g_bind.c_str(), &addr.sin_addr);
    
    if (bind(srv, (sockaddr*)&addr, sizeof(addr)) < 0) { 
        perror("bind"); 
        return 1; 
    }
    listen(srv, 32);
    
    std::cout << "\n";
    std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║         PDC Network Forensics Analyzer - GUI Server          ║\n";
    std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  URL:        http://" << g_bind << ":" << g_port;
    for (size_t i = 0; i < 35 - g_bind.size() - std::to_string(g_port).size(); i++) std::cout << " ";
    std::cout << "║\n";
    std::cout << "║  Workspace:  " << g_workspace;
    for (size_t i = 0; i < 47 - g_workspace.size(); i++) std::cout << " ";
    std::cout << "║\n";
    std::cout << "║  Analyzer:   " << g_analyzer;
    for (size_t i = 0; i < 47 - g_analyzer.size(); i++) std::cout << " ";
    std::cout << "║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
    std::cout << "\nOpen your browser to start analyzing PCAP files.\n";
    std::cout << "Press Ctrl+C to stop the server.\n\n";
    
    while (true) {
        int cli = accept(srv, nullptr, nullptr);
        if (cli >= 0) std::thread(handle_client, cli).detach();
    }
    return 0;
}
