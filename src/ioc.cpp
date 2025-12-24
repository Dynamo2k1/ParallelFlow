#include "ioc.h"
#include "common.h"
#include <sstream>
#include <vector>
#if defined(_WIN32)
  #include <winsock2.h>
#else
  #include <arpa/inet.h>
#endif

static bool parse_cidr(const std::string& s, CidrNet* out, std::string* err) {
  auto pos = s.find('/');
  if (pos == std::string::npos) return false;
  std::string ip = s.substr(0, pos);
  std::string bits = s.substr(pos + 1);
  bool ok = false;
  uint32_t ip_be = util::parse_ipv4_be(ip, &ok);
  if (!ok) { if (err) *err = "Invalid CIDR IP: " + s; return false; }
  int b = 0;
  try {
    size_t idx = 0;
    b = std::stoi(bits, &idx, 10);
    if (idx != bits.size()) throw std::runtime_error("bad");
  } catch (...) {
    if (err) *err = "Invalid CIDR mask bits: " + s;
    return false;
  }
  if (b < 0 || b > 32) { if (err) *err = "CIDR bits out of range: " + s; return false; }

  uint32_t mask_host = (b == 0) ? 0u : (0xFFFFFFFFu << (32 - b));
  // Convert mask_host (host order) to network byte order
  uint32_t mask_be = htonl(mask_host);
  // Compute network_be = ip_be & mask_be
  uint32_t network_be = ip_be & mask_be;

  out->network_be = network_be;
  out->mask_be = mask_be;
  return true;
}

IocLoadResult load_iocs(const std::string& ip_blocklist_path,
                        const std::string& domain_blocklist_path,
                        const std::string& keywords_path) {
  IocLoadResult r;
  IocLists lists;

  if (!ip_blocklist_path.empty()) {
    std::string err;
    auto lines = util::read_lines(ip_blocklist_path, &err);
    if (!err.empty()) { r.ok=false; r.error=err; return r; }
    for (const auto& line : lines) {
      CidrNet cn;
      std::string e;
      if (parse_cidr(line, &cn, &e)) {
        lists.ip_cidrs.push_back(cn);
        continue;
      }
      bool ok = false;
      uint32_t ip_be = util::parse_ipv4_be(line, &ok);
      if (!ok) { r.ok=false; r.error="Invalid IP entry in blocklist: " + line; return r; }
      lists.ip_exact_be.insert(ip_be);
    }
  }

  if (!domain_blocklist_path.empty()) {
    std::string err;
    auto lines = util::read_lines(domain_blocklist_path, &err);
    if (!err.empty()) { r.ok=false; r.error=err; return r; }
    for (auto d : lines) {
      d = util::to_lower(util::trim(d));
      if (d.empty()) continue;
      // remove trailing dot if any
      if (!d.empty() && d.back() == '.') d.pop_back();
      lists.domains_lower.insert(d);
    }
  }

  if (!keywords_path.empty()) {
    std::string err;
    auto lines = util::read_lines(keywords_path, &err);
    if (!err.empty()) { r.ok=false; r.error=err; return r; }
    for (auto k : lines) {
      k = util::trim(k);
      if (k.empty()) continue;
      lists.keywords.push_back(k);
    }
  }

  r.ok = true;
  r.lists = std::move(lists);
  return r;
}

bool ip_is_blocklisted(uint32_t ip_be, const IocLists& l) {
  if (l.ip_exact_be.find(ip_be) != l.ip_exact_be.end()) return true;
  for (const auto& c : l.ip_cidrs) {
    if ((ip_be & c.mask_be) == c.network_be) return true;
  }
  return false;
}

static bool ends_with_domain(const std::string& q, const std::string& d) {
  if (q == d) return true;
  if (q.size() <= d.size()) return false;
  // suffix match with dot boundary: *.d
  size_t pos = q.size() - d.size();
  if (q.compare(pos, d.size(), d) != 0) return false;
  return q[pos - 1] == '.';
}

bool domain_is_blocklisted(const std::string& qname_lower, const IocLists& l) {
  if (qname_lower.empty()) return false;
  auto q = qname_lower;
  if (!q.empty() && q.back() == '.') q.pop_back();
  if (l.domains_lower.find(q) != l.domains_lower.end()) return true;
  for (const auto& d : l.domains_lower) {
    if (ends_with_domain(q, d)) return true;
  }
  return false;
}
