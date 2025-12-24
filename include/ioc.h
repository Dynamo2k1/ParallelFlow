#pragma once
#include <cstdint>
#include <string>
#include <unordered_set>
#include <vector>
#include <optional>

struct CidrNet {
  uint32_t network_be = 0; // network byte order
  uint32_t mask_be = 0;    // network byte order (contiguous mask)
};

struct IocLists {
  std::unordered_set<uint32_t> ip_exact_be;
  std::vector<CidrNet> ip_cidrs;

  std::unordered_set<std::string> domains_lower; // stored lowercase

  std::vector<std::string> keywords; // raw
};

struct IocLoadResult {
  bool ok = true;
  std::string error;
  IocLists lists;
};

IocLoadResult load_iocs(const std::string& ip_blocklist_path,
                        const std::string& domain_blocklist_path,
                        const std::string& keywords_path);

bool ip_is_blocklisted(uint32_t ip_be, const IocLists& l);
bool domain_is_blocklisted(const std::string& qname_lower, const IocLists& l);
