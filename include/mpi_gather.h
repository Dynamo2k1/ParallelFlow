#pragma once
#include <mpi.h>
#include <cstdint>
#include <string>
#include <vector>
#include <utility>

struct IpCount {
  uint32_t ip_be;
  uint64_t count;
};

struct StrCount {
  std::string key;
  uint64_t count;
};

std::vector<uint8_t> serialize_strcounts(const std::vector<StrCount>& v);
std::vector<StrCount> deserialize_strcounts(const uint8_t* data, size_t n);

std::vector<uint8_t> serialize_ipcounts(const std::vector<IpCount>& v);
std::vector<IpCount> deserialize_ipcounts(const uint8_t* data, size_t n);

std::vector<std::vector<uint8_t>> mpi_gather_buffers(const std::vector<uint8_t>& local, int root, MPI_Comm comm);
