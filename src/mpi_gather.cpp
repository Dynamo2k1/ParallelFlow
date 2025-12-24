#include "mpi_gather.h"
#include <cstring>
#include <stdexcept>

static void append_u32(std::vector<uint8_t>& b, uint32_t v) {
  for (int i = 0; i < 4; i++) b.push_back((uint8_t)((v >> (i*8)) & 0xFF));
}
static void append_u64(std::vector<uint8_t>& b, uint64_t v) {
  for (int i = 0; i < 8; i++) b.push_back((uint8_t)((v >> (i*8)) & 0xFF));
}
static bool read_u32(const uint8_t* d, size_t n, size_t* off, uint32_t* v) {
  if (*off + 4 > n) return false;
  uint32_t r = 0;
  for (int i = 0; i < 4; i++) r |= (uint32_t)d[*off + i] << (i*8);
  *off += 4; *v = r; return true;
}
static bool read_u64(const uint8_t* d, size_t n, size_t* off, uint64_t* v) {
  if (*off + 8 > n) return false;
  uint64_t r = 0;
  for (int i = 0; i < 8; i++) r |= (uint64_t)d[*off + i] << (i*8);
  *off += 8; *v = r; return true;
}

std::vector<uint8_t> serialize_strcounts(const std::vector<StrCount>& v) {
  std::vector<uint8_t> b;
  append_u32(b, (uint32_t)v.size());
  for (const auto& it : v) {
    append_u64(b, it.count);
    append_u32(b, (uint32_t)it.key.size());
    b.insert(b.end(), it.key.begin(), it.key.end());
  }
  return b;
}

std::vector<StrCount> deserialize_strcounts(const uint8_t* data, size_t n) {
  std::vector<StrCount> v;
  size_t off = 0;
  uint32_t sz = 0;
  if (!read_u32(data, n, &off, &sz)) return v;
  v.reserve(sz);
  for (uint32_t i = 0; i < sz; i++) {
    uint64_t count = 0; uint32_t len = 0;
    if (!read_u64(data, n, &off, &count)) break;
    if (!read_u32(data, n, &off, &len)) break;
    if (off + len > n) break;
    std::string key((const char*)(data + off), (size_t)len);
    off += len;
    v.push_back(StrCount{std::move(key), count});
  }
  return v;
}

std::vector<uint8_t> serialize_ipcounts(const std::vector<IpCount>& v) {
  std::vector<uint8_t> b;
  append_u32(b, (uint32_t)v.size());
  for (const auto& it : v) {
    append_u32(b, it.ip_be);
    append_u64(b, it.count);
  }
  return b;
}

std::vector<IpCount> deserialize_ipcounts(const uint8_t* data, size_t n) {
  std::vector<IpCount> v;
  size_t off = 0;
  uint32_t sz = 0;
  if (!read_u32(data, n, &off, &sz)) return v;
  v.reserve(sz);
  for (uint32_t i = 0; i < sz; i++) {
    uint32_t ip = 0; uint64_t c = 0;
    if (!read_u32(data, n, &off, &ip)) break;
    if (!read_u64(data, n, &off, &c)) break;
    v.push_back(IpCount{ip, c});
  }
  return v;
}

std::vector<std::vector<uint8_t>> mpi_gather_buffers(const std::vector<uint8_t>& local, int root, MPI_Comm comm) {
  int rank = 0, size = 1;
  MPI_Comm_rank(comm, &rank);
  MPI_Comm_size(comm, &size);

  int local_n = (int)local.size();
  std::vector<int> sizes;
  if (rank == root) sizes.resize(size);
  MPI_Gather(&local_n, 1, MPI_INT, sizes.data(), 1, MPI_INT, root, comm);

  std::vector<int> displs;
  int total = 0;
  if (rank == root) {
    displs.resize(size);
    for (int i = 0; i < size; i++) {
      displs[i] = total;
      total += sizes[i];
    }
  }

  std::vector<uint8_t> all;
  if (rank == root) all.resize((size_t)total);

  MPI_Gatherv((void*)local.data(), local_n, MPI_BYTE,
              all.data(), sizes.data(), displs.data(), MPI_BYTE,
              root, comm);

  std::vector<std::vector<uint8_t>> out;
  if (rank != root) return out;

  out.resize(size);
  for (int i = 0; i < size; i++) {
    int n = sizes[i];
    out[i].assign(all.begin() + displs[i], all.begin() + displs[i] + n);
  }
  return out;
}
