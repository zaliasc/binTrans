#include "murmur3.h"

struct map_info {
  int key_size;
  int value_size;
  int entries;
  int start_addr;
};

struct map_info _map_info[10];

// uint32_t hash;
// uint32_t seed = 42;

// std::string key = map_name;;
// MurmurHash3_x86_32(key.c_str(), key.size(), seed, &hash);

// uint32_t offset = hash % _info.entries;

void * bpf_map_lookup_elem(int fd, void *key) {
  // how to get addr from map ?
  // int offset = hash(_map_info[fd].key_size + _map_info[fd].value_size) % _map_info[fd].entries;
  int offset = _map_info[fd].key_size(key);
  void *ret = (key)map + offset;
}