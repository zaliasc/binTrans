#include "type.h"
#include "bpf.h"

#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <vector>
#include <map>
#include <string>

// elf-map-info ----------------------
// #define maps_entry_len 7
#define maps_entry_len 5
#define maps_key_size_offset 1
#define maps_value_size_offset 2
#define maps_max_entries_offset 3

typedef struct bpf_map {
    u32 type;
    u32 key_size;
    u32 value_size;
    u32 max_entry;
} bpf_map;

typedef struct relo_entry {
    u64 offset;
    u32 type;
    u32 index;
    std::string map_name;
} relo_entry;

typedef struct map_alloc_info {
    u32 start_addr;
    u32 end_addr;
    u32 entries;
} map_alloc_info;

class map_manager {
public:
    map_manager() = default;
    ~map_manager() = default;
    map_manager(const map_manager &) = delete;
    map_manager(map_manager &&) = delete;
    map_manager &operator=(const map_manager &) = delete;
    map_manager &operator=(map_manager &&) = delete;

    int parse_file(const std::string filePath);
    static int get_sec(Elf *elf, int i, GElf_Ehdr *ehdr, char **shname, GElf_Shdr *shdr, Elf_Data **data);
    void map_addr_alloc();
    u_int32_t map_addr_get(const std::string &map_name);
    void map_fix(struct bpf_prog &_bpf_prog);


private:
    const std::string _xdp_section = "xdp11";
    const std::string _rel_section = ".rel" + _xdp_section;

    std::map<u32, std::string> _symbol_info;

    std::vector<bpf_map> _map_parse_info;

    std::vector<relo_entry> _relo_info;

    std::map<std::string, map_alloc_info> _map_alloc_info;

    u_int32_t addr_map_cnt1 = 0x1234;

    u_int32_t addr_map_cnt2 = 0x5678;

    u_int32_t addr_map_cnt3 = 0x9999;
};