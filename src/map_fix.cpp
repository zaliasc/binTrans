#include "type.h"
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

// const char *symtype[] = {"STT_NOTYPE", "STT_OBJECT", "STT_FUNC", "STT_SECTION", "STT_FILE", "STT_COMMON", "STT_TLS"};
// const char *symbind[] = {"STB_LOCAL", "STB_GLOBAL", "STB_WEAK"};
// const char *symvisual[] = {"STV_DEFAULT", "STV_INTERNAL", "STV_HIDDEN", "STV_PROTECTED"};

std::string xdp_section = "xdp1";
std::string rel_section = ".rel" + xdp_section;

// elf-symbol-info ----------------------

std::map<u32, std::string>
    symbol_info_global;

// elf-map-info ----------------------
#define maps_entry_len 7
#define maps_key_size_offset 1
#define maps_value_size_offset 2
#define maps_max_entries_offset 3

typedef struct bpf_map {
    u32 type;
    u32 key_size;
    u32 value_size;
    u32 max_entry;
} bpf_map;

std::vector<bpf_map> map_info_global;

// format
// type | key_size | value_size| max_entries
// 06000000 02000000 02000000 01010000 00000000 00000000 00000000  ................
// 06000000 08000000 04000000 fc010000 00000000 00000000 00000000
// 06000000 08000000 08000000 fd030000 00000000 00000000 00000000

#define rel_entry_len 7
#define rel_key_size_offset 1
#define rel_value_size_offset 2
#define rel_max_entries_offset 3

typedef struct relo_entry {
    u64 offset;
    u32 type;
    u32 index;
    std::string map_name;
} relo_entry;

std::vector<relo_entry> relo_info_global;
// ----------------------

// 0x00000000 08000000 00000000 01000000 44030000 ............ D...
// 0x00000010 30000000 00000000 01000000 44030000 0...........D...
// 0x00000020 58000000 00000000 01000000 44030000 X...........D...
// 0x00000030 80000000 00000000 01000000 44030000 ............ D...

// 每一个重定位的 entry 的组成：
//     64 | 32 | 32
//     offset | type | index
// - 低 64 位是 offset，用于关联当前 entry 对应代码 section 中具体的指令。(addr = **** / 8)
//   代码 section 指令位置到其 section 起始地址，偏移的长度 offset 等于这个 offset；
// - 高 64 位是 Info，其中的低 32 位对应重定位 symbol 的 type(0x01 map)，高 32 位对应重定位 symbol 的index（在 symbol 表的 id）。

static int
get_sec(Elf *elf, int i, GElf_Ehdr *ehdr, char **shname, GElf_Shdr *shdr, Elf_Data **data) {
    Elf_Scn *scn;
    scn = elf_getscn(elf, i); //从elf描述符获取按照节索引获取节接口
    if (!scn)
        return 1;
    if (gelf_getshdr(scn, shdr) != shdr) // 通过节结构复制节表头
        return 2;
    *shname = elf_strptr(elf, ehdr->e_shstrndx,
                         shdr->sh_name); // 从指定的字符串表中通过偏移获取字符串
    if (!*shname || !shdr->sh_size)
        return 3;
    *data = elf_getdata(scn, 0); //从节中获取节数据（经过了字节序的转换）
    if (!*data || elf_getdata(scn, *data) != NULL)
        return 4;
    return 0;
}

int parse_file(const char *path) {
    Elf *elf;
    int fd;
    GElf_Ehdr ehdr;
    GElf_Shdr shdr;
    char *shname, *shname_prog;
    Elf_Data *data;
    Elf_Data *data_strtab;

    if (elf_version(EV_CURRENT) == EV_NONE)
        return 1;
    fd = open(path, O_RDONLY, 0); //打开elf文件
    if (fd < 0) {
        printf("can not open %s\n", path);
        return -1;
    }
    elf = elf_begin(fd, ELF_C_READ, NULL); //获取elf描述符,使用‘读取’的方式
    if (!elf) {
        printf("can not get elf desc\n");
        return -1;
    }
    if (gelf_getehdr(elf, &ehdr) != &ehdr)
        return 1;

    // collect maps info
    for (int i = 1; i < ehdr.e_shnum; i++) {
        if (get_sec(elf, i, &ehdr, &shname, &shdr, &data))
            continue;

        if (strcmp(shname, "maps") == 0) {
            u32 *cusor = (u32 *)data->d_buf;
            int maps_entry_num = data->d_size / (maps_entry_len * sizeof(u32));

            for (int i = 0; i < maps_entry_num; i++) {
                map_info_global.push_back(bpf_map{
                    .type = cusor[0],
                    .key_size = cusor[maps_key_size_offset],
                    .value_size = cusor[maps_value_size_offset],
                    .max_entry = cusor[rel_max_entries_offset]});
                cusor += maps_entry_len;
            }
            break;
        }
    }

    // collect strtab data baseaddr
    for (int i = 1; i < ehdr.e_shnum; i++) {
        if (get_sec(elf, i, &ehdr, &shname, &shdr, &data_strtab))
            continue;

        if (strcmp(shname, ".strtab") == 0) {
            break;
        }
    }

    // https://bbs.pediy.com/thread-223569.htm
    // collect symbol info
    for (int i = 1; i < ehdr.e_shnum; i++) {
        if (get_sec(elf, i, &ehdr, &shname, &shdr, &data))
            continue;

        if (strcmp(shname, ".symtab") == 0) {
            u8 *cusor = (u8 *)data->d_buf;
            int symtab_entry_num = shdr.sh_size / shdr.sh_entsize;

            for (int i = 0; i < symtab_entry_num; i++) {
                Elf64_Sym tmpsym;
                memcpy(&tmpsym.st_name, cusor, 4);
                memcpy(&tmpsym.st_info, cusor + 4, 1);
                memcpy(&tmpsym.st_other, cusor + 5, 1);
                memcpy(&tmpsym.st_shndx, cusor + 6, 2);
                memcpy(&tmpsym.st_value, cusor + 8, 8);
                memcpy(&tmpsym.st_size, cusor + 16, 8);
                char *s = (char *)data_strtab->d_buf + tmpsym.st_name;
                if (*s != '\0') {
                    char buf[128];
                    sprintf(buf, "%s", s);
                    symbol_info_global[i] = buf;
                }
                cusor += shdr.sh_entsize;
            }
            break;
        }
    }

    // collect relo info
    for (int i = 1; i < ehdr.e_shnum; i++) {
        if (get_sec(elf, i, &ehdr, &shname, &shdr, &data))
            continue;

        if (strcmp(shname, rel_section.c_str()) == 0) {
            u8 *cusor = (u8 *)data->d_buf;
            int relo_entry_num = shdr.sh_size / shdr.sh_entsize;

            for (int i = 0; i < relo_entry_num; i++) {
                relo_entry tmprelo;
                memcpy(&tmprelo.offset, cusor, 8);
                memcpy(&tmprelo.type, cusor + 8, 4);
                memcpy(&tmprelo.index, cusor + 12, 4);
                tmprelo.offset /= 8;
                if (tmprelo.type == 0x01) {
                    tmprelo.map_name = symbol_info_global[tmprelo.index];
                    // printf("%llu: %s\n", tmprelo.offset, symbol_info_global[tmprelo.index].c_str());
                }
                relo_info_global.push_back(tmprelo);
                cusor += shdr.sh_entsize;
            }
            break;
        }
    }

    return 0;
    // for (int i = 1; i < ehdr.e_shnum; i++) {
    //     if (get_sec(elf, i, &ehdr, &shname, &shdr, &data))
    //         continue;
    //     printf("section %d:%s data %p size %zd link %d flags %d type %d\n", i, shname, data->d_buf, data->d_size, shdr.sh_link, (int)shdr.sh_flags, (int)shdr.sh_type);
    //     if (strcmp(shname, ".text") == 0) {
    //         printf(".text data:\n");
    //         unsigned char *p = (unsigned char *)data->d_buf;
    //         for (int j = 0; j < data->d_size; j++) {
    //             if (j % 8 == 0) {
    //                 printf("\n");
    //             }
    //             printf("%4x", *p++);
    //         }
    //         printf("\n");
    //     }
    // }
}

// Map的分布是按顺序的吗？
void alloc_map() {

}

int main() {
    parse_file("/space1/zzc_data/ebpf/bintrans/resource/prog/xdp11_kern.o");
    return 0;
}
