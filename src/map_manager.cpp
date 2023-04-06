#include "map_manager.h"
#include <cassert>
// const char *symtype[] = {"STT_NOTYPE", "STT_OBJECT", "STT_FUNC", "STT_SECTION", "STT_FILE", "STT_COMMON", "STT_TLS"};
// const char *symbind[] = {"STB_LOCAL", "STB_GLOBAL", "STB_WEAK"};
// const char *symvisual[] = {"STV_DEFAULT", "STV_INTERNAL", "STV_HIDDEN", "STV_PROTECTED"};

int map_manager::get_sec(Elf *elf, int i, GElf_Ehdr *ehdr, char **shname, GElf_Shdr *shdr, Elf_Data **data) {
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

int map_manager::parse_file(const std::string filePath) {
    const char *path = filePath.c_str();
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
                _map_parse_info.push_back(bpf_map{
                    .type = cusor[0],
                    .key_size = cusor[maps_key_size_offset],
                    .value_size = cusor[maps_value_size_offset],
                    .max_entry = cusor[maps_max_entries_offset]});
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
                    _symbol_info[i] = buf;
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

        if (strcmp(shname, _rel_section.c_str()) == 0) {
            u8 *cusor = (u8 *)data->d_buf;
            int relo_entry_num = shdr.sh_size / shdr.sh_entsize;

            for (int i = 0; i < relo_entry_num; i++) {
                relo_entry tmprelo;
                memcpy(&tmprelo.offset, cusor, 8);
                memcpy(&tmprelo.type, cusor + 8, 4);
                memcpy(&tmprelo.index, cusor + 12, 4);
                tmprelo.offset /= 8;
                if (tmprelo.type == 0x01) {
                    tmprelo.map_name = _symbol_info[tmprelo.index];
                    // printf("%llu: %s\n", tmprelo.offset, _symbol_info[tmprelo.index].c_str());
                }
                _relo_info.push_back(tmprelo);
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

void map_manager::map_addr_alloc() {
    assert(!_map_parse_info.empty());

    int index = 0;

    for (auto &it: _map_parse_info) {
        
    }
}

u_int32_t map_manager::map_addr_get(const std::string &map_name) {
    u_int32_t func_addr;

    return addr_map_cnt1;
}

void map_manager::map_fix(struct bpf_prog &_bpf_prog) {
    int len = _bpf_prog.len;

    for (auto &relo_e : _relo_info) {
        // if (relo_e.type == 1) {
        auto offset = relo_e.offset;
        std::string map_name = relo_e.map_name;
        u_int32_t map_addr_fix = map_addr_get(map_name);
        _bpf_prog.insnsi[offset].imm = map_addr_fix;
    }
}

// int main() {
//     map_manager m;
//     m.parse_file("/home/zzc/project/bintrans/resource/prog_clang/xdp11_kern_clang.o");
//     return 0;
// }
