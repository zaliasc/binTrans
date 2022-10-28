#ifndef __BINTRANS_H__
#define __BINTRANS_H__

#include <assert.h>
#include <string.h>

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "bpf_jit.h"
#include "filter.h"
#include "type.h"

using namespace std;

namespace utils {
int file_load(vector<string> &v);

struct bpf_insn StringToInsn(const std::string &insn_string);

void dissassemble(uint64_t pc, char * buf, int buflen, u32 inst);

void riscv_insn_dump(struct rv_jit_context *ctx);


}  // namespace utils

namespace binTrans {

const std::string ebpf_resource_path = "/home/zzc/project/binTrans/ebpf_resource/";
const std::string prog_name = "xdp1_kern.o";
const std::string prog_path = ebpf_resource_path + prog_name;
const std::string bytecode_path = ebpf_resource_path + "bytecode_raw";

}  // namespace binTrans

#endif