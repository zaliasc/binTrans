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

const std::string root_path = "/home/zzc/project/code/ebpf/binTrans/prog/";
const std::string prog_name = "xdp1_kern.o";
const std::string prog_path = root_path + prog_name;
const std::string bytecode_path = "../prog/bytecode_raw";

}  // namespace binTrans

#endif