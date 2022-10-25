#include "binTrans.h"

#include "log.h"
#include "riscv-disas.h"

namespace utils {

int file_load(vector<string> &v) {
  std::ifstream infile;
  infile.open(binTrans::bytecode_path);
  assert(infile.is_open());
  int idx = 0;
  std::string s;

  while (getline(infile, s)) {
    // infile >> s;
    v.push_back(s);
    idx++;
  }

  infile.close();

  return idx;
}

// format:85 00 00 00 01 00 00 00	call 1
// 07 02 00 00 fc ff ff ff	r2 += -4
// code | src_reg | dst_reg | off | imm
// struct bpf_insn {
// 	__u8	code;		/* opcode */
// 	__u8	dst_reg:4;	/* dest register */
// 	__u8	src_reg:4;	/* source register */
// 	__s16	off;		/* signed offset */
// 	__s32	imm;		/* signed immediate constant */
// };
struct bpf_insn StringToInsn(const std::string &insn_string) {
  struct bpf_insn insn;
  insn.code = std::stoi(insn_string.substr(0, 2), 0, 16);
  insn.src_reg = std::stoi(insn_string.substr(2, 1), 0, 16);
  insn.dst_reg = std::stoi(insn_string.substr(3, 1), 0, 16);
  insn.off = ntohs(std::stoi(insn_string.substr(4, 4), 0, 16));
  int imm_low = ntohs(std::stoi(insn_string.substr(8, 4), 0, 16));
  int imm_high = ntohs(std::stoi(insn_string.substr(12, 4), 0, 16));
  insn.imm = imm_low + imm_high * 65536;
  return insn;
}

void dissassemble(uint64_t pc, char * buf, int buflen, u32 inst) {
  static int offset = 0;
  disasm_inst(buf, buflen, rv32, pc + offset, inst);
  // INSN(buf);
  INSN_ADDR(pc + offset, buf);
  offset += 4;
}

void riscv_insn_dump(struct rv_jit_context *ctx) {
  int riscv_len = ctx->ninsns;
  int *offset = ctx->offset;

  char buf[128] = {0};
  for (int i = 0; i < riscv_len / 2; i++) {
    u32 inst = ((u32)ctx->insns[2 * i + 1] << 16) + ((u32)ctx->insns[2 * i]);
    dissassemble(0, buf, sizeof(buf), inst);
  }
}

}  // namespace utils

static int build_body(struct rv_jit_context *ctx, bool extra_pass,
                      int *offset) {
  const struct bpf_prog *prog = ctx->prog;
  int i;

  for (i = 0; i < prog->len; i++) {
    const struct bpf_insn *insn = &prog->insnsi[i];
    int ret;

    ret = bpf_jit_emit_insn(insn, ctx, extra_pass);
    /* BPF_LD | BPF_IMM | BPF_DW: skip the next instruction. */
    if (ret > 0) i++;
    if (offset) offset[i] = ctx->ninsns;
    if (ret < 0) return ret;
  }
  return 0;
}

void bpf_int_jit_compile(struct bpf_prog *prog, struct rv_jit_context *ctx) {
  // struct rv_jit_context ctx;
  ctx->prog = prog;
  ctx->insns = new u16[10000];
  ctx->ninsns = 0;
  ctx->offset = new int[10000];
  // bpf_jit_build_prologue(ctx);
  build_body(ctx, false, ctx->offset);

  utils::riscv_insn_dump(ctx);

  // bpf_jit_build_epilogue(ctx);
}

int main() {
  std::vector<std::string> v1;

  int idx = utils::file_load(v1);

  struct bpf_insn *ins_vec = new bpf_insn[idx];

  for (int i = 0; i < idx; i++) ins_vec[i] = utils::StringToInsn(v1[i]);

  struct bpf_prog _bpf_prog;
  struct rv_jit_context ctx;

  _bpf_prog.len = idx;
  _bpf_prog.insnsi = ins_vec;

  auto my_logger =
      spdlog::basic_logger_mt("mylogger", "logs/riscvcode", true);
  spdlog::set_default_logger(my_logger);
  my_logger->set_pattern("%v");

  bpf_int_jit_compile(&_bpf_prog, &ctx);

  return 0;
}
