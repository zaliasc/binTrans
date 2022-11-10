/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Linux Socket Filter Data Structures
 */
#ifndef __LINUX_FILTER_H__
#define __LINUX_FILTER_H__

/* ArgX, context and stack frame pointer register positions. Note,
 * Arg1, Arg2, Arg3, etc are used as argument mappings of function
 * calls in BPF_CALL instruction.
 */
#include "type.h"
#define BPF_REG_ARG1 BPF_REG_1
#define BPF_REG_ARG2 BPF_REG_2
#define BPF_REG_ARG3 BPF_REG_3
#define BPF_REG_ARG4 BPF_REG_4
#define BPF_REG_ARG5 BPF_REG_5
#define BPF_REG_CTX BPF_REG_6
#define BPF_REG_FP BPF_REG_10

/* Additional register mappings for converted user programs. */
#define BPF_REG_A BPF_REG_0
#define BPF_REG_X BPF_REG_7
#define BPF_REG_TMP BPF_REG_2 /* scratch reg */
#define BPF_REG_D BPF_REG_8   /* data, callee-saved */
#define BPF_REG_H BPF_REG_9   /* hlen, callee-saved */

/* Kernel hidden auxiliary/helper register. */
#define BPF_REG_AX MAX_BPF_REG
#define MAX_BPF_EXT_REG (MAX_BPF_REG + 1)
#define MAX_BPF_JIT_REG MAX_BPF_EXT_REG

/* unused opcode to mark special call to bpf_tail_call() helper */
#define BPF_TAIL_CALL 0xf0

/* unused opcode to mark special load instruction. Same as BPF_ABS */
#define BPF_PROBE_MEM 0x20

/* unused opcode to mark call to interpreter with arguments */
#define BPF_CALL_ARGS 0xe0

/* unused opcode to mark speculation barrier for mitigating
 * Speculative Store Bypass
 */
#define BPF_NOSPEC 0xc0

/* As per nm, we expose JITed images as text (code) section for
 * kallsyms. That way, tools like perf can find it to match
 * addresses.
 */
#define BPF_SYM_ELF_TYPE 't'

/* BPF program can access up to 512 bytes of stack space. */
#define MAX_BPF_STACK 512

#define BPF_IMAGE_ALIGNMENT 8

// struct bpf_binary_header {
//   u32 size;
//   u8 image[];
// };

int bpf_jit_get_func_addr(const struct bpf_prog *prog,
			  const struct bpf_insn *insn, bool extra_pass,
			  u64 *func_addr, bool *func_addr_fixed);

#endif