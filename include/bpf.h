/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2011-2014 PLUMgrid, http://plumgrid.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _UAPI__LINUX_BPF_H__
#define _UAPI__LINUX_BPF_H__

// #include <linux/types.h>
#include "bpf_common.h"
#include "type.h"

/* Extended instruction set based on top of classic BPF */

/* instruction classes */
#define BPF_JMP32 0x06 /* jmp mode in word width */
#define BPF_ALU64 0x07 /* alu mode in double word width */

/* ld/ldx fields */
#define BPF_DW 0x18     /* double word (64-bit) */
#define BPF_ATOMIC 0xc0 /* atomic memory ops - op type in immediate */
#define BPF_XADD 0xc0   /* exclusive add - legacy name */

/* alu/jmp fields */
#define BPF_MOV 0xb0  /* mov reg to reg */
#define BPF_ARSH 0xc0 /* sign extending arithmetic shift right */

/* change endianness of a register */
#define BPF_END 0xd0   /* flags for endianness conversion: */
#define BPF_TO_LE 0x00 /* convert to little-endian */
#define BPF_TO_BE 0x08 /* convert to big-endian */
#define BPF_FROM_LE BPF_TO_LE
#define BPF_FROM_BE BPF_TO_BE

/* jmp encodings */
#define BPF_JNE 0x50  /* jump != */
#define BPF_JLT 0xa0  /* LT is unsigned, '<' */
#define BPF_JLE 0xb0  /* LE is unsigned, '<=' */
#define BPF_JSGT 0x60 /* SGT is signed '>', GT in x86 */
#define BPF_JSGE 0x70 /* SGE is signed '>=', GE in x86 */
#define BPF_JSLT 0xc0 /* SLT is signed, '<' */
#define BPF_JSLE 0xd0 /* SLE is signed, '<=' */
#define BPF_CALL 0x80 /* function call */
#define BPF_EXIT 0x90 /* function return */

/* atomic op type fields (stored in immediate) */
#define BPF_FETCH 0x01 /* not an opcode on its own, used to build others */
#define BPF_XCHG (0xe0 | BPF_FETCH)    /* atomic exchange */
#define BPF_CMPXCHG (0xf0 | BPF_FETCH) /* atomic compare-and-write */

/* Register numbers */
enum {
  BPF_REG_0 = 0,
  BPF_REG_1,
  BPF_REG_2,
  BPF_REG_3,
  BPF_REG_4,
  BPF_REG_5,
  BPF_REG_6,
  BPF_REG_7,
  BPF_REG_8,
  BPF_REG_9,
  BPF_REG_10,
  __MAX_BPF_REG,
};

/* BPF has 10 general purpose 64-bit registers and stack frame. */
#define MAX_BPF_REG __MAX_BPF_REG

struct bpf_insn {
  __u8 code;        /* opcode */
  __u8 dst_reg : 4; /* dest register */
  __u8 src_reg : 4; /* source register */
  __s16 off;        /* signed offset */
  __s32 imm;        /* signed immediate constant */
};

/* Key of an a BPF_MAP_TYPE_LPM_TRIE entry */
struct bpf_lpm_trie_key {
  __u32 prefixlen; /* up to 32 for AF_INET, 128 for AF_INET6 */
  __u8 data[0];    /* Arbitrary size */
};

struct bpf_cgroup_storage_key {
  __u64 cgroup_inode_id; /* cgroup inode id */
  __u32 attach_type;     /* program attach type (enum bpf_attach_type) */
};

union bpf_iter_link_info {
  struct {
    __u32 map_fd;
  } map;
};

enum bpf_cmd {
  BPF_MAP_CREATE,
  BPF_MAP_LOOKUP_ELEM,
  BPF_MAP_UPDATE_ELEM,
  BPF_MAP_DELETE_ELEM,
  BPF_MAP_GET_NEXT_KEY,
  BPF_PROG_LOAD,
  BPF_OBJ_PIN,
  BPF_OBJ_GET,
  BPF_PROG_ATTACH,
  BPF_PROG_DETACH,
  BPF_PROG_TEST_RUN,
  BPF_PROG_RUN = BPF_PROG_TEST_RUN,
  BPF_PROG_GET_NEXT_ID,
  BPF_MAP_GET_NEXT_ID,
  BPF_PROG_GET_FD_BY_ID,
  BPF_MAP_GET_FD_BY_ID,
  BPF_OBJ_GET_INFO_BY_FD,
  BPF_PROG_QUERY,
  BPF_RAW_TRACEPOINT_OPEN,
  BPF_BTF_LOAD,
  BPF_BTF_GET_FD_BY_ID,
  BPF_TASK_FD_QUERY,
  BPF_MAP_LOOKUP_AND_DELETE_ELEM,
  BPF_MAP_FREEZE,
  BPF_BTF_GET_NEXT_ID,
  BPF_MAP_LOOKUP_BATCH,
  BPF_MAP_LOOKUP_AND_DELETE_BATCH,
  BPF_MAP_UPDATE_BATCH,
  BPF_MAP_DELETE_BATCH,
  BPF_LINK_CREATE,
  BPF_LINK_UPDATE,
  BPF_LINK_GET_FD_BY_ID,
  BPF_LINK_GET_NEXT_ID,
  BPF_ENABLE_STATS,
  BPF_ITER_CREATE,
  BPF_LINK_DETACH,
  BPF_PROG_BIND_MAP,
};

enum bpf_map_type {
  BPF_MAP_TYPE_UNSPEC,
  BPF_MAP_TYPE_HASH,
  BPF_MAP_TYPE_ARRAY,
  BPF_MAP_TYPE_PROG_ARRAY,
  BPF_MAP_TYPE_PERF_EVENT_ARRAY,
  BPF_MAP_TYPE_PERCPU_HASH,
  BPF_MAP_TYPE_PERCPU_ARRAY,
  BPF_MAP_TYPE_STACK_TRACE,
  BPF_MAP_TYPE_CGROUP_ARRAY,
  BPF_MAP_TYPE_LRU_HASH,
  BPF_MAP_TYPE_LRU_PERCPU_HASH,
  BPF_MAP_TYPE_LPM_TRIE,
  BPF_MAP_TYPE_ARRAY_OF_MAPS,
  BPF_MAP_TYPE_HASH_OF_MAPS,
  BPF_MAP_TYPE_DEVMAP,
  BPF_MAP_TYPE_SOCKMAP,
  BPF_MAP_TYPE_CPUMAP,
  BPF_MAP_TYPE_XSKMAP,
  BPF_MAP_TYPE_SOCKHASH,
  BPF_MAP_TYPE_CGROUP_STORAGE,
  BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
  BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE,
  BPF_MAP_TYPE_QUEUE,
  BPF_MAP_TYPE_STACK,
  BPF_MAP_TYPE_SK_STORAGE,
  BPF_MAP_TYPE_DEVMAP_HASH,
  BPF_MAP_TYPE_STRUCT_OPS,
  BPF_MAP_TYPE_RINGBUF,
  BPF_MAP_TYPE_INODE_STORAGE,
  BPF_MAP_TYPE_TASK_STORAGE,
  BPF_MAP_TYPE_BLOOM_FILTER,
};



/* cgroup-bpf attach flags used in BPF_PROG_ATTACH command
 *
 * NONE(default): No further bpf programs allowed in the subtree.
 *
 * BPF_F_ALLOW_OVERRIDE: If a sub-cgroup installs some bpf program,
 * the program in this cgroup yields to sub-cgroup program.
 *
 * BPF_F_ALLOW_MULTI: If a sub-cgroup installs some bpf program,
 * that cgroup program gets run in addition to the program in this cgroup.
 *
 * Only one program is allowed to be attached to a cgroup with
 * NONE or BPF_F_ALLOW_OVERRIDE flag.
 * Attaching another program on top of NONE or BPF_F_ALLOW_OVERRIDE will
 * release old program and attach the new one. Attach flags has to match.
 *
 * Multiple programs are allowed to be attached to a cgroup with
 * BPF_F_ALLOW_MULTI flag. They are executed in FIFO order
 * (those that were attached first, run first)
 * The programs of sub-cgroup are executed first, then programs of
 * this cgroup and then programs of parent cgroup.
 * When children program makes decision (like picking TCP CA or sock bind)
 * parent program has a chance to override it.
 *
 * With BPF_F_ALLOW_MULTI a new program is added to the end of the list of
 * programs for a cgroup. Though it's possible to replace an old program at
 * any position by also specifying BPF_F_REPLACE flag and position itself in
 * replace_bpf_fd attribute. Old program at this position will be released.
 *
 * A cgroup with MULTI or OVERRIDE flag allows any attach flags in sub-cgroups.
 * A cgroup with NONE doesn't allow any programs in sub-cgroups.
 * Ex1:
 * cgrp1 (MULTI progs A, B) ->
 *    cgrp2 (OVERRIDE prog C) ->
 *      cgrp3 (MULTI prog D) ->
 *        cgrp4 (OVERRIDE prog E) ->
 *          cgrp5 (NONE prog F)
 * the event in cgrp5 triggers execution of F,D,A,B in that order.
 * if prog F is detached, the execution is E,D,A,B
 * if prog F and D are detached, the execution is E,A,B
 * if prog F, E and D are detached, the execution is C,A,B
 *
 * All eligible programs are executed regardless of return code from
 * earlier programs.
 */
#define BPF_F_ALLOW_OVERRIDE (1U << 0)
#define BPF_F_ALLOW_MULTI (1U << 1)
#define BPF_F_REPLACE (1U << 2)

/* If BPF_F_STRICT_ALIGNMENT is used in BPF_PROG_LOAD command, the
 * verifier will perform strict alignment checking as if the kernel
 * has been built with CONFIG_EFFICIENT_UNALIGNED_ACCESS not set,
 * and NET_IP_ALIGN defined to 2.
 */
#define BPF_F_STRICT_ALIGNMENT (1U << 0)

/* If BPF_F_ANY_ALIGNMENT is used in BPF_PROF_LOAD command, the
 * verifier will allow any alignment whatsoever.  On platforms
 * with strict alignment requirements for loads ands stores (such
 * as sparc and mips) the verifier validates that all loads and
 * stores provably follow this requirement.  This flag turns that
 * checking and enforcement off.
 *
 * It is mostly used for testing when we want to validate the
 * context and memory access aspects of the verifier, but because
 * of an unaligned access the alignment check would trigger before
 * the one we are interested in.
 */
#define BPF_F_ANY_ALIGNMENT (1U << 1)

/* BPF_F_TEST_RND_HI32 is used in BPF_PROG_LOAD command for testing purpose.
 * Verifier does sub-register def/use analysis and identifies instructions whose
 * def only matters for low 32-bit, high 32-bit is never referenced later
 * through implicit zero extension. Therefore verifier notifies JIT back-ends
 * that it is safe to ignore clearing high 32-bit for these instructions. This
 * saves some back-ends a lot of code-gen. However such optimization is not
 * necessary on some arches, for example x86_64, arm64 etc, whose JIT back-ends
 * hence hasn't used verifier's analysis result. But, we really want to have a
 * way to be able to verify the correctness of the described optimization on
 * x86_64 on which testsuites are frequently exercised.
 *
 * So, this flag is introduced. Once it is set, verifier will randomize high
 * 32-bit for those instructions who has been identified as safe to ignore them.
 * Then, if verifier is not doing correct analysis, such randomization will
 * regress tests to expose bugs.
 */
#define BPF_F_TEST_RND_HI32 (1U << 2)

/* The verifier internal test flag. Behavior is undefined */
#define BPF_F_TEST_STATE_FREQ (1U << 3)

/* If BPF_F_SLEEPABLE is used in BPF_PROG_LOAD command, the verifier will
 * restrict map and helper usage for such programs. Sleepable BPF programs can
 * only be attached to hooks where kernel execution context allows sleeping.
 * Such programs are allowed to use helpers that may sleep like
 * bpf_copy_from_user().
 */
#define BPF_F_SLEEPABLE (1U << 4)

/* If BPF_F_XDP_HAS_FRAGS is used in BPF_PROG_LOAD command, the loaded program
 * fully support xdp frags.
 */
#define BPF_F_XDP_HAS_FRAGS (1U << 5)

/* link_create.kprobe_multi.flags used in LINK_CREATE command for
 * BPF_TRACE_KPROBE_MULTI attach type to create return probe.
 */
#define BPF_F_KPROBE_MULTI_RETURN (1U << 0)

/* When BPF ldimm64's insn[0].src_reg != 0 then this can have
 * the following extensions:
 *
 * insn[0].src_reg:  BPF_PSEUDO_MAP_[FD|IDX]
 * insn[0].imm:      map fd or fd_idx
 * insn[1].imm:      0
 * insn[0].off:      0
 * insn[1].off:      0
 * ldimm64 rewrite:  address of map
 * verifier type:    CONST_PTR_TO_MAP
 */
#define BPF_PSEUDO_MAP_FD 1
#define BPF_PSEUDO_MAP_IDX 5

/* insn[0].src_reg:  BPF_PSEUDO_MAP_[IDX_]VALUE
 * insn[0].imm:      map fd or fd_idx
 * insn[1].imm:      offset into value
 * insn[0].off:      0
 * insn[1].off:      0
 * ldimm64 rewrite:  address of map[0]+offset
 * verifier type:    PTR_TO_MAP_VALUE
 */
#define BPF_PSEUDO_MAP_VALUE 2
#define BPF_PSEUDO_MAP_IDX_VALUE 6

/* insn[0].src_reg:  BPF_PSEUDO_BTF_ID
 * insn[0].imm:      kernel btd id of VAR
 * insn[1].imm:      0
 * insn[0].off:      0
 * insn[1].off:      0
 * ldimm64 rewrite:  address of the kernel variable
 * verifier type:    PTR_TO_BTF_ID or PTR_TO_MEM, depending on whether the var
 *                   is struct/union.
 */
#define BPF_PSEUDO_BTF_ID 3
/* insn[0].src_reg:  BPF_PSEUDO_FUNC
 * insn[0].imm:      insn offset to the func
 * insn[1].imm:      0
 * insn[0].off:      0
 * insn[1].off:      0
 * ldimm64 rewrite:  address of the function
 * verifier type:    PTR_TO_FUNC.
 */
#define BPF_PSEUDO_FUNC 4

/* when bpf_call->src_reg == BPF_PSEUDO_CALL, bpf_call->imm == pc-relative
 * offset to another bpf function
 */
#define BPF_PSEUDO_CALL 1
/* when bpf_call->src_reg == BPF_PSEUDO_KFUNC_CALL,
 * bpf_call->imm == btf_id of a BTF_KIND_FUNC in the running kernel
 */
#define BPF_PSEUDO_KFUNC_CALL 2

/* flags for BPF_MAP_UPDATE_ELEM command */
enum {
  BPF_ANY = 0,     /* create new element or update existing */
  BPF_NOEXIST = 1, /* create new element if it didn't exist */
  BPF_EXIST = 2,   /* update existing element */
  BPF_F_LOCK = 4,  /* spin_lock-ed map_lookup/map_update */
};

/* flags for BPF_MAP_CREATE command */
enum {
  BPF_F_NO_PREALLOC = (1U << 0),
  /* Instead of having one common LRU list in the
   * BPF_MAP_TYPE_LRU_[PERCPU_]HASH map, use a percpu LRU list
   * which can scale and perform better.
   * Note, the LRU nodes (including free nodes) cannot be moved
   * across different LRU lists.
   */
  BPF_F_NO_COMMON_LRU = (1U << 1),
  /* Specify numa node during map creation */
  BPF_F_NUMA_NODE = (1U << 2),

  /* Flags for accessing BPF object from syscall side. */
  BPF_F_RDONLY = (1U << 3),
  BPF_F_WRONLY = (1U << 4),

  /* Flag for stack_map, store build_id+offset instead of pointer */
  BPF_F_STACK_BUILD_ID = (1U << 5),

  /* Zero-initialize hash function seed. This should only be used for testing.
   */
  BPF_F_ZERO_SEED = (1U << 6),

  /* Flags for accessing BPF object from program side. */
  BPF_F_RDONLY_PROG = (1U << 7),
  BPF_F_WRONLY_PROG = (1U << 8),

  /* Clone map from listener for newly accepted socket */
  BPF_F_CLONE = (1U << 9),

  /* Enable memory-mapping BPF map */
  BPF_F_MMAPABLE = (1U << 10),

  /* Share perf_event among processes */
  BPF_F_PRESERVE_ELEMS = (1U << 11),

  /* Create a map that is suitable to be an inner map with dynamic max entries
   */
  BPF_F_INNER_MAP = (1U << 12),
};

/* Flags for BPF_PROG_QUERY. */

/* Query effective (directly attached + inherited from ancestor cgroups)
 * programs that will be executed for events within a cgroup.
 * attach_flags with this flag are returned only for directly attached programs.
 */
#define BPF_F_QUERY_EFFECTIVE (1U << 0)

/* Flags for BPF_PROG_TEST_RUN */

/* If set, run the test on the cpu specified by bpf_attr.test.cpu */
#define BPF_F_TEST_RUN_ON_CPU (1U << 0)
/* If set, XDP frames will be transmitted after processing */
#define BPF_F_TEST_XDP_LIVE_FRAMES (1U << 1)

/* type for BPF_ENABLE_STATS */
enum bpf_stats_type {
  /* enabled run_time_ns and run_cnt */
  BPF_STATS_RUN_TIME = 0,
};

enum bpf_stack_build_id_status {
  /* user space need an empty entry to identify end of a trace */
  BPF_STACK_BUILD_ID_EMPTY = 0,
  /* with valid build_id and offset */
  BPF_STACK_BUILD_ID_VALID = 1,
  /* couldn't get build_id, fallback to ip */
  BPF_STACK_BUILD_ID_IP = 2,
};

#define BPF_BUILD_ID_SIZE 20
struct bpf_stack_build_id {
  __s32 status;
  unsigned char build_id[BPF_BUILD_ID_SIZE];
  union {
    __u64 offset;
    __u64 ip;
  };
};

#define BPF_OBJ_NAME_LEN 16U

union bpf_attr {
  struct {              /* anonymous struct used by BPF_MAP_CREATE command */
    __u32 map_type;     /* one of enum bpf_map_type */
    __u32 key_size;     /* size of key in bytes */
    __u32 value_size;   /* size of value in bytes */
    __u32 max_entries;  /* max number of entries in a map */
    __u32 map_flags;    /* BPF_MAP_CREATE related
                         * flags defined above.
                         */
    __u32 inner_map_fd; /* fd pointing to the inner map */
    __u32 numa_node;    /* numa node (effective only if
                         * BPF_F_NUMA_NODE is set).
                         */
    char map_name[BPF_OBJ_NAME_LEN];
    __u32 map_ifindex;               /* ifindex of netdev to create on */
    __u32 btf_fd;                    /* fd pointing to a BTF type data */
    __u32 btf_key_type_id;           /* BTF type_id of the key */
    __u32 btf_value_type_id;         /* BTF type_id of the value */
    __u32 btf_vmlinux_value_type_id; /* BTF type_id of a kernel-
                                      * struct stored as the
                                      * map value
                                      */
    /* Any per-map-type extra fields
     *
     * BPF_MAP_TYPE_BLOOM_FILTER - the lowest 4 bits indicate the
     * number of hash functions (if 0, the bloom filter will default
     * to using 5 hash functions).
     */
    __u64 map_extra;
  };

  struct { /* anonymous struct used by BPF_MAP_*_ELEM commands */
    __u32 map_fd;
    __aligned_u64 key;
    union {
      __aligned_u64 value;
      __aligned_u64 next_key;
    };
    __u64 flags;
  };

  struct {                   /* struct used by BPF_MAP_*_BATCH commands */
    __aligned_u64 in_batch;  /* start batch,
                              * NULL to start from beginning
                              */
    __aligned_u64 out_batch; /* output: next start batch */
    __aligned_u64 keys;
    __aligned_u64 values;
    __u32 count; /* input/output:
                  * input: # of key/value
                  * elements
                  * output: # of filled elements
                  */
    __u32 map_fd;
    __u64 elem_flags;
    __u64 flags;
  } batch;

  struct {           /* anonymous struct used by BPF_PROG_LOAD command */
    __u32 prog_type; /* one of enum bpf_prog_type */
    __u32 insn_cnt;
    __aligned_u64 insns;
    __aligned_u64 license;
    __u32 log_level;       /* verbosity level of verifier */
    __u32 log_size;        /* size of user buffer */
    __aligned_u64 log_buf; /* user supplied buffer */
    __u32 kern_version;    /* not used */
    __u32 prog_flags;
    char prog_name[BPF_OBJ_NAME_LEN];
    __u32 prog_ifindex; /* ifindex of netdev to prep for */
    /* For some prog types expected attach type must be known at
     * load time to verify attach type specific parts of prog
     * (context accesses, allowed helpers, etc).
     */
    __u32 expected_attach_type;
    __u32 prog_btf_fd;        /* fd pointing to BTF type data */
    __u32 func_info_rec_size; /* userspace bpf_func_info size */
    __aligned_u64 func_info;  /* func info */
    __u32 func_info_cnt;      /* number of bpf_func_info records */
    __u32 line_info_rec_size; /* userspace bpf_line_info size */
    __aligned_u64 line_info;  /* line info */
    __u32 line_info_cnt;      /* number of bpf_line_info records */
    __u32 attach_btf_id;      /* in-kernel BTF type id to attach to */
    union {
      /* valid prog_fd to attach to bpf prog */
      __u32 attach_prog_fd;
      /* or valid module BTF object fd or 0 to attach to vmlinux */
      __u32 attach_btf_obj_fd;
    };
    __u32 core_relo_cnt;    /* number of bpf_core_relo */
    __aligned_u64 fd_array; /* array of FDs */
    __aligned_u64 core_relos;
    __u32 core_relo_rec_size; /* sizeof(struct bpf_core_relo) */
  };

  struct { /* anonymous struct used by BPF_OBJ_* commands */
    __aligned_u64 pathname;
    __u32 bpf_fd;
    __u32 file_flags;
  };

  struct { /* anonymous struct used by BPF_PROG_ATTACH/DETACH commands */
    __u32 target_fd;     /* container object to attach to */
    __u32 attach_bpf_fd; /* eBPF program to attach */
    __u32 attach_type;
    __u32 attach_flags;
    __u32 replace_bpf_fd; /* previously attached eBPF
                           * program to replace if
                           * BPF_F_REPLACE is used
                           */
  };

  struct { /* anonymous struct used by BPF_PROG_TEST_RUN command */
    __u32 prog_fd;
    __u32 retval;
    __u32 data_size_in;  /* input: len of data_in */
    __u32 data_size_out; /* input/output: len of data_out
                          *   returns ENOSPC if data_out
                          *   is too small.
                          */
    __aligned_u64 data_in;
    __aligned_u64 data_out;
    __u32 repeat;
    __u32 duration;
    __u32 ctx_size_in;  /* input: len of ctx_in */
    __u32 ctx_size_out; /* input/output: len of ctx_out
                         *   returns ENOSPC if ctx_out
                         *   is too small.
                         */
    __aligned_u64 ctx_in;
    __aligned_u64 ctx_out;
    __u32 flags;
    __u32 cpu;
    __u32 batch_size;
  } test;

  struct { /* anonymous struct used by BPF_*_GET_*_ID */
    union {
      __u32 start_id;
      __u32 prog_id;
      __u32 map_id;
      __u32 btf_id;
      __u32 link_id;
    };
    __u32 next_id;
    __u32 open_flags;
  };

  struct { /* anonymous struct used by BPF_OBJ_GET_INFO_BY_FD */
    __u32 bpf_fd;
    __u32 info_len;
    __aligned_u64 info;
  } info;

  struct {           /* anonymous struct used by BPF_PROG_QUERY command */
    __u32 target_fd; /* container object to query */
    __u32 attach_type;
    __u32 query_flags;
    __u32 attach_flags;
    __aligned_u64 prog_ids;
    __u32 prog_cnt;
    __aligned_u64 prog_attach_flags; /* output: per-program attach_flags */
  } query;

  struct { /* anonymous struct used by BPF_RAW_TRACEPOINT_OPEN command */
    __u64 name;
    __u32 prog_fd;
  } raw_tracepoint;

  struct { /* anonymous struct for BPF_BTF_LOAD */
    __aligned_u64 btf;
    __aligned_u64 btf_log_buf;
    __u32 btf_size;
    __u32 btf_log_size;
    __u32 btf_log_level;
  };

  struct {
    __u32 pid;          /* input: pid */
    __u32 fd;           /* input: fd */
    __u32 flags;        /* input: flags */
    __u32 buf_len;      /* input/output: buf len */
    __aligned_u64 buf;  /* input/output:
                         *   tp_name for tracepoint
                         *   symbol for kprobe
                         *   filename for uprobe
                         */
    __u32 prog_id;      /* output: prod_id */
    __u32 fd_type;      /* output: BPF_FD_TYPE_* */
    __u64 probe_offset; /* output: probe_offset */
    __u64 probe_addr;   /* output: probe_addr */
  } task_fd_query;

  struct {         /* struct used by BPF_LINK_CREATE command */
    __u32 prog_fd; /* eBPF program to attach */
    union {
      __u32 target_fd;      /* object to attach to */
      __u32 target_ifindex; /* target ifindex */
    };
    __u32 attach_type; /* attach type */
    __u32 flags;       /* extra flags */
    union {
      __u32 target_btf_id; /* btf_id of target to attach to */
      struct {
        __aligned_u64 iter_info; /* extra bpf_iter_link_info */
        __u32 iter_info_len;     /* iter_info length */
      };
      struct {
        /* black box user-provided value passed through
         * to BPF program at the execution time and
         * accessible through bpf_get_attach_cookie() BPF helper
         */
        __u64 bpf_cookie;
      } perf_event;
      struct {
        __u32 flags;
        __u32 cnt;
        __aligned_u64 syms;
        __aligned_u64 addrs;
        __aligned_u64 cookies;
      } kprobe_multi;
      struct {
        /* this is overlaid with the target_btf_id above. */
        __u32 target_btf_id;
        /* black box user-provided value passed through
         * to BPF program at the execution time and
         * accessible through bpf_get_attach_cookie() BPF helper
         */
        __u64 cookie;
      } tracing;
    };
  } link_create;

  struct {         /* struct used by BPF_LINK_UPDATE command */
    __u32 link_fd; /* link fd */
    /* new program fd to update link with */
    __u32 new_prog_fd;
    __u32 flags; /* extra flags */
    /* expected link's program fd; is specified only if
     * BPF_F_REPLACE flag is set in flags */
    __u32 old_prog_fd;
  } link_update;

  struct {
    __u32 link_fd;
  } link_detach;

  struct { /* struct used by BPF_ENABLE_STATS command */
    __u32 type;
  } enable_stats;

  struct { /* struct used by BPF_ITER_CREATE command */
    __u32 link_fd;
    __u32 flags;
  } iter_create;

  struct { /* struct used by BPF_PROG_BIND_MAP command */
    __u32 prog_fd;
    __u32 map_fd;
    __u32 flags; /* extra flags */
  } prog_bind_map;

} __attribute__((aligned(8)));

#define __BPF_FUNC_MAPPER(FN)                                                  \
  FN(unspec), FN(map_lookup_elem), FN(map_update_elem), FN(map_delete_elem),   \
      FN(probe_read), FN(ktime_get_ns), FN(trace_printk), FN(get_prandom_u32), \
      FN(get_smp_processor_id), FN(skb_store_bytes), FN(l3_csum_replace),      \
      FN(l4_csum_replace), FN(tail_call), FN(clone_redirect),                  \
      FN(get_current_pid_tgid), FN(get_current_uid_gid), FN(get_current_comm), \
      FN(get_cgroup_classid), FN(skb_vlan_push), FN(skb_vlan_pop),             \
      FN(skb_get_tunnel_key), FN(skb_set_tunnel_key), FN(perf_event_read),     \
      FN(redirect), FN(get_route_realm), FN(perf_event_output),                \
      FN(skb_load_bytes), FN(get_stackid), FN(csum_diff),                      \
      FN(skb_get_tunnel_opt), FN(skb_set_tunnel_opt), FN(skb_change_proto),    \
      FN(skb_change_type), FN(skb_under_cgroup), FN(get_hash_recalc),          \
      FN(get_current_task), FN(probe_write_user),                              \
      FN(current_task_under_cgroup), FN(skb_change_tail), FN(skb_pull_data),   \
      FN(csum_update), FN(set_hash_invalid), FN(get_numa_node_id),             \
      FN(skb_change_head), FN(xdp_adjust_head), FN(probe_read_str),            \
      FN(get_socket_cookie), FN(get_socket_uid), FN(set_hash), FN(setsockopt), \
      FN(skb_adjust_room), FN(redirect_map), FN(sk_redirect_map),              \
      FN(sock_map_update), FN(xdp_adjust_meta), FN(perf_event_read_value),     \
      FN(perf_prog_read_value), FN(getsockopt), FN(override_return),           \
      FN(sock_ops_cb_flags_set), FN(msg_redirect_map), FN(msg_apply_bytes),    \
      FN(msg_cork_bytes), FN(msg_pull_data), FN(bind), FN(xdp_adjust_tail),    \
      FN(skb_get_xfrm_state), FN(get_stack), FN(skb_load_bytes_relative),      \
      FN(fib_lookup), FN(sock_hash_update), FN(msg_redirect_hash),             \
      FN(sk_redirect_hash), FN(lwt_push_encap), FN(lwt_seg6_store_bytes),      \
      FN(lwt_seg6_adjust_srh), FN(lwt_seg6_action), FN(rc_repeat),             \
      FN(rc_keydown), FN(skb_cgroup_id), FN(get_current_cgroup_id),            \
      FN(get_local_storage), FN(sk_select_reuseport),                          \
      FN(skb_ancestor_cgroup_id), FN(sk_lookup_tcp), FN(sk_lookup_udp),        \
      FN(sk_release), FN(map_push_elem), FN(map_pop_elem), FN(map_peek_elem),  \
      FN(msg_push_data), FN(msg_pop_data), FN(rc_pointer_rel), FN(spin_lock),  \
      FN(spin_unlock), FN(sk_fullsock), FN(tcp_sock), FN(skb_ecn_set_ce),      \
      FN(get_listener_sock), FN(skc_lookup_tcp), FN(tcp_check_syncookie),      \
      FN(sysctl_get_name), FN(sysctl_get_current_value),                       \
      FN(sysctl_get_new_value), FN(sysctl_set_new_value), FN(strtol),          \
      FN(strtoul), FN(sk_storage_get), FN(sk_storage_delete), FN(send_signal), \
      FN(tcp_gen_syncookie), FN(skb_output), FN(probe_read_user),              \
      FN(probe_read_kernel), FN(probe_read_user_str),                          \
      FN(probe_read_kernel_str), FN(tcp_send_ack), FN(send_signal_thread),     \
      FN(jiffies64), FN(read_branch_records), FN(get_ns_current_pid_tgid),     \
      FN(xdp_output), FN(get_netns_cookie),                                    \
      FN(get_current_ancestor_cgroup_id), FN(sk_assign),                       \
      FN(ktime_get_boot_ns), FN(seq_printf), FN(seq_write), FN(sk_cgroup_id),  \
      FN(sk_ancestor_cgroup_id), FN(ringbuf_output), FN(ringbuf_reserve),      \
      FN(ringbuf_submit), FN(ringbuf_discard), FN(ringbuf_query),              \
      FN(csum_level), FN(skc_to_tcp6_sock), FN(skc_to_tcp_sock),               \
      FN(skc_to_tcp_timewait_sock), FN(skc_to_tcp_request_sock),               \
      FN(skc_to_udp6_sock), FN(get_task_stack), FN(load_hdr_opt),              \
      FN(store_hdr_opt), FN(reserve_hdr_opt), FN(inode_storage_get),           \
      FN(inode_storage_delete), FN(d_path), FN(copy_from_user),                \
      FN(snprintf_btf), FN(seq_printf_btf), FN(skb_cgroup_classid),            \
      FN(redirect_neigh), FN(per_cpu_ptr), FN(this_cpu_ptr),                   \
      FN(redirect_peer), FN(task_storage_get), FN(task_storage_delete),        \
      FN(get_current_task_btf), FN(bprm_opts_set), FN(ktime_get_coarse_ns),    \
      FN(ima_inode_hash), FN(sock_from_file), FN(check_mtu),                   \
      FN(for_each_map_elem), FN(snprintf), FN(sys_bpf),                        \
      FN(btf_find_by_name_kind), FN(sys_close), FN(timer_init),                \
      FN(timer_set_callback), FN(timer_start), FN(timer_cancel),               \
      FN(get_func_ip), FN(get_attach_cookie), FN(task_pt_regs),                \
      FN(get_branch_snapshot), FN(trace_vprintk), FN(skc_to_unix_sock),        \
      FN(kallsyms_lookup_name), FN(find_vma), FN(loop), FN(strncmp),           \
      FN(get_func_arg), FN(get_func_ret), FN(get_func_arg_cnt),                \
      FN(get_retval), FN(set_retval), FN(xdp_get_buff_len),                    \
      FN(xdp_load_bytes), FN(xdp_store_bytes), FN(copy_from_user_task),        \
      FN(skb_set_tstamp), FN(ima_file_hash), FN(kptr_xchg),                    \
      FN(map_lookup_percpu_elem), FN(skc_to_mptcp_sock), FN(dynptr_from_mem),  \
      FN(ringbuf_reserve_dynptr), FN(ringbuf_submit_dynptr),                   \
      FN(ringbuf_discard_dynptr), FN(dynptr_read), FN(dynptr_write),           \
      FN(dynptr_data), FN(tcp_raw_gen_syncookie_ipv4),                         \
      FN(tcp_raw_gen_syncookie_ipv6), FN(tcp_raw_check_syncookie_ipv4),        \
      FN(tcp_raw_check_syncookie_ipv6), /* */

/* integer value in 'imm' field of BPF_CALL instruction selects which helper
 * function eBPF program intends to call
 */
#define __BPF_ENUM_FN(x) BPF_FUNC_##x
enum bpf_func_id {
  __BPF_FUNC_MAPPER(__BPF_ENUM_FN) __BPF_FUNC_MAX_ID,
};
#undef __BPF_ENUM_FN

/* All flags used by eBPF helper functions, placed here. */

/* BPF_FUNC_skb_store_bytes flags. */
enum {
  BPF_F_RECOMPUTE_CSUM = (1ULL << 0),
  BPF_F_INVALIDATE_HASH = (1ULL << 1),
};

/* BPF_FUNC_l3_csum_replace and BPF_FUNC_l4_csum_replace flags.
 * First 4 bits are for passing the header field size.
 */
enum {
  BPF_F_HDR_FIELD_MASK = 0xfULL,
};

/* BPF_FUNC_l4_csum_replace flags. */
enum {
  BPF_F_PSEUDO_HDR = (1ULL << 4),
  BPF_F_MARK_MANGLED_0 = (1ULL << 5),
  BPF_F_MARK_ENFORCE = (1ULL << 6),
};

/* BPF_FUNC_clone_redirect and BPF_FUNC_redirect flags. */
enum {
  BPF_F_INGRESS = (1ULL << 0),
};

/* BPF_FUNC_skb_set_tunnel_key and BPF_FUNC_skb_get_tunnel_key flags. */
enum {
  BPF_F_TUNINFO_IPV6 = (1ULL << 0),
};

/* flags for both BPF_FUNC_get_stackid and BPF_FUNC_get_stack. */
enum {
  BPF_F_SKIP_FIELD_MASK = 0xffULL,
  BPF_F_USER_STACK = (1ULL << 8),
  /* flags used by BPF_FUNC_get_stackid only. */
  BPF_F_FAST_STACK_CMP = (1ULL << 9),
  BPF_F_REUSE_STACKID = (1ULL << 10),
  /* flags used by BPF_FUNC_get_stack only. */
  BPF_F_USER_BUILD_ID = (1ULL << 11),
};

/* BPF_FUNC_skb_set_tunnel_key flags. */
enum {
  BPF_F_ZERO_CSUM_TX = (1ULL << 1),
  BPF_F_DONT_FRAGMENT = (1ULL << 2),
  BPF_F_SEQ_NUMBER = (1ULL << 3),
};

/* BPF_FUNC_perf_event_output, BPF_FUNC_perf_event_read and
 * BPF_FUNC_perf_event_read_value flags.
 */
enum {
  BPF_F_INDEX_MASK = 0xffffffffULL,
  BPF_F_CURRENT_CPU = BPF_F_INDEX_MASK,
  /* BPF_FUNC_perf_event_output for sk_buff input context. */
  BPF_F_CTXLEN_MASK = (0xfffffULL << 32),
};

/* Current network namespace */
enum {
  BPF_F_CURRENT_NETNS = (-1L),
};

/* BPF_FUNC_csum_level level values. */
enum {
  BPF_CSUM_LEVEL_QUERY,
  BPF_CSUM_LEVEL_INC,
  BPF_CSUM_LEVEL_DEC,
  BPF_CSUM_LEVEL_RESET,
};

/* BPF_FUNC_skb_adjust_room flags. */
enum {
  BPF_F_ADJ_ROOM_FIXED_GSO = (1ULL << 0),
  BPF_F_ADJ_ROOM_ENCAP_L3_IPV4 = (1ULL << 1),
  BPF_F_ADJ_ROOM_ENCAP_L3_IPV6 = (1ULL << 2),
  BPF_F_ADJ_ROOM_ENCAP_L4_GRE = (1ULL << 3),
  BPF_F_ADJ_ROOM_ENCAP_L4_UDP = (1ULL << 4),
  BPF_F_ADJ_ROOM_NO_CSUM_RESET = (1ULL << 5),
  BPF_F_ADJ_ROOM_ENCAP_L2_ETH = (1ULL << 6),
};

enum {
  BPF_ADJ_ROOM_ENCAP_L2_MASK = 0xff,
  BPF_ADJ_ROOM_ENCAP_L2_SHIFT = 56,
};

#define BPF_F_ADJ_ROOM_ENCAP_L2(len) \
  (((__u64)len & BPF_ADJ_ROOM_ENCAP_L2_MASK) << BPF_ADJ_ROOM_ENCAP_L2_SHIFT)

/* BPF_FUNC_sysctl_get_name flags. */
enum {
  BPF_F_SYSCTL_BASE_NAME = (1ULL << 0),
};

/* BPF_FUNC_<kernel_obj>_storage_get flags */
enum {
  BPF_LOCAL_STORAGE_GET_F_CREATE = (1ULL << 0),
  /* BPF_SK_STORAGE_GET_F_CREATE is only kept for backward compatibility
   * and BPF_LOCAL_STORAGE_GET_F_CREATE must be used instead.
   */
  BPF_SK_STORAGE_GET_F_CREATE = BPF_LOCAL_STORAGE_GET_F_CREATE,
};

/* BPF_FUNC_read_branch_records flags. */
enum {
  BPF_F_GET_BRANCH_RECORDS_SIZE = (1ULL << 0),
};

/* BPF_FUNC_bpf_ringbuf_commit, BPF_FUNC_bpf_ringbuf_discard, and
 * BPF_FUNC_bpf_ringbuf_output flags.
 */
enum {
  BPF_RB_NO_WAKEUP = (1ULL << 0),
  BPF_RB_FORCE_WAKEUP = (1ULL << 1),
};

/* BPF_FUNC_bpf_ringbuf_query flags */
enum {
  BPF_RB_AVAIL_DATA = 0,
  BPF_RB_RING_SIZE = 1,
  BPF_RB_CONS_POS = 2,
  BPF_RB_PROD_POS = 3,
};

/* BPF ring buffer constants */
enum {
  BPF_RINGBUF_BUSY_BIT = (1U << 31),
  BPF_RINGBUF_DISCARD_BIT = (1U << 30),
  BPF_RINGBUF_HDR_SZ = 8,
};

/* BPF_FUNC_sk_assign flags in bpf_sk_lookup context. */
enum {
  BPF_SK_LOOKUP_F_REPLACE = (1ULL << 0),
  BPF_SK_LOOKUP_F_NO_REUSEPORT = (1ULL << 1),
};

/* Mode for BPF_FUNC_skb_adjust_room helper. */
enum bpf_adj_room_mode {
  BPF_ADJ_ROOM_NET,
  BPF_ADJ_ROOM_MAC,
};

/* Mode for BPF_FUNC_skb_load_bytes_relative helper. */
enum bpf_hdr_start_off {
  BPF_HDR_START_MAC,
  BPF_HDR_START_NET,
};

/* Encapsulation type for BPF_FUNC_lwt_push_encap helper. */
enum bpf_lwt_encap_mode {
  BPF_LWT_ENCAP_SEG6,
  BPF_LWT_ENCAP_SEG6_INLINE,
  BPF_LWT_ENCAP_IP,
};

/* Flags for bpf_bprm_opts_set helper */
enum {
  BPF_F_BPRM_SECUREEXEC = (1ULL << 0),
};

/* Flags for bpf_redirect_map helper */
enum {
  BPF_F_BROADCAST = (1ULL << 3),
  BPF_F_EXCLUDE_INGRESS = (1ULL << 4),
};

#define __bpf_md_ptr(type, name) \
  union {                        \
    type name;                   \
    __u64 : 64;                  \
  } __attribute__((aligned(8)))

enum {
  BPF_SKB_TSTAMP_UNSPEC,
  BPF_SKB_TSTAMP_DELIVERY_MONO, /* tstamp has mono delivery time */
  /* For any BPF_SKB_TSTAMP_* that the bpf prog cannot handle,
   * the bpf prog should handle it like BPF_SKB_TSTAMP_UNSPEC
   * and try to deduce it by ingress, egress or skb->sk->sk_clockid.
   */
};

/* user accessible mirror of in-kernel sk_buff.
 * new fields can only be added to the end of this structure
 */
struct __sk_buff {
  __u32 len;
  __u32 pkt_type;
  __u32 mark;
  __u32 queue_mapping;
  __u32 protocol;
  __u32 vlan_present;
  __u32 vlan_tci;
  __u32 vlan_proto;
  __u32 priority;
  __u32 ingress_ifindex;
  __u32 ifindex;
  __u32 tc_index;
  __u32 cb[5];
  __u32 hash;
  __u32 tc_classid;
  __u32 data;
  __u32 data_end;
  __u32 napi_id;

  /* Accessed by BPF_PROG_TYPE_sk_skb types from here to ... */
  __u32 family;
  __u32 remote_ip4;    /* Stored in network byte order */
  __u32 local_ip4;     /* Stored in network byte order */
  __u32 remote_ip6[4]; /* Stored in network byte order */
  __u32 local_ip6[4];  /* Stored in network byte order */
  __u32 remote_port;   /* Stored in network byte order */
  __u32 local_port;    /* stored in host byte order */
  /* ... here. */

  __u32 data_meta;
  __bpf_md_ptr(struct bpf_flow_keys *, flow_keys);
  __u64 tstamp;
  __u32 wire_len;
  __u32 gso_segs;
  __bpf_md_ptr(struct bpf_sock *, sk);
  __u32 gso_size;
  __u8 tstamp_type;
  __u32 : 24; /* Padding, future use. */
  __u64 hwtstamp;
};

struct bpf_tunnel_key {
  __u32 tunnel_id;
  union {
    __u32 remote_ipv4;
    __u32 remote_ipv6[4];
  };
  __u8 tunnel_tos;
  __u8 tunnel_ttl;
  __u16 tunnel_ext; /* Padding, future use. */
  __u32 tunnel_label;
  union {
    __u32 local_ipv4;
    __u32 local_ipv6[4];
  };
};

/* user accessible mirror of in-kernel xfrm_state.
 * new fields can only be added to the end of this structure
 */
struct bpf_xfrm_state {
  __u32 reqid;
  __u32 spi; /* Stored in network byte order */
  __u16 family;
  __u16 ext; /* Padding, future use. */
  union {
    __u32 remote_ipv4;    /* Stored in network byte order */
    __u32 remote_ipv6[4]; /* Stored in network byte order */
  };
};

/* Generic BPF return codes which all BPF program types may support.
 * The values are binary compatible with their TC_ACT_* counter-part to
 * provide backwards compatibility with existing SCHED_CLS and SCHED_ACT
 * programs.
 *
 * XDP is handled seprately, see XDP_*.
 */
enum bpf_ret_code {
  BPF_OK = 0,
  /* 1 reserved */
  BPF_DROP = 2,
  /* 3-6 reserved */
  BPF_REDIRECT = 7,
  /* >127 are reserved for prog type specific return codes.
   *
   * BPF_LWT_REROUTE: used by BPF_PROG_TYPE_LWT_IN and
   *    BPF_PROG_TYPE_LWT_XMIT to indicate that skb had been
   *    changed and should be routed based on its new L3 header.
   *    (This is an L3 redirect, as opposed to L2 redirect
   *    represented by BPF_REDIRECT above).
   */
  BPF_LWT_REROUTE = 128,
};

struct bpf_sock {
  __u32 bound_dev_if;
  __u32 family;
  __u32 type;
  __u32 protocol;
  __u32 mark;
  __u32 priority;
  /* IP address also allows 1 and 2 bytes access */
  __u32 src_ip4;
  __u32 src_ip6[4];
  __u32 src_port;  /* host byte order */
  __be16 dst_port; /* network byte order */
  __u16 : 16;      /* zero padding */
  __u32 dst_ip4;
  __u32 dst_ip6[4];
  __u32 state;
  __s32 rx_queue_mapping;
};

struct bpf_tcp_sock {
  __u32 snd_cwnd; /* Sending congestion window		*/
  __u32 srtt_us;  /* smoothed round trip time << 3 in usecs */
  __u32 rtt_min;
  __u32 snd_ssthresh;     /* Slow start size threshold		*/
  __u32 rcv_nxt;          /* What we want to receive next		*/
  __u32 snd_nxt;          /* Next sequence we send		*/
  __u32 snd_una;          /* First byte we want an ack for	*/
  __u32 mss_cache;        /* Cached effective mss, not including SACKS */
  __u32 ecn_flags;        /* ECN status bits.			*/
  __u32 rate_delivered;   /* saved rate sample: packets delivered */
  __u32 rate_interval_us; /* saved rate sample: time elapsed */
  __u32 packets_out;      /* Packets which are "in flight"	*/
  __u32 retrans_out;      /* Retransmitted packets out		*/
  __u32 total_retrans;    /* Total retransmits for entire connection */
  __u32 segs_in;          /* RFC4898 tcpEStatsPerfSegsIn
                           * total number of segments in.
                           */
  __u32 data_segs_in;     /* RFC4898 tcpEStatsPerfDataSegsIn
                           * total number of data segments in.
                           */
  __u32 segs_out;         /* RFC4898 tcpEStatsPerfSegsOut
                           * The total number of segments sent.
                           */
  __u32 data_segs_out;    /* RFC4898 tcpEStatsPerfDataSegsOut
                           * total number of data segments sent.
                           */
  __u32 lost_out;         /* Lost packets			*/
  __u32 sacked_out;       /* SACK'd packets			*/
  __u64 bytes_received;   /* RFC4898 tcpEStatsAppHCThruOctetsReceived
                           * sum(delta(rcv_nxt)), or how many bytes
                           * were acked.
                           */
  __u64 bytes_acked;      /* RFC4898 tcpEStatsAppHCThruOctetsAcked
                           * sum(delta(snd_una)), or how many bytes
                           * were acked.
                           */
  __u32 dsack_dups;       /* RFC4898 tcpEStatsStackDSACKDups
                           * total number of DSACK blocks received
                           */
  __u32 delivered;        /* Total data packets delivered incl. rexmits */
  __u32 delivered_ce;     /* Like the above but only ECE marked packets */
  __u32 icsk_retransmits; /* Number of unrecovered [RTO] timeouts */
};

struct bpf_sock_tuple {
  union {
    struct {
      __be32 saddr;
      __be32 daddr;
      __be16 sport;
      __be16 dport;
    } ipv4;
    struct {
      __be32 saddr[4];
      __be32 daddr[4];
      __be16 sport;
      __be16 dport;
    } ipv6;
  };
};

struct bpf_xdp_sock {
  __u32 queue_id;
};

#define XDP_PACKET_HEADROOM 256

/* User return codes for XDP prog type.
 * A valid XDP program must return one of these defined values. All other
 * return codes are reserved for future use. Unknown return codes will
 * result in packet drops and a warning via bpf_warn_invalid_xdp_action().
 */
enum xdp_action {
  XDP_ABORTED = 0,
  XDP_DROP,
  XDP_PASS,
  XDP_TX,
  XDP_REDIRECT,
};

/* user accessible metadata for XDP packet hook
 * new fields must be added to the end of this structure
 */
struct xdp_md {
  __u32 data;
  __u32 data_end;
  __u32 data_meta;
  /* Below access go through struct xdp_rxq_info */
  __u32 ingress_ifindex; /* rxq->dev->ifindex */
  __u32 rx_queue_index;  /* rxq->queue_index  */

  __u32 egress_ifindex; /* txq->dev->ifindex */
};

/* DEVMAP map-value layout
 *
 * The struct data-layout of map-value is a configuration interface.
 * New members can only be added to the end of this structure.
 */
struct bpf_devmap_val {
  __u32 ifindex; /* device index */
  union {
    int fd;   /* prog fd on map write */
    __u32 id; /* prog id on map read */
  } bpf_prog;
};

/* CPUMAP map-value layout
 *
 * The struct data-layout of map-value is a configuration interface.
 * New members can only be added to the end of this structure.
 */
struct bpf_cpumap_val {
  __u32 qsize; /* queue size to remote target CPU */
  union {
    int fd;   /* prog fd on map write */
    __u32 id; /* prog id on map read */
  } bpf_prog;
};

enum sk_action {
  SK_DROP = 0,
  SK_PASS,
};

/* user accessible metadata for SK_MSG packet hook, new fields must
 * be added to the end of this structure
 */
struct sk_msg_md {
  __bpf_md_ptr(void *, data);
  __bpf_md_ptr(void *, data_end);

  __u32 family;
  __u32 remote_ip4;    /* Stored in network byte order */
  __u32 local_ip4;     /* Stored in network byte order */
  __u32 remote_ip6[4]; /* Stored in network byte order */
  __u32 local_ip6[4];  /* Stored in network byte order */
  __u32 remote_port;   /* Stored in network byte order */
  __u32 local_port;    /* stored in host byte order */
  __u32 size;          /* Total size of sk_msg */

  __bpf_md_ptr(struct bpf_sock *, sk); /* current socket */
};

struct sk_reuseport_md {
  /*
   * Start of directly accessible data. It begins from
   * the tcp/udp header.
   */
  __bpf_md_ptr(void *, data);
  /* End of directly accessible data */
  __bpf_md_ptr(void *, data_end);
  /*
   * Total length of packet (starting from the tcp/udp header).
   * Note that the directly accessible bytes (data_end - data)
   * could be less than this "len".  Those bytes could be
   * indirectly read by a helper "bpf_skb_load_bytes()".
   */
  __u32 len;
  /*
   * Eth protocol in the mac header (network byte order). e.g.
   * ETH_P_IP(0x0800) and ETH_P_IPV6(0x86DD)
   */
  __u32 eth_protocol;
  __u32 ip_protocol; /* IP protocol. e.g. IPPROTO_TCP, IPPROTO_UDP */
  __u32 bind_inany;  /* Is sock bound to an INANY address? */
  __u32 hash;        /* A hash of the packet 4 tuples */
  /* When reuse->migrating_sk is NULL, it is selecting a sk for the
   * new incoming connection request (e.g. selecting a listen sk for
   * the received SYN in the TCP case).  reuse->sk is one of the sk
   * in the reuseport group. The bpf prog can use reuse->sk to learn
   * the local listening ip/port without looking into the skb.
   *
   * When reuse->migrating_sk is not NULL, reuse->sk is closed and
   * reuse->migrating_sk is the socket that needs to be migrated
   * to another listening socket.  migrating_sk could be a fullsock
   * sk that is fully established or a reqsk that is in-the-middle
   * of 3-way handshake.
   */
  __bpf_md_ptr(struct bpf_sock *, sk);
  __bpf_md_ptr(struct bpf_sock *, migrating_sk);
};

#define BPF_TAG_SIZE 8

struct bpf_prog_info {
  __u32 type;
  __u32 id;
  __u8 tag[BPF_TAG_SIZE];
  __u32 jited_prog_len;
  __u32 xlated_prog_len;
  __aligned_u64 jited_prog_insns;
  __aligned_u64 xlated_prog_insns;
  __u64 load_time; /* ns since boottime */
  __u32 created_by_uid;
  __u32 nr_map_ids;
  __aligned_u64 map_ids;
  char name[BPF_OBJ_NAME_LEN];
  __u32 ifindex;
  __u32 gpl_compatible : 1;
  __u32 : 31; /* alignment pad */
  __u64 netns_dev;
  __u64 netns_ino;
  __u32 nr_jited_ksyms;
  __u32 nr_jited_func_lens;
  __aligned_u64 jited_ksyms;
  __aligned_u64 jited_func_lens;
  __u32 btf_id;
  __u32 func_info_rec_size;
  __aligned_u64 func_info;
  __u32 nr_func_info;
  __u32 nr_line_info;
  __aligned_u64 line_info;
  __aligned_u64 jited_line_info;
  __u32 nr_jited_line_info;
  __u32 line_info_rec_size;
  __u32 jited_line_info_rec_size;
  __u32 nr_prog_tags;
  __aligned_u64 prog_tags;
  __u64 run_time_ns;
  __u64 run_cnt;
  __u64 recursion_misses;
  __u32 verified_insns;
  __u32 attach_btf_obj_id;
  __u32 attach_btf_id;
} __attribute__((aligned(8)));

struct bpf_map_info {
  __u32 type;
  __u32 id;
  __u32 key_size;
  __u32 value_size;
  __u32 max_entries;
  __u32 map_flags;
  char name[BPF_OBJ_NAME_LEN];
  __u32 ifindex;
  __u32 btf_vmlinux_value_type_id;
  __u64 netns_dev;
  __u64 netns_ino;
  __u32 btf_id;
  __u32 btf_key_type_id;
  __u32 btf_value_type_id;
  __u32 : 32; /* alignment pad */
  __u64 map_extra;
} __attribute__((aligned(8)));

struct bpf_btf_info {
  __aligned_u64 btf;
  __u32 btf_size;
  __u32 id;
  __aligned_u64 name;
  __u32 name_len;
  __u32 kernel_btf;
} __attribute__((aligned(8)));

struct bpf_link_info {
  __u32 type;
  __u32 id;
  __u32 prog_id;
  union {
    struct {
      __aligned_u64 tp_name; /* in/out: tp_name buffer ptr */
      __u32 tp_name_len;     /* in/out: tp_name buffer len */
    } raw_tracepoint;
    struct {
      __u32 attach_type;
      __u32 target_obj_id; /* prog_id for PROG_EXT, otherwise btf object id */
      __u32 target_btf_id; /* BTF type id inside the object */
    } tracing;
    struct {
      __u64 cgroup_id;
      __u32 attach_type;
    } cgroup;
    struct {
      __aligned_u64 target_name; /* in/out: target_name buffer ptr */
      __u32 target_name_len;     /* in/out: target_name buffer len */
      union {
        struct {
          __u32 map_id;
        } map;
      };
    } iter;
    struct {
      __u32 netns_ino;
      __u32 attach_type;
    } netns;
    struct {
      __u32 ifindex;
    } xdp;
  };
} __attribute__((aligned(8)));

/* User bpf_sock_addr struct to access socket fields and sockaddr struct passed
 * by user and intended to be used by socket (e.g. to bind to, depends on
 * attach type).
 */
struct bpf_sock_addr {
  __u32 user_family;    /* Allows 4-byte read, but no write. */
  __u32 user_ip4;       /* Allows 1,2,4-byte read and 4-byte write.
                         * Stored in network byte order.
                         */
  __u32 user_ip6[4];    /* Allows 1,2,4,8-byte read and 4,8-byte write.
                         * Stored in network byte order.
                         */
  __u32 user_port;      /* Allows 1,2,4-byte read and 4-byte write.
                         * Stored in network byte order
                         */
  __u32 family;         /* Allows 4-byte read, but no write */
  __u32 type;           /* Allows 4-byte read, but no write */
  __u32 protocol;       /* Allows 4-byte read, but no write */
  __u32 msg_src_ip4;    /* Allows 1,2,4-byte read and 4-byte write.
                         * Stored in network byte order.
                         */
  __u32 msg_src_ip6[4]; /* Allows 1,2,4,8-byte read and 4,8-byte write.
                         * Stored in network byte order.
                         */
  __bpf_md_ptr(struct bpf_sock *, sk);
};

/* User bpf_sock_ops struct to access socket values and specify request ops
 * and their replies.
 * Some of this fields are in network (bigendian) byte order and may need
 * to be converted before use (bpf_ntohl() defined in samples/bpf/bpf_endian.h).
 * New fields can only be added at the end of this structure
 */
struct bpf_sock_ops {
  __u32 op;
  union {
    __u32 args[4];      /* Optionally passed to bpf program */
    __u32 reply;        /* Returned by bpf program	    */
    __u32 replylong[4]; /* Optionally returned by bpf prog  */
  };
  __u32 family;
  __u32 remote_ip4;    /* Stored in network byte order */
  __u32 local_ip4;     /* Stored in network byte order */
  __u32 remote_ip6[4]; /* Stored in network byte order */
  __u32 local_ip6[4];  /* Stored in network byte order */
  __u32 remote_port;   /* Stored in network byte order */
  __u32 local_port;    /* stored in host byte order */
  __u32 is_fullsock;   /* Some TCP fields are only valid if
                        * there is a full socket. If not, the
                        * fields read as zero.
                        */
  __u32 snd_cwnd;
  __u32 srtt_us;               /* Averaged RTT << 3 in usecs */
  __u32 bpf_sock_ops_cb_flags; /* flags defined in uapi/linux/tcp.h */
  __u32 state;
  __u32 rtt_min;
  __u32 snd_ssthresh;
  __u32 rcv_nxt;
  __u32 snd_nxt;
  __u32 snd_una;
  __u32 mss_cache;
  __u32 ecn_flags;
  __u32 rate_delivered;
  __u32 rate_interval_us;
  __u32 packets_out;
  __u32 retrans_out;
  __u32 total_retrans;
  __u32 segs_in;
  __u32 data_segs_in;
  __u32 segs_out;
  __u32 data_segs_out;
  __u32 lost_out;
  __u32 sacked_out;
  __u32 sk_txhash;
  __u64 bytes_received;
  __u64 bytes_acked;
  __bpf_md_ptr(struct bpf_sock *, sk);
  /* [skb_data, skb_data_end) covers the whole TCP header.
   *
   * BPF_SOCK_OPS_PARSE_HDR_OPT_CB: The packet received
   * BPF_SOCK_OPS_HDR_OPT_LEN_CB:   Not useful because the
   *                                header has not been written.
   * BPF_SOCK_OPS_WRITE_HDR_OPT_CB: The header and options have
   *				  been written so far.
   * BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:  The SYNACK that concludes
   *					the 3WHS.
   * BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: The ACK that concludes
   *					the 3WHS.
   *
   * bpf_load_hdr_opt() can also be used to read a particular option.
   */
  __bpf_md_ptr(void *, skb_data);
  __bpf_md_ptr(void *, skb_data_end);
  __u32 skb_len;       /* The total length of a packet.
                        * It includes the header, options,
                        * and payload.
                        */
  __u32 skb_tcp_flags; /* tcp_flags of the header.  It provides
                        * an easy way to check for tcp_flags
                        * without parsing skb_data.
                        *
                        * In particular, the skb_tcp_flags
                        * will still be available in
                        * BPF_SOCK_OPS_HDR_OPT_LEN even though
                        * the outgoing header has not
                        * been written yet.
                        */
};

/* Definitions for bpf_sock_ops_cb_flags */
enum {
  BPF_SOCK_OPS_RTO_CB_FLAG = (1 << 0),
  BPF_SOCK_OPS_RETRANS_CB_FLAG = (1 << 1),
  BPF_SOCK_OPS_STATE_CB_FLAG = (1 << 2),
  BPF_SOCK_OPS_RTT_CB_FLAG = (1 << 3),
  /* Call bpf for all received TCP headers.  The bpf prog will be
   * called under sock_ops->op == BPF_SOCK_OPS_PARSE_HDR_OPT_CB
   *
   * Please refer to the comment in BPF_SOCK_OPS_PARSE_HDR_OPT_CB
   * for the header option related helpers that will be useful
   * to the bpf programs.
   *
   * It could be used at the client/active side (i.e. connect() side)
   * when the server told it that the server was in syncookie
   * mode and required the active side to resend the bpf-written
   * options.  The active side can keep writing the bpf-options until
   * it received a valid packet from the server side to confirm
   * the earlier packet (and options) has been received.  The later
   * example patch is using it like this at the active side when the
   * server is in syncookie mode.
   *
   * The bpf prog will usually turn this off in the common cases.
   */
  BPF_SOCK_OPS_PARSE_ALL_HDR_OPT_CB_FLAG = (1 << 4),
  /* Call bpf when kernel has received a header option that
   * the kernel cannot handle.  The bpf prog will be called under
   * sock_ops->op == BPF_SOCK_OPS_PARSE_HDR_OPT_CB.
   *
   * Please refer to the comment in BPF_SOCK_OPS_PARSE_HDR_OPT_CB
   * for the header option related helpers that will be useful
   * to the bpf programs.
   */
  BPF_SOCK_OPS_PARSE_UNKNOWN_HDR_OPT_CB_FLAG = (1 << 5),
  /* Call bpf when the kernel is writing header options for the
   * outgoing packet.  The bpf prog will first be called
   * to reserve space in a skb under
   * sock_ops->op == BPF_SOCK_OPS_HDR_OPT_LEN_CB.  Then
   * the bpf prog will be called to write the header option(s)
   * under sock_ops->op == BPF_SOCK_OPS_WRITE_HDR_OPT_CB.
   *
   * Please refer to the comment in BPF_SOCK_OPS_HDR_OPT_LEN_CB
   * and BPF_SOCK_OPS_WRITE_HDR_OPT_CB for the header option
   * related helpers that will be useful to the bpf programs.
   *
   * The kernel gets its chance to reserve space and write
   * options first before the BPF program does.
   */
  BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG = (1 << 6),
  /* Mask of all currently supported cb flags */
  BPF_SOCK_OPS_ALL_CB_FLAGS = 0x7F,
};

/* List of known BPF sock_ops operators.
 * New entries can only be added at the end
 */
enum {
  BPF_SOCK_OPS_VOID,
  BPF_SOCK_OPS_TIMEOUT_INIT,           /* Should return SYN-RTO value to use or
                                        * -1 if default value should be used
                                        */
  BPF_SOCK_OPS_RWND_INIT,              /* Should return initial advertized
                                        * window (in packets) or -1 if default
                                        * value should be used
                                        */
  BPF_SOCK_OPS_TCP_CONNECT_CB,         /* Calls BPF program right before an
                                        * active connection is initialized
                                        */
  BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB,  /* Calls BPF program when an
                                        * active connection is
                                        * established
                                        */
  BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB, /* Calls BPF program when a
                                        * passive connection is
                                        * established
                                        */
  BPF_SOCK_OPS_NEEDS_ECN,              /* If connection's congestion control
                                        * needs ECN
                                        */
  BPF_SOCK_OPS_BASE_RTT,               /* Get base RTT. The correct value is
                                        * based on the path and may be
                                        * dependent on the congestion control
                                        * algorithm. In general it indicates
                                        * a congestion threshold. RTTs above
                                        * this indicate congestion
                                        */
  BPF_SOCK_OPS_RTO_CB,                 /* Called when an RTO has triggered.
                                        * Arg1: value of icsk_retransmits
                                        * Arg2: value of icsk_rto
                                        * Arg3: whether RTO has expired
                                        */
  BPF_SOCK_OPS_RETRANS_CB,             /* Called when skb is retransmitted.
                                        * Arg1: sequence number of 1st byte
                                        * Arg2: # segments
                                        * Arg3: return value of
                                        *       tcp_transmit_skb (0 => success)
                                        */
  BPF_SOCK_OPS_STATE_CB,               /* Called when TCP changes state.
                                        * Arg1: old_state
                                        * Arg2: new_state
                                        */
  BPF_SOCK_OPS_TCP_LISTEN_CB,          /* Called on listen(2), right after
                                        * socket transition to LISTEN state.
                                        */
  BPF_SOCK_OPS_RTT_CB,                 /* Called on every RTT.
                                        */
  BPF_SOCK_OPS_PARSE_HDR_OPT_CB,       /* Parse the header option.
                                        * It will be called to handle
                                        * the packets received at
                                        * an already established
                                        * connection.
                                        *
                                        * sock_ops->skb_data:
                                        * Referring to the received skb.
                                        * It covers the TCP header only.
                                        *
                                        * bpf_load_hdr_opt() can also
                                        * be used to search for a
                                        * particular option.
                                        */
  BPF_SOCK_OPS_HDR_OPT_LEN_CB,         /* Reserve space for writing the
                                        * header option later in
                                        * BPF_SOCK_OPS_WRITE_HDR_OPT_CB.
                                        * Arg1: bool want_cookie. (in
                                        *       writing SYNACK only)
                                        *
                                        * sock_ops->skb_data:
                                        * Not available because no header has
                                        * been	written yet.
                                        *
                                        * sock_ops->skb_tcp_flags:
                                        * The tcp_flags of the
                                        * outgoing skb. (e.g. SYN, ACK, FIN).
                                        *
                                        * bpf_reserve_hdr_opt() should
                                        * be used to reserve space.
                                        */
  BPF_SOCK_OPS_WRITE_HDR_OPT_CB,       /* Write the header options
                                        * Arg1: bool want_cookie. (in
                                        *       writing SYNACK only)
                                        *
                                        * sock_ops->skb_data:
                                        * Referring to the outgoing skb.
                                        * It covers the TCP header
                                        * that has already been written
                                        * by the kernel and the
                                        * earlier bpf-progs.
                                        *
                                        * sock_ops->skb_tcp_flags:
                                        * The tcp_flags of the outgoing
                                        * skb. (e.g. SYN, ACK, FIN).
                                        *
                                        * bpf_store_hdr_opt() should
                                        * be used to write the
                                        * option.
                                        *
                                        * bpf_load_hdr_opt() can also
                                        * be used to search for a
                                        * particular option that
                                        * has already been written
                                        * by the kernel or the
                                        * earlier bpf-progs.
                                        */
};

/* List of TCP states. There is a build check in net/ipv4/tcp.c to detect
 * changes between the TCP and BPF versions. Ideally this should never happen.
 * If it does, we need to add code to convert them before calling
 * the BPF sock_ops function.
 */
enum {
  BPF_TCP_ESTABLISHED = 1,
  BPF_TCP_SYN_SENT,
  BPF_TCP_SYN_RECV,
  BPF_TCP_FIN_WAIT1,
  BPF_TCP_FIN_WAIT2,
  BPF_TCP_TIME_WAIT,
  BPF_TCP_CLOSE,
  BPF_TCP_CLOSE_WAIT,
  BPF_TCP_LAST_ACK,
  BPF_TCP_LISTEN,
  BPF_TCP_CLOSING, /* Now a valid state */
  BPF_TCP_NEW_SYN_RECV,

  BPF_TCP_MAX_STATES /* Leave at the end! */
};

enum {
  TCP_BPF_IW = 1001,            /* Set TCP initial congestion window */
  TCP_BPF_SNDCWND_CLAMP = 1002, /* Set sndcwnd_clamp */
  TCP_BPF_DELACK_MAX = 1003,    /* Max delay ack in usecs */
  TCP_BPF_RTO_MIN = 1004,       /* Min delay ack in usecs */
  /* Copy the SYN pkt to optval
   *
   * BPF_PROG_TYPE_SOCK_OPS only.  It is similar to the
   * bpf_getsockopt(TCP_SAVED_SYN) but it does not limit
   * to only getting from the saved_syn.  It can either get the
   * syn packet from:
   *
   * 1. the just-received SYN packet (only available when writing the
   *    SYNACK).  It will be useful when it is not necessary to
   *    save the SYN packet for latter use.  It is also the only way
   *    to get the SYN during syncookie mode because the syn
   *    packet cannot be saved during syncookie.
   *
   * OR
   *
   * 2. the earlier saved syn which was done by
   *    bpf_setsockopt(TCP_SAVE_SYN).
   *
   * The bpf_getsockopt(TCP_BPF_SYN*) option will hide where the
   * SYN packet is obtained.
   *
   * If the bpf-prog does not need the IP[46] header,  the
   * bpf-prog can avoid parsing the IP header by using
   * TCP_BPF_SYN.  Otherwise, the bpf-prog can get both
   * IP[46] and TCP header by using TCP_BPF_SYN_IP.
   *
   *      >0: Total number of bytes copied
   * -ENOSPC: Not enough space in optval. Only optlen number of
   *          bytes is copied.
   * -ENOENT: The SYN skb is not available now and the earlier SYN pkt
   *	    is not saved by setsockopt(TCP_SAVE_SYN).
   */
  TCP_BPF_SYN = 1005,     /* Copy the TCP header */
  TCP_BPF_SYN_IP = 1006,  /* Copy the IP[46] and TCP header */
  TCP_BPF_SYN_MAC = 1007, /* Copy the MAC, IP[46], and TCP header */
};

enum {
  BPF_LOAD_HDR_OPT_TCP_SYN = (1ULL << 0),
};

/* args[0] value during BPF_SOCK_OPS_HDR_OPT_LEN_CB and
 * BPF_SOCK_OPS_WRITE_HDR_OPT_CB.
 */
enum {
  BPF_WRITE_HDR_TCP_CURRENT_MSS = 1,   /* Kernel is finding the
                                        * total option spaces
                                        * required for an established
                                        * sk in order to calculate the
                                        * MSS.  No skb is actually
                                        * sent.
                                        */
  BPF_WRITE_HDR_TCP_SYNACK_COOKIE = 2, /* Kernel is in syncookie mode
                                        * when sending a SYN.
                                        */
};

struct bpf_perf_event_value {
  __u64 counter;
  __u64 enabled;
  __u64 running;
};

enum {
  BPF_DEVCG_ACC_MKNOD = (1ULL << 0),
  BPF_DEVCG_ACC_READ = (1ULL << 1),
  BPF_DEVCG_ACC_WRITE = (1ULL << 2),
};

enum {
  BPF_DEVCG_DEV_BLOCK = (1ULL << 0),
  BPF_DEVCG_DEV_CHAR = (1ULL << 1),
};

struct bpf_cgroup_dev_ctx {
  /* access_type encoded as (BPF_DEVCG_ACC_* << 16) | BPF_DEVCG_DEV_* */
  __u32 access_type;
  __u32 major;
  __u32 minor;
};

struct bpf_raw_tracepoint_args {
  __u64 args[0];
};

/* DIRECT:  Skip the FIB rules and go to FIB table associated with device
 * OUTPUT:  Do lookup from egress perspective; default is ingress
 */
enum {
  BPF_FIB_LOOKUP_DIRECT = (1U << 0),
  BPF_FIB_LOOKUP_OUTPUT = (1U << 1),
};

enum {
  BPF_FIB_LKUP_RET_SUCCESS,      /* lookup successful */
  BPF_FIB_LKUP_RET_BLACKHOLE,    /* dest is blackholed; can be dropped */
  BPF_FIB_LKUP_RET_UNREACHABLE,  /* dest is unreachable; can be dropped */
  BPF_FIB_LKUP_RET_PROHIBIT,     /* dest not allowed; can be dropped */
  BPF_FIB_LKUP_RET_NOT_FWDED,    /* packet is not forwarded */
  BPF_FIB_LKUP_RET_FWD_DISABLED, /* fwding is not enabled on ingress */
  BPF_FIB_LKUP_RET_UNSUPP_LWT,   /* fwd requires encapsulation */
  BPF_FIB_LKUP_RET_NO_NEIGH,     /* no neighbor entry for nh */
  BPF_FIB_LKUP_RET_FRAG_NEEDED,  /* fragmentation required to fwd */
};

struct bpf_fib_lookup {
  /* input:  network family for lookup (AF_INET, AF_INET6)
   * output: network family of egress nexthop
   */
  __u8 family;

  /* set if lookup is to consider L4 data - e.g., FIB rules */
  __u8 l4_protocol;
  __be16 sport;
  __be16 dport;

  union { /* used for MTU check */
    /* input to lookup */
    __u16 tot_len; /* L3 length from network hdr (iph->tot_len) */

    /* output: MTU value */
    __u16 mtu_result;
  };
  /* input: L3 device index for lookup
   * output: device index from FIB lookup
   */
  __u32 ifindex;

  union {
    /* inputs to lookup */
    __u8 tos;        /* AF_INET  */
    __be32 flowinfo; /* AF_INET6, flow_label + priority */

    /* output: metric of fib result (IPv4/IPv6 only) */
    __u32 rt_metric;
  };

  union {
    __be32 ipv4_src;
    __u32 ipv6_src[4]; /* in6_addr; network order */
  };

  /* input to bpf_fib_lookup, ipv{4,6}_dst is destination address in
   * network header. output: bpf_fib_lookup sets to gateway address
   * if FIB lookup returns gateway route
   */
  union {
    __be32 ipv4_dst;
    __u32 ipv6_dst[4]; /* in6_addr; network order */
  };

  /* output */
  __be16 h_vlan_proto;
  __be16 h_vlan_TCI;
  __u8 smac[6]; /* ETH_ALEN */
  __u8 dmac[6]; /* ETH_ALEN */
};

struct bpf_redir_neigh {
  /* network family for lookup (AF_INET, AF_INET6) */
  __u32 nh_family;
  /* network address of nexthop; skips fib lookup to find gateway */
  union {
    __be32 ipv4_nh;
    __u32 ipv6_nh[4]; /* in6_addr; network order */
  };
};

/* bpf_check_mtu flags*/
enum bpf_check_mtu_flags {
  BPF_MTU_CHK_SEGS = (1U << 0),
};

enum bpf_check_mtu_ret {
  BPF_MTU_CHK_RET_SUCCESS,     /* check and lookup successful */
  BPF_MTU_CHK_RET_FRAG_NEEDED, /* fragmentation required to fwd */
  BPF_MTU_CHK_RET_SEGS_TOOBIG, /* GSO re-segmentation needed to fwd */
};

enum bpf_task_fd_type {
  BPF_FD_TYPE_RAW_TRACEPOINT, /* tp name */
  BPF_FD_TYPE_TRACEPOINT,     /* tp name */
  BPF_FD_TYPE_KPROBE,         /* (symbol + offset) or addr */
  BPF_FD_TYPE_KRETPROBE,      /* (symbol + offset) or addr */
  BPF_FD_TYPE_UPROBE,         /* filename + offset */
  BPF_FD_TYPE_URETPROBE,      /* filename + offset */
};

enum {
  BPF_FLOW_DISSECTOR_F_PARSE_1ST_FRAG = (1U << 0),
  BPF_FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL = (1U << 1),
  BPF_FLOW_DISSECTOR_F_STOP_AT_ENCAP = (1U << 2),
};

struct bpf_flow_keys {
  __u16 nhoff;
  __u16 thoff;
  __u16 addr_proto; /* ETH_P_* of valid addrs */
  __u8 is_frag;
  __u8 is_first_frag;
  __u8 is_encap;
  __u8 ip_proto;
  __be16 n_proto;
  __be16 sport;
  __be16 dport;
  union {
    struct {
      __be32 ipv4_src;
      __be32 ipv4_dst;
    };
    struct {
      __u32 ipv6_src[4]; /* in6_addr; network order */
      __u32 ipv6_dst[4]; /* in6_addr; network order */
    };
  };
  __u32 flags;
  __be32 flow_label;
};

struct bpf_func_info {
  __u32 insn_off;
  __u32 type_id;
};

#define BPF_LINE_INFO_LINE_NUM(line_col) ((line_col) >> 10)
#define BPF_LINE_INFO_LINE_COL(line_col) ((line_col)&0x3ff)

struct bpf_line_info {
  __u32 insn_off;
  __u32 file_name_off;
  __u32 line_off;
  __u32 line_col;
};

struct bpf_spin_lock {
  __u32 val;
};

struct bpf_timer {
  __u64 : 64;
  __u64 : 64;
} __attribute__((aligned(8)));

struct bpf_dynptr {
  __u64 : 64;
  __u64 : 64;
} __attribute__((aligned(8)));

struct bpf_sysctl {
  __u32 write;    /* Sysctl is being read (= 0) or written (= 1).
                   * Allows 1,2,4-byte read, but no write.
                   */
  __u32 file_pos; /* Sysctl file position to read from, write to.
                   * Allows 1,2,4-byte read an 4-byte write.
                   */
};

struct bpf_sockopt {
  __bpf_md_ptr(struct bpf_sock *, sk);
  __bpf_md_ptr(void *, optval);
  __bpf_md_ptr(void *, optval_end);

  __s32 level;
  __s32 optname;
  __s32 optlen;
  __s32 retval;
};

struct bpf_pidns_info {
  __u32 pid;
  __u32 tgid;
};

/* User accessible data for SK_LOOKUP programs. Add new fields at the end. */
struct bpf_sk_lookup {
  union {
    __bpf_md_ptr(struct bpf_sock *, sk); /* Selected socket */
    __u64 cookie; /* Non-zero if socket was selected in PROG_TEST_RUN */
  };

  __u32 family;          /* Protocol family (AF_INET, AF_INET6) */
  __u32 protocol;        /* IP protocol (IPPROTO_TCP, IPPROTO_UDP) */
  __u32 remote_ip4;      /* Network byte order */
  __u32 remote_ip6[4];   /* Network byte order */
  __be16 remote_port;    /* Network byte order */
  __u16 : 16;            /* Zero padding */
  __u32 local_ip4;       /* Network byte order */
  __u32 local_ip6[4];    /* Network byte order */
  __u32 local_port;      /* Host byte order */
  __u32 ingress_ifindex; /* The arriving interface. Determined by inet_iif. */
};

/*
 * struct btf_ptr is used for typed pointer representation; the
 * type id is used to render the pointer data as the appropriate type
 * via the bpf_snprintf_btf() helper described above.  A flags field -
 * potentially to specify additional details about the BTF pointer
 * (rather than its mode of display) - is included for future use.
 * Display flags - BTF_F_* - are passed to bpf_snprintf_btf separately.
 */
struct btf_ptr {
  void *ptr;
  __u32 type_id;
  __u32 flags; /* BTF ptr flags; unused at present. */
};

/*
 * Flags to control bpf_snprintf_btf() behaviour.
 *     - BTF_F_COMPACT: no formatting around type information
 *     - BTF_F_NONAME: no struct/union member names/types
 *     - BTF_F_PTR_RAW: show raw (unobfuscated) pointer values;
 *       equivalent to %px.
 *     - BTF_F_ZERO: show zero-valued struct/union members; they
 *       are not displayed by default
 */
enum {
  BTF_F_COMPACT = (1ULL << 0),
  BTF_F_NONAME = (1ULL << 1),
  BTF_F_PTR_RAW = (1ULL << 2),
  BTF_F_ZERO = (1ULL << 3),
};

/* bpf_core_relo_kind encodes which aspect of captured field/type/enum value
 * has to be adjusted by relocations. It is emitted by llvm and passed to
 * libbpf and later to the kernel.
 */
enum bpf_core_relo_kind {
  BPF_CORE_FIELD_BYTE_OFFSET = 0, /* field byte offset */
  BPF_CORE_FIELD_BYTE_SIZE = 1,   /* field size in bytes */
  BPF_CORE_FIELD_EXISTS = 2,      /* field existence in target kernel */
  BPF_CORE_FIELD_SIGNED = 3, /* field signedness (0 - unsigned, 1 - signed) */
  BPF_CORE_FIELD_LSHIFT_U64 = 4, /* bitfield-specific left bitshift */
  BPF_CORE_FIELD_RSHIFT_U64 = 5, /* bitfield-specific right bitshift */
  BPF_CORE_TYPE_ID_LOCAL = 6,    /* type ID in local BPF object */
  BPF_CORE_TYPE_ID_TARGET = 7,   /* type ID in target kernel */
  BPF_CORE_TYPE_EXISTS = 8,      /* type existence in target kernel */
  BPF_CORE_TYPE_SIZE = 9,        /* type size in bytes */
  BPF_CORE_ENUMVAL_EXISTS = 10,  /* enum value existence in target kernel */
  BPF_CORE_ENUMVAL_VALUE = 11,   /* enum value integer value */
  BPF_CORE_TYPE_MATCHES = 12,    /* type match in target kernel */
};

/*
 * "struct bpf_core_relo" is used to pass relocation data form LLVM to libbpf
 * and from libbpf to the kernel.
 *
 * CO-RE relocation captures the following data:
 * - insn_off - instruction offset (in bytes) within a BPF program that needs
 *   its insn->imm field to be relocated with actual field info;
 * - type_id - BTF type ID of the "root" (containing) entity of a relocatable
 *   type or field;
 * - access_str_off - offset into corresponding .BTF string section. String
 *   interpretation depends on specific relocation kind:
 *     - for field-based relocations, string encodes an accessed field using
 *       a sequence of field and array indices, separated by colon (:). It's
 *       conceptually very close to LLVM's getelementptr ([0]) instruction's
 *       arguments for identifying offset to a field.
 *     - for type-based relocations, strings is expected to be just "0";
 *     - for enum value-based relocations, string contains an index of enum
 *       value within its enum type;
 * - kind - one of enum bpf_core_relo_kind;
 *
 * Example:
 *   struct sample {
 *       int a;
 *       struct {
 *           int b[10];
 *       };
 *   };
 *
 *   struct sample *s = ...;
 *   int *x = &s->a;     // encoded as "0:0" (a is field #0)
 *   int *y = &s->b[5];  // encoded as "0:1:0:5" (anon struct is field #1,
 *                       // b is field #0 inside anon struct, accessing elem #5)
 *   int *z = &s[10]->b; // encoded as "10:1" (ptr is used as an array)
 *
 * type_id for all relocs in this example will capture BTF type id of
 * `struct sample`.
 *
 * Such relocation is emitted when using __builtin_preserve_access_index()
 * Clang built-in, passing expression that captures field address, e.g.:
 *
 * bpf_probe_read(&dst, sizeof(dst),
 *		  __builtin_preserve_access_index(&src->a.b.c));
 *
 * In this case Clang will emit field relocation recording necessary data to
 * be able to find offset of embedded `a.b.c` field within `src` struct.
 *
 * [0] https://llvm.org/docs/LangRef.html#getelementptr-instruction
 */
struct bpf_core_relo {
  __u32 insn_off;
  __u32 type_id;
  __u32 access_str_off;
  enum bpf_core_relo_kind kind;
};

struct bpf_prog {
  u32 len;       /* Number of filter blocks */
  u32 jited_len; /* Size of jited insns in bytes */
  // vector<struct bpf_insn> insnsi;
  struct bpf_insn * insnsi;
};

#endif /* _UAPI__LINUX_BPF_H__ */
