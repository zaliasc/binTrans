/* SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2017 Jesper Dangaard Brouer, Red Hat Inc.
 *
 *  Example howto extract XDP RX-queue info
 */
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/in.h>
#include <uapi/linux/ip.h>
#include "bpf_helpers.h"

#define SEC(NAME) __attribute__((section(NAME), used))
 
SEC("xdp_filter")
int filter(struct xdp_md *ctx) {
    int ipsize = 0;
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr *ip;
 
    ipsize = sizeof(*eth);
    ip = data + ipsize;
 
    ipsize += sizeof(struct iphdr);
    if (data + ipsize > data_end) {
        return XDP_DROP;
    }
 
    if (ip->protocol == IPPROTO_TCP) {
        return XDP_DROP;
    }
 
    return XDP_PASS;
}


char _license[] SEC("license") = "GPL";