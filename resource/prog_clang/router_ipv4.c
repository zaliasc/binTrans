#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <sys/socket.h>

struct trie_value {
    __u8 prefix[4];
    __be64 value;
    int ifindex;
    int metric;
    __be32 gw;
};

/* Key for lpm_trie*/
union key_4 {
    __u32 b32[2];
    __u8 b8[8];
};

struct arp_entry {
    __be64 mac;
    __be32 dst;
};

struct direct_map {
    struct arp_entry arp;
    int ifindex;
    __be64 mac;
};

/* Map for trie implementation*/
struct bpf_map_def SEC("maps") lpm_map = {
    .type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = 8,
    .value_size = sizeof(struct trie_value),
    .max_entries = 50,
    .map_flags = BPF_F_NO_PREALLOC,
};

/* Map for counter*/
struct bpf_map_def SEC("maps") rxcnt = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 256,
};

/* Map for ARP table*/
struct bpf_map_def SEC("maps") arp_table = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__be32),
    .value_size = sizeof(__be64),
    .max_entries = 50,
};

/* Map to keep the exact match entries in the route table*/
struct bpf_map_def SEC("maps") exact_match = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__be32),
    .value_size = sizeof(struct direct_map),
    .max_entries = 50,
};

struct bpf_map_def SEC("maps") tx_port = {
    .type = BPF_MAP_TYPE_DEVMAP,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = 100,
};

/* Function to set source and destination mac of the packet */
static inline void set_src_dst_mac(void *data, void *src, void *dst) {
    unsigned short *source = src;
    unsigned short *dest = dst;
    unsigned short *p = data;

    __builtin_memcpy(p, dest, 6);
    __builtin_memcpy(p + 3, source, 6);
}

/* Parse IPV4 packet to get SRC, DST IP and protocol */
static inline int parse_ipv4(void *data, __u64 nh_off, void *data_end,
                             __be32 *src, __be32 *dest) {
    struct iphdr *iph = data + nh_off;

    if ((void *)(iph + 1) > data_end)
        return 0;
    *src = iph->saddr;
    *dest = iph->daddr;
    return iph->protocol;
}

SEC("router_ipv4")
int xdp_router_ipv4_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    __be64 *dest_mac = NULL, *src_mac = NULL;
    void *data = (void *)(long)ctx->data;
    struct trie_value *prefix_value;
    int rc = XDP_DROP, forward_to;
    struct ethhdr *eth = data;
    union key_4 key4;
    long *value;
    __u16 h_proto;
    __u32 ipproto;
    __u64 nh_off;

    nh_off = sizeof(*eth);
    if (data + nh_off > data_end)
        return rc;

    h_proto = eth->h_proto;

    if (h_proto == __constant_htons(ETH_P_ARP)) {
        return XDP_PASS;
    } else if (h_proto == __constant_htons(ETH_P_IP)) {
        struct direct_map *direct_entry;
        __be32 src_ip = 0, dest_ip = 0;

        ipproto = parse_ipv4(data, nh_off, data_end, &src_ip, &dest_ip);
        direct_entry = bpf_map_lookup_elem(&exact_match, &dest_ip);
        /* Check for exact match, this would give a faster lookup*/
        if (direct_entry && direct_entry->mac && direct_entry->arp.mac) {
            src_mac = &direct_entry->mac;
            dest_mac = &direct_entry->arp.mac;
            forward_to = direct_entry->ifindex;
        } else {
            /* Look up in the trie for lpm*/
            key4.b32[0] = 32;
            key4.b8[4] = dest_ip & 0xff;
            key4.b8[5] = (dest_ip >> 8) & 0xff;
            key4.b8[6] = (dest_ip >> 16) & 0xff;
            key4.b8[7] = (dest_ip >> 24) & 0xff;
            prefix_value = bpf_map_lookup_elem(&lpm_map, &key4);
            if (!prefix_value)
                return XDP_DROP;
            src_mac = &prefix_value->value;
            if (!src_mac)
                return XDP_DROP;
            dest_mac = bpf_map_lookup_elem(&arp_table, &dest_ip);
            if (!dest_mac) {
                if (!prefix_value->gw)
                    return XDP_DROP;
                dest_ip = prefix_value->gw;
                dest_mac = bpf_map_lookup_elem(&arp_table, &dest_ip);
            }
            forward_to = prefix_value->ifindex;
        }
    } else {
        ipproto = 0;
    }
    if (src_mac && dest_mac) {
        set_src_dst_mac(data, src_mac, dest_mac);
        value = bpf_map_lookup_elem(&rxcnt, &ipproto);
        if (value)
            *value += 1;
        return bpf_redirect_map(&tx_port, forward_to, 0);
    }
    return rc;
}

char _license[] SEC("license") = "GPL";