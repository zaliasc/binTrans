#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>

struct bpf_map_def SEC("maps") udp_counts = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 256,
};

char * my_strnstr(char *str, int str_len, char *substr, int substr_len) {
    int i, j;

    for (i = 0; i <= str_len - substr_len; i++) {
        for (j = 0; j < substr_len; j++) {
            if (str[i + j] != substr[j]) {
                break;
            }
        }

        if (j == substr_len) {
            return str + i;
        }
    }

    return NULL;
}

SEC("udp_filter")
int udp_filter_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_DROP;

    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(struct ethhdr);

    if (ip + 1 > data_end)
        return XDP_DROP;

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    struct udphdr *udp = (void*)ip + sizeof(*ip);

    if (udp + 1 > data_end)
        return XDP_DROP;

    void *payload = (void *)(long)udp + sizeof(struct udphdr);
    void *payload_end = data_end;

    if (payload > payload_end)
        return XDP_DROP;

    char *ptr = payload;
    int len = payload_end - payload;

    if (len > 0) {
        // 查找目标字符串
        char *target_str = "example";
        bpf_printk("%s",ptr);
        char *found = my_strnstr(ptr, len, target_str, sizeof(target_str)-1);
        
        // 如果找到目标字符串，则将计数器加 1
        if (found != NULL) {
            __u32 key = 0;
            __u64 *val;
            val = bpf_map_lookup_elem(&udp_counts, &key);
            if (val) {
                (*val)++;
            }
        }
    }

    return XDP_PASS;
}

