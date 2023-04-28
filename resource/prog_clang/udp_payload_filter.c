#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

struct bpf_map_def SEC("maps") packet_count = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 256};

// __always_inline int kmp_match(const void *data, __u32 len, const char *target, __u32 target_len, void *data_end) {
//     __u32 i, j;

//     int ne[target_len];

//     __u32 n = target_len;

//     char *s = (char *)data;
//     char *t = (char *)target;

//     /* compute ne array */
//     ne[0] = 0;
//     for (i = 1, j = 0; i < n; ++i) {
//         while (j > 0 && t[i] != t[j])
//             j = ne[j - 1];
//         if (t[i] == t[j])
//             ++j;
//         ne[i] = j;
//     }

//     /* match */
//     for (i = 0, j = 0; i < len; ++i) {
//         if ((void *)(s + i + 1) < data_end) {
//             while (j > 0 && s[i] != t[j])
//                 j = ne[j - 1];
//             if (s[i] == t[j])
//                 ++j;
//             if (j == n) {
//                 return 1; // match
//             }
//         }
//     }
//     return 0; // no match
// }

__always_inline int my_strnstr(char *str, int str_len, char *substr, int substr_len, void *data_end) {
    // KMP算法实现字符串匹配
    // int i, j;

    bpf_printk("strlen: %d substrlen: %d", str_len, substr_len);

    int ne[substr_len];

    ne[0] = 0;

    for (int i = 1, j = 0; i < substr_len; ++i) {
        while (j > 0 && substr[i] != substr[j])
            j = ne[j - 1];
        if (substr[i] == substr[j])
            ++j;
        ne[i] = j;
    }

    // for (int i = 1, j = 0; i < substr_len && i < 10; i++) {
    //     while (j && substr[i] != substr[j]) j = ne[j - 1];
    //     if (substr[i] == substr[j]) j++;
    //     ne[i] = j;
    // }

    // for (int i = 1, j = 0; i <= str_len && i < 1470; i++) {
    //     while (j && str[i] != substr[j + 1]) j = ne[j];
    //     if ((void *)(str + i + 1) < data_end) {
    //         if (str[i] == substr[j + 1]) j++;
    //         if (j == substr_len) {
    //             // match success
    //             // bpf_printk("match success: %d ", i - substr_len);
    //             return str + i - substr_len;
    //             j = ne[j];
    //         }
    //     }
    // }

    return 0;

    // if ((void *)(str + str_len) > data_end) {
    //     return str;
    // }

    // 这里需要注意，不能是无限循环，加上 i < 1500 保证循环有限
    // for (int i = 0; i < 1500 && i < str_len; i++) {
    //     if ((void *)str + i + 1 > data_end) // 每次访存前需要判断
    //         break;
    //     bpf_printk("str: %c", *(char *)(str + i));
    // }

    // for (int i = 0; i <= substr_len; i++) {
    //     bpf_printk("substr: %c", substr[i]);
    // }

    // for (int i = 0; i <= (str_len - substr_len) && i < 1470; i++) {
    //     for (j = 0; j < substr_len && j < 10; j++) {
    //         if ((void *)(str + i + j + 1) < data_end) // 每次访存前需要判断
    //             if (str[i + j] != substr[j]) {
    //                 break;
    //             }
    //     }

    //     if ((i + j) == substr_len) {
    //         return str + i;
    //     }
    // }
}

SEC("udp_payload_filter")
int xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end; //报文数据开始处
    void *data = (void *)(long)ctx->data;         //报文数据结束处

    struct ethhdr *eh = data;          //以太头
    if ((void *)(eh + 1) > data_end) { //这个检测非常重要，否则在下面读取 eh->h_proto 的时候，无法通过bpf verifier的验证，程序就无法加载
        return XDP_DROP;
    }

    if (eh->h_proto != __constant_htons(ETH_P_IP)) //不是IP报文，放过
        return XDP_PASS;

    struct iphdr *iph = data + sizeof(struct ethhdr);
    if ((void *)(iph + 1) > data_end) {
        return XDP_DROP;
    }

    if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
        if ((void *)(udph + 1) > data_end) {
            return XDP_DROP;
        }

        void *payload = (void *)(long)udph + sizeof(struct udphdr);
        void *payload_end = data_end;

        if ((void *)(payload + 1) > payload_end)
            return XDP_DROP;

        int payload_len = payload_end - payload;

        bpf_printk("payload:%x payload_end: %x payload_len: %d", payload, payload_end, payload_len);

        if (payload_len > 0) {
            // 查找目标字符串
            char target_str[] = "example";
            int found = my_strnstr(payload, payload_len, target_str, sizeof(target_str) - 1, data_end);
            bpf_printk("found: %d\n", found);
            // // // 如果找到目标字符串，则将计数器加 1
            if (found == 1) {
                __u32 key = 0;
                __u64 *val;
                val = bpf_map_lookup_elem(&packet_count, &key);
                if (val) {
                    (*val)++;
                }
                return XDP_DROP;
            }
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";