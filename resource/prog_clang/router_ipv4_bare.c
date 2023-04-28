#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <sys/socket.h>

// 最简单的一个转发表项
struct rt_item {
    int ifindex;               // 转发出去的接口
    char eth_source[ETH_ALEN]; // 封装帧的源MAC地址。
    char eth_dest[ETH_ALEN];   // 封装帧的目标MAC地址。
};

// 路由转发表
struct bpf_map_def SEC("maps") router_map = {
    .type = BPF_MAP_TYPE_LRU_HASH, // 采用LRU机制，自动老化表项
    .key_size = sizeof(int),
    .value_size = sizeof(struct rt_item),
    .max_entries = 1000000,
};

// 递减TTL
static __always_inline int ip_decrease_ttl(struct iphdr *iph) {
    __u32 check = (__u32)iph->check;

    check += (__u32)__constant_htons(0x0100);
    iph->check = (__sum16)(check + (check >= 0xFFFF));
    return --iph->ttl;
}

// 字节码的C程序本身
SEC("xdp_rtcache")
int xdp_rtcache_prog(struct xdp_md *ctx) {
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

    unsigned int daddr = iph->daddr;

    struct bpf_fib_lookup ifib;

    char fast_info[] = "Fast path to [%d]\n";

    // 精确查找转发表
    struct rt_item *pitem = bpf_map_lookup_elem(&router_map, &daddr);

    if (pitem) {
        ip_decrease_ttl(iph);
#pragma unroll
        for (int i = 0; i < ETH_ALEN; i++) {
            eh->h_dest[i] = pitem->eth_dest[i];
            eh->h_source[i] = pitem->eth_source[i];
        }

        bpf_trace_printk(fast_info, sizeof(fast_info), pitem->ifindex);
        return bpf_redirect(pitem->ifindex, 0);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";