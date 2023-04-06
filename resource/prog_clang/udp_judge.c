#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if (eth + 1 > data_end) {
        return XDP_DROP;
    }

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if (ip + 1 > data_end) {
        return XDP_DROP;
    }

    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
        if (udp + 1 > data_end) {
            return XDP_DROP;
        }

        void *payload = (void *)(long)udp + sizeof(struct udphdr);
        void *payload_end = data_end;

        if (payload + 1 > payload_end)
            return XDP_DROP;

        char *ptr = payload;
        int len = payload_end - payload;

        if (len > 0) {
            // bpf_printk("UDP Packet len2%d\n", len);
            // const char * msg = "UDP payload: %s"; 
            // bpf_trace_printk(msg, len, ptr);
            bpf_printk("UDP payload: %d, %s", len, ptr);
        }

        // 如果是 UDP 数据包，可以在这里进行相应处理
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
