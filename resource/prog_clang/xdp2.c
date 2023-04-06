#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>

SEC("udp_payload")
int udp_payload_prog(struct xdp_md *ctx)
{
    int nh_off = 0;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    struct ethhdr *eth = data;
    nh_off = sizeof(struct ethhdr);

    if (data + nh_off > data_end)
        return XDP_DROP;

    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + nh_off;
    nh_off += sizeof(struct iphdr);

    if (data + nh_off > data_end)
        return XDP_DROP;

    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = data + nh_off;
        nh_off += sizeof(struct udphdr);

        if (data + nh_off > data_end)
            return XDP_DROP;

        void *payload = (void *)(long)udp + sizeof(struct udphdr);
        void *payload_end = data_end;

        if (payload + 1 > payload_end)
            return XDP_DROP;

        char *ptr = payload;
        int len = payload_end - payload;

        if (len > 0) {
            bpf_printk("UDP payload size: %d, content: %s", len, ptr);
        }
    }

    return XDP_PASS;
}
