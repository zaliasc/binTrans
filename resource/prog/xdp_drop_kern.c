#include <linux/bpf.h>

#define SEC(NAME) __attribute__((section(NAME), used))

SEC("xdp_drop")
int xdp_drop_the_world(struct xdp_md *ctx) {
    // drop everything
	// 意思是无论什么网络数据包，都drop丢弃掉
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";