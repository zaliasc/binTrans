#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#define SEC(NAME) __attribute__((section(NAME), used))

SEC("dropper_main")
int dropper(struct xdp_md *ctx) {
  int nh_off = 0;

  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct ethhdr *eth = data;
  nh_off = sizeof(struct ethhdr);

  struct iphdr *ip = data + nh_off;
  nh_off += sizeof(struct iphdr);
  
  if (data + nh_off > data_end) {
    return XDP_DROP;
  }

  if (ip->protocol == IPPROTO_UDP) {
    return XDP_DROP;
  }
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";