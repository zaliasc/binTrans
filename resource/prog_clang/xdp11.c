#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

// #include <linux/bpf.h>
// #include <bpf/bpf_helpers.h>
// #include <linux/in.h>
// #include <linux/if_ether.h>
// #include <arpa/inet.h>


struct p {
	int a;
	char b;
};

struct vlan_hdr {
	__be16	h_vlan_TCI;
	__be16	h_vlan_encapsulated_proto;
};


struct bpf_map_def SEC("maps") rxcnt1 = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u16),
	.value_size = sizeof(__u16),
	.max_entries = 257,
};

struct bpf_map_def SEC("maps") rxcnt2 = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(struct p),
	.value_size = sizeof(__u32),
	.max_entries = 508,
};

struct bpf_map_def SEC("maps") rxcnt3 = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u16),
	.value_size = sizeof(__u16),
	.max_entries = 1021,
};



static int parse_ipv4(void *data, __u64 nh_off, void *data_end)
{
	struct iphdr *iph = data + nh_off;

	if (iph + 1 > data_end)
		return 0;
	return iph->protocol;
}

static int parse_ipv6(void *data, __u64 nh_off, void *data_end)
{
	struct ipv6hdr *ip6h = data + nh_off;

	if (ip6h + 1 > data_end)
		return 0;
	return ip6h->nexthdr;
}

SEC("xdp11")
int xdp_prog1(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	int rc = XDP_DROP;
	long *value;
	__u16 h_proto;
	__u64 nh_off;
	__u32 ipproto;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return rc;

	h_proto = eth->h_proto;

	if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
		struct vlan_hdr *vhdr;

		vhdr = data + nh_off;
		nh_off += sizeof(struct vlan_hdr);
		if (data + nh_off > data_end)
			return rc;
		h_proto = vhdr->h_vlan_encapsulated_proto;
	}
	if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
		struct vlan_hdr *vhdr;

		vhdr = data + nh_off;
		nh_off += sizeof(struct vlan_hdr);
		if (data + nh_off > data_end)
			return rc;
		h_proto = vhdr->h_vlan_encapsulated_proto;
	}

	if (h_proto == htons(ETH_P_IP))
		ipproto = parse_ipv4(data, nh_off, data_end);
	else if (h_proto == htons(ETH_P_IPV6))
		ipproto = parse_ipv6(data, nh_off, data_end);
	else
		ipproto = 0;

	value = bpf_map_lookup_elem(&rxcnt3, &ipproto);
	if (value)
		*value += 1;

	return rc;
}

char _license[] SEC("license") = "GPL";
