typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
#define packet_addr 0x12340000;
#define packet_len 64

#define ETH_ALEN 6  //定义了以太网接口的MAC地址的长度为6个字节
#define ETH_HLAN 14  //定义了以太网帧的头长度为14个字节
#define ETH_ZLEN 60  //定义了以太网帧的最小长度为 ETH_ZLEN + ETH_FCS_LEN = 64个字节
#define ETH_DATA_LEN 1500  //定义了以太网帧的最大负载为1500个字节
#define ETH_FRAME_LEN 1514  //定义了以太网正的最大长度为ETH_DATA_LEN + ETH_FCS_LEN = 1518个字节
#define ETH_FCS_LEN 4   //定义了以太网帧的CRC值占4个字节
 
 
struct ethhdr
{
     unsigned  char  h_dest[ETH_ALEN];  //目的MAC地址
     unsigned  char  h_source[ETH_ALEN];  //源MAC地址
     __u16 h_proto ;  //网络层所使用的协议类型
}__attribute__((packed));   //用于告诉编译器不要对这个结构体中的缝隙部分进行填充操作；


struct iphdr {
    __u8   ihl:4,
           version:4;
    __u8   tos;
    __u16  tot_len;
    __u16  id;
    __u16  frag_off;
    __u8   ttl;
    __u8   protocol;
    __u16  check;
    __u32  saddr;
    __u32  daddr;
}__attribute__((packed));

struct udphdr {
    __u16   source;
    __u16   dest;
    __u16   len;
    __u16   check;
};

struct xdp_md {
	__u32 data;
	__u32 data_end;
	__u32 data_meta;
	/* Below access go through struct xdp_rxq_info */
	__u32 ingress_ifindex; /* rxq->dev->ifindex */
	__u32 rx_queue_index;  /* rxq->queue_index  */
};


void mem_udp_init();
void prepare_xdp_md(struct xdp_md * ctx);
int xdp_prog(struct xdp_md * ctx);

int main() {
    mem_udp_init();
    struct xdp_md ctx;
    prepare_xdp_md(&ctx);
    int r = xdp_prog(&ctx);
    return 0;
}

void mem_udp_init() {
    // char * start = packet_addr;
    struct ethhdr * ehdr = (struct ethhdr *) packet_addr;
    ehdr->h_proto = 0x0800;
    struct iphdr * ihdr = (struct iphdr *) (ehdr + sizeof(struct ethhdr));
    // ihdr->protocol = 0x11; // UDP
    ihdr->protocol = 0x01; // ICMP

}

void prepare_xdp_md(struct xdp_md * ctx) {
    ctx->data = packet_addr;
    ctx->data_end = packet_addr + packet_len;
}


int xdp_prog(struct xdp_md * ctx){
    // 需要使用a0、a1保存 XDP_MD 地址
    // ctx->data = 1;
    __asm__ __volatile__(
        "lw a0, %0 #append_tag"
        :"=m" (ctx) // %0
    );
    // return 0;
}