#define LOCATE_FUNC __attribute__((__section__(".mysection")))

typedef unsigned int __u32;

struct xdp_md {
    __u32 data;
    __u32 data_end;
    __u32 data_meta;
    /* Below access go through struct xdp_rxq_info */
    __u32 ingress_ifindex; /* rxq->dev->ifindex */
    __u32 rx_queue_index;  /* rxq->queue_index  */
};

// #define LED_MATRIX_0_BASE	(0xf0000024)
// #define LED_MATRIX_0_SIZE	(0xdac)
// #define LED_MATRIX_0_WIDTH	(0x23)
// #define LED_MATRIX_0_HEIGHT	(0x19)

void prepare_xdp_md(struct xdp_md *ctx) {
    ctx->data = 0xffffff00;
    ctx->data_end = 0xffffffff;
}

void LOCATE_FUNC xdp_prog(struct xdp_md *ctx) {
}

void main() {
    struct xdp_md ctx;
    prepare_xdp_md(&ctx);
    xdp_prog(&ctx);
}