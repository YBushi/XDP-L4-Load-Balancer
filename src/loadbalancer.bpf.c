#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <stddef.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <bpf/bpf_endian.h>
#include <linux/ip.h>


/*
 *struct xdp_md {
 *  __u32 data;
 *  __u32 data_end;
 *  __u32 data_meta;
 *  __u32 ingress_ifindex;   / interface the packet arrived on /
 *  __u32 rx_queue_index;    / RX queue on that interface /
 *  __u32 egress_ifindex;    / only valid for devmap programs /
*/
/* this function fires for every received packet*/

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

struct flow {
    __u32 src_ip;
    __u32 dest_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 pad[3];
};

static __always_inline int parse_ethhdr(struct hdr_cursor *curr, void *data_end, struct ethhdr **ethhdr) {
    struct ethhdr *eth = curr->pos;
	int hdrsize = sizeof(*eth);

    /* check whether we are still in bounds */
    if (curr->pos + hdrsize > data_end) {
        return -1;
    }

    curr->pos += hdrsize;
    *ethhdr = eth;

    /* return the protocol */
    return bpf_ntohs(eth->h_proto);
}

static __always_inline int parse_ip4hdr(struct hdr_cursor *curr, void *data_end, 
                                        struct iphdr **iphdr, struct flow *packet) {
    struct iphdr *iph = curr->pos; 
    if ((void *)(iph + 1) > data_end) {
        return -1;
    }

    int hdrsize = iph->ihl * 4;
    if (hdrsize < sizeof(*iph)) {
        return -1;
    }
    if (curr->pos + hdrsize > data_end) {
        return -1;
    }
    
    curr->pos += hdrsize;
    *iphdr = iph;
    packet->src_ip = iph->saddr;
    packet->dest_ip = iph->daddr;
    return iph->protocol;
}

SEC("xdp")
int recv_packet(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
    struct ethhdr *eth;
    struct iphdr *iph;

    struct hdr_cursor curr;
    curr.pos = data;

    int traffic_type;
    traffic_type = parse_ethhdr(&curr, data_end, &eth);
    
    /* if it's not a IPv4 packet, let kernel handle it unchagned */
    if (traffic_type != ETH_P_IP) {
        return XDP_PASS;
    }

    struct flow packet = {};
    int transport_protocol;
    transport_protocol = parse_ip4hdr(&curr, data_end, &iph, &packet);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";