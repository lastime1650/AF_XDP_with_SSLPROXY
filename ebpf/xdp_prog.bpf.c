// xdp_prog.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP    0x0800

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64); /* NIC 큐 개수에 맞춰 조정 가능 */
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} xsks_map SEC(".maps");// 인터페이스별로 가지는 XDP소켓 파일디스크립터 값

SEC("xdp")
int xdp_packet_handler(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    __u64 pkt_len = (void *)data_end - (void *)data;
    if (pkt_len == 0) return XDP_PASS;  
    struct ethhdr *eth = data;
    
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    if (ip->ihl < 5) return XDP_PASS;
    void *l4_hdr = (void *)ip + (ip->ihl * 4);
    if (l4_hdr > data_end) return XDP_PASS;

    __u16 src_port = 0;
    __u16 dst_port = 0;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4_hdr;
        if ((void *)(tcp + 1) > data_end) return XDP_PASS;
        src_port = tcp->source;
        dst_port = tcp->dest;

        __u16 src_port = bpf_ntohs(tcp->source);
        __u16 dst_port = bpf_ntohs(tcp->dest);
        if (src_port == 22 || dst_port == 22) 
            return XDP_PASS; // 유저 sslproxy에서 별도 처리 (패킷 수집도 유저모드단에서 처리된다.)
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4_hdr;
        if ((void *)(udp + 1) > data_end) return XDP_PASS;
        src_port = udp->source;
        dst_port = udp->dest;
    } else if (ip->protocol == IPPROTO_ICMP) 
        return XDP_PASS;








    int rx_index = ctx->rx_queue_index;

    bpf_printk(" ifindex: %d , rx_index: %d \n", ctx->ingress_ifindex, ctx->rx_queue_index);

    if (bpf_map_lookup_elem(&xsks_map, &rx_index)) {
        return bpf_redirect_map(&xsks_map, rx_index, 0); // 바로 유저모드로 직송
    }
    else
    {
        return XDP_PASS;
    }
}

char LICENSE[] SEC("license") = "GPL";


