#ifndef GLOBAL_CPP
#define GLOBAL_CPP

#include "../util/util.hpp"

extern "C" {
    #include "../ebpf/xdp_prog.bpf.skel.h"
    #include <bpf/libbpf.h>
    #include <xdp/xsk.h>
    #include <bpf/bpf.h>
}

// System Headers
#include <thread>
#include <atomic>
#include <vector>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <memory>
#include <iostream>
#include <functional>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>

#include <pcapplusplus/RawPacket.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/UdpLayer.h>

#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>


// --- Helper: 5-Tuple Hash Calculation ---
struct ParsedLayer{
    struct ethhdr* eth = nullptr;
    struct iphdr* ip = nullptr;
    struct tcphdr* tcp = nullptr;
    struct udphdr* udp = nullptr;
};
// --- 1. 패킷 파싱 전용 함수 ---
static inline bool parse_packet(const uint8_t* data, uint32_t len, ParsedLayer& output_layer) {
    if (len < sizeof(struct ethhdr) + sizeof(struct iphdr)) return false;

    struct ethhdr* eth = (struct ethhdr*)data;
    if (ntohs(eth->h_proto) != ETH_P_IP) 
        return false; // IPv4만 처리

    output_layer.eth = eth;

    struct iphdr* ip = (struct iphdr*)(data + sizeof(struct ethhdr));
    output_layer.ip = ip;

    uint32_t ip_header_len = ip->ihl * 4;
    uint8_t* l4_ptr = (uint8_t*)ip + ip_header_len;

    if (ip->protocol == IPPROTO_TCP && len >= sizeof(struct ethhdr) + ip_header_len + sizeof(struct tcphdr)) {
        output_layer.tcp = (struct tcphdr*)l4_ptr;
    } else if (ip->protocol == IPPROTO_UDP && len >= sizeof(struct ethhdr) + ip_header_len + sizeof(struct udphdr)) {
        output_layer.udp = (struct udphdr*)l4_ptr;
    }

    return true;
}

// --- 2. 파싱 결과 기반 5-tuple 해시 계산 ---
static inline uint32_t calculate_5tuple_hash_from_parsed(const ParsedLayer& layer) {
    if (!layer.ip) return 0;

    uint32_t src = layer.ip->saddr;
    uint32_t dst = layer.ip->daddr;
    uint32_t src_port = 0;
    uint32_t dst_port = 0;
    uint32_t proto = layer.ip->protocol;

    if (proto == IPPROTO_TCP && layer.tcp) {
        src_port = layer.tcp->source;
        dst_port = layer.tcp->dest;
    } else if (proto == IPPROTO_UDP && layer.udp) {
        src_port = layer.udp->source;
        dst_port = layer.udp->dest;
    }

    uint32_t hash = proto;
    if (src < dst || (src == dst && src_port < dst_port)) {
        hash ^= src ^ dst ^ src_port ^ dst_port;
    } else {
        hash ^= dst ^ src ^ dst_port ^ src_port;
    }

    return hash;
}

struct xsk_umem_info {
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    struct xsk_umem *umem;
    void *buffer;
};

struct xsk_socket_info {
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    struct xsk_socket *xsk;
    struct xsk_umem_info *umem;
};

// 인터페이스 정보와 TX 정보

class XskSocket;
struct interface_information_for_XDP {
    interface_information interface_info;
    std::vector<XskSocket*>Tx_sockets;
};

#endif