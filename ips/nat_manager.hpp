#ifndef NAT_MANAGER_HPP
#define NAT_MANAGER_HPP

#include "global.hpp"
#include <shared_mutex>
#include <unordered_map>
#include <atomic>
#include <chrono>

// 해시 테이블 충돌 방지 및 락 분산을 위한 샤드 개수
#define NAT_MAP_SHARDS 1024
#define NAT_PORT_START 10001
#define NAT_PORT_END   65535

class NAT_MANAGER
{
public:
    NAT_MANAGER() {
        srand(time(NULL));
        next_alloc_port = NAT_PORT_START + (rand() % (NAT_PORT_END - NAT_PORT_START));
    }

    ~NAT_MANAGER() = default;

    /**
     * @brief NAT 및 라우팅 결정 처리
     * @return 전송할 인터페이스 정보 포인터 (nullptr이면 Drop)
     */
    interface_information_for_XDP* NAT_PROCESSING(
        pcpp::Packet* packet, 
        interface_information& ingress_interface, 
        std::vector<interface_information_for_XDP>& other_interfaces)
    {
        // 1. L3, L4 파싱 (IPv4만 처리)
        pcpp::IPv4Layer* ipLayer = packet->getLayerOfType<pcpp::IPv4Layer>();
        if (!ipLayer) return nullptr; // Non-IP 패킷 Drop (또는 L2 스위칭 로직 필요 시 수정)

        pcpp::TcpLayer* tcpLayer = packet->getLayerOfType<pcpp::TcpLayer>();
        pcpp::UdpLayer* udpLayer = packet->getLayerOfType<pcpp::UdpLayer>();

        if (!tcpLayer && !udpLayer) return nullptr; // TCP/UDP가 아니면 일단 Drop (ICMP 별도 구현 필요)

        // 패킷 헤더 정보 추출 (Network Byte Order 그대로 사용 또는 변환)
        uint32_t src_ip = ipLayer->getIPv4Header()->ipSrc; // Little Endian (pcpp behavior check needed, usually Host Order inside getter but struct is Net Order)
        // pcpp::IPv4Address.toInt() returns Host Byte Order usually. 
        // Raw Header access returns Network Byte Order.
        // 여기서는 pcpp getter를 사용하므로 Host Byte Order로 가정하고 로직 작성하되,
        // 실제 값 비교시 주의 필요. (코드 일관성을 위해 Raw Header 값 사용 권장)
        
        // 성능을 위해 Raw Header 접근
        pcpp::iphdr* raw_ip = ipLayer->getIPv4Header();
        uint32_t src_ip_n = raw_ip->ipSrc; // Network Byte Order
        uint32_t dst_ip_n = raw_ip->ipDst; 
        uint8_t protocol = raw_ip->protocol;
        
        uint16_t src_port_n = 0;
        uint16_t dst_port_n = 0;

        if (tcpLayer) {
            src_port_n = tcpLayer->getTcpHeader()->portSrc;
            dst_port_n = tcpLayer->getTcpHeader()->portDst;
        } else {
            src_port_n = udpLayer->getUdpHeader()->portSrc;
            dst_port_n = udpLayer->getUdpHeader()->portDst;
        }

        // 2. 패킷 방향 판별 및 처리

        // [CASE A] WAN에서 들어온 패킷 -> DNAT 수행 -> 내부망 인터페이스 찾기
        if (ingress_interface.interface.interface_type == interface_type::WAN)
        {
            // DNAT 테이블 조회 및 패킷 수정
            // 성공 시, 원래의 내부 IP(original_ip)를 반환받음
            uint32_t target_internal_ip_n = 0;
            if (process_dnat(packet, ipLayer, tcpLayer, udpLayer, src_ip_n, dst_ip_n, src_port_n, dst_port_n, protocol, &target_internal_ip_n))
            {
                // 라우팅: 대상 내부 IP가 속한 인터페이스 찾기
                // target_internal_ip_n (Network Order)
                for (auto& out_iface : other_interfaces) {
                    // IsIpInSubnet은 Host Order를 기대하는지 Network Order를 기대하는지 확인 필요.
                    // 기존 코드: ipv4 & mask. 보통 저장된 ipv4가 Network Order라면 그대로 비교.
                    if (out_iface.interface_info.IsIpInSubnet(target_internal_ip_n)) {
                        
                        // L2 헤더 수정 (Target Host의 MAC으로)
                        update_ethernet_header(packet, out_iface.interface_info, target_internal_ip_n, false);
                        return &out_iface;
                    }
                }
            }
            return nullptr; // DNAT 실패 혹은 라우팅 경로 없음 -> Drop
        }

        // [CASE B] LAN(내부)에서 들어온 패킷
        else
        {
            // 1. 목적지가 다른 내부망(LAN)인지 확인 (Inter-VLAN Routing)
            for (auto& out_iface : other_interfaces) {
                if (out_iface.interface_info.interface.interface_type == interface_type::WAN) continue;

                if (out_iface.interface_info.IsIpInSubnet(dst_ip_n)) {
                    // 내부 -> 내부 라우팅 (NAT 없음)
                    // L2 헤더 수정 (Destination Host MAC으로)
                    update_ethernet_header(packet, out_iface.interface_info, dst_ip_n, false);
                    return &out_iface;
                }
            }

            // 2. 목적지가 외부(Internet)임 -> WAN 인터페이스 찾아서 SNAT 수행
            interface_information_for_XDP* wan_iface = nullptr;
            for (auto& out_iface : other_interfaces) {
                if (out_iface.interface_info.interface.interface_type == interface_type::WAN) {
                    wan_iface = &out_iface;
                    break;
                }
            }

            if (wan_iface) {
                // SNAT 수행 (Source IP를 WAN IP로 변경)
                process_snat(packet, ipLayer, tcpLayer, udpLayer, 
                             src_ip_n, dst_ip_n, src_port_n, dst_port_n, protocol, 
                             wan_iface->interface_info.interface.ipv4); // ipv4 assumes Network Order

                // L2 헤더 수정 (Gateway MAC으로 - ISP 라우터)
                // WAN으로 나갈 때는 Gateway IP로 MAC을 찾아야 함
                update_ethernet_header(packet, wan_iface->interface_info, wan_iface->interface_info.interface.gw_ipv4, true);
                
                return wan_iface;
            }
        }

        return nullptr; // 갈 곳을 못 찾음 -> Drop
    }

private:
    struct FlowKey {
        uint32_t src_ip; uint32_t dst_ip;
        uint16_t src_port; uint16_t dst_port;
        uint8_t protocol;
        bool operator==(const FlowKey& o) const {
            return src_ip==o.src_ip && dst_ip==o.dst_ip && src_port==o.src_port && dst_port==o.dst_port && protocol==o.protocol;
        }
    };
    struct FlowKeyHash {
        std::size_t operator()(const FlowKey& k) const {
            return k.src_ip ^ k.dst_ip ^ (k.src_port << 16 | k.dst_port) ^ k.protocol;
        }
    };
    struct NatEntry {
        uint32_t original_ip; uint16_t original_port;
        uint32_t translated_ip; uint16_t translated_port;
        uint64_t last_seen;
    };

    std::unordered_map<FlowKey, NatEntry, FlowKeyHash> snat_table[NAT_MAP_SHARDS];
    std::shared_mutex snat_locks[NAT_MAP_SHARDS];
    std::unordered_map<FlowKey, NatEntry, FlowKeyHash> dnat_table[NAT_MAP_SHARDS];
    std::shared_mutex dnat_locks[NAT_MAP_SHARDS];
    std::atomic<uint16_t> next_alloc_port;

    inline size_t get_shard(const FlowKey& k) { return FlowKeyHash{}(k) % NAT_MAP_SHARDS; }
    
    // 포트 할당 (Big Endian 반환)
    inline uint16_t allocate_port() {
        uint16_t p = next_alloc_port.fetch_add(1, std::memory_order_relaxed);
        if(p > NAT_PORT_END) {
            next_alloc_port.store(NAT_PORT_START, std::memory_order_relaxed);
            p = NAT_PORT_START;
        }
        return htons(p);
    }

    // --- SNAT (LAN -> WAN) ---
    void process_snat(pcpp::Packet* pkt, pcpp::IPv4Layer* ip, pcpp::TcpLayer* tcp, pcpp::UdpLayer* udp,
                      uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport, uint8_t proto, uint32_t wan_ip)
    {
        FlowKey key = {sip, dip, sport, dport, proto};
        size_t idx = get_shard(key);
        NatEntry entry;
        bool exists = false;

        {
            std::shared_lock<std::shared_mutex> lock(snat_locks[idx]);
            auto it = snat_table[idx].find(key);
            if (it != snat_table[idx].end()) { entry = it->second; exists = true; }
        }

        if (!exists) {
            std::unique_lock<std::shared_mutex> lock(snat_locks[idx]);
            // Double-check
            if (snat_table[idx].find(key) != snat_table[idx].end()) {
                entry = snat_table[idx][key];
            } else {
                entry = {sip, sport, wan_ip, allocate_port(), 0};
                snat_table[idx][key] = entry;

                // Register Reverse (DNAT)
                // 돌아오는 패킷: Src=DstIP, Dst=WanIP, Sport=DstPort, Dport=AllocPort
                FlowKey rkey = {dip, wan_ip, dport, entry.translated_port, proto};
                size_t ridx = get_shard(rkey);
                {
                    std::unique_lock<std::shared_mutex> rlock(dnat_locks[ridx]);
                    dnat_table[ridx][rkey] = entry;
                }
            }
        }

        // 패킷 수정
        ip->getIPv4Header()->ipSrc = entry.translated_ip;
        if (tcp) tcp->getTcpHeader()->portSrc = entry.translated_port;
        else udp->getUdpHeader()->portSrc = entry.translated_port;
        
        recalculate_checksums(ip, tcp, udp);
    }

    // --- DNAT (WAN -> LAN) ---
    // Returns true if found and modified, outputs original_internal_ip
    bool process_dnat(pcpp::Packet* pkt, pcpp::IPv4Layer* ip, pcpp::TcpLayer* tcp, pcpp::UdpLayer* udp,
                      uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport, uint8_t proto, uint32_t* out_internal_ip)
    {
        FlowKey key = {sip, dip, sport, dport, proto};
        size_t idx = get_shard(key);
        NatEntry entry;
        bool found = false;

        {
            std::shared_lock<std::shared_mutex> lock(dnat_locks[idx]);
            auto it = dnat_table[idx].find(key);
            if (it != dnat_table[idx].end()) {
                entry = it->second;
                found = true;
            }
        }

        if (!found) return false;

        // 패킷 수정 (Destination을 내부망 호스트로 복구)
        ip->getIPv4Header()->ipDst = entry.original_ip;
        if (tcp) tcp->getTcpHeader()->portDst = entry.original_port;
        else udp->getUdpHeader()->portDst = entry.original_port;

        *out_internal_ip = entry.original_ip;
        recalculate_checksums(ip, tcp, udp);
        return true;
    }

    // --- L2 Header Rewrite ---
    void update_ethernet_header(pcpp::Packet* packet, interface_information& tx_iface, uint32_t target_ip_n, bool is_gateway)
    {
        pcpp::EthLayer* eth = packet->getLayerOfType<pcpp::EthLayer>();
        if (!eth) return;

        // 1. Source MAC: 나가는 인터페이스의 MAC
        eth->setSourceMac(pcpp::MacAddress(tx_iface.interface.mac_addr));

        // 2. Dest MAC: Target IP (또는 Gateway)에 해당하는 MAC 찾기
        // ARP 테이블(hosts)에서 검색
        bool mac_found = false;
        
        // WAN으로 나가는 경우 등 Gateway로 보내야 할 때
        if (is_gateway) {
             eth->setDestMac(pcpp::MacAddress(tx_iface.interface.gw_mac_addr));
             return;
        }

        // 내부망 호스트로 보내는 경우
        for (const auto& host : tx_iface.hosts) {
            if (host.host_ip == target_ip_n) {
                eth->setDestMac(pcpp::MacAddress(host.host_mac));
                mac_found = true;
                break;
            }
        }

        if (!mac_found) {
            // ARP Miss 처리: 실제로는 여기서 패킷을 큐에 넣고 ARP Request를 보내야 함.
            // 현재 구조상으로는 Broadcast하거나 Drop해야 함.
            // 임시로 FF:FF:FF:FF:FF:FF (Broadcast) 또는 00:00... 설정
             eth->setDestMac(pcpp::MacAddress("ff:ff:ff:ff:ff:ff"));
        }
    }

    void recalculate_checksums(pcpp::IPv4Layer* ip, pcpp::TcpLayer* tcp, pcpp::UdpLayer* udp) {
        ip->computeCalculateFields();
        if(tcp) tcp->computeCalculateFields();
        else if(udp) udp->computeCalculateFields();
    }
};

#endif