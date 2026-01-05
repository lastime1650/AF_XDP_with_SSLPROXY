#ifndef INTERFACEM_HPP
#define INTERFACEM_HPP
#define SSL_MIRROR_DUMMY_INTERFACE_NAME "SslMirrorDummy"

#include "json.hpp"
using namespace nlohmann;

#include "Queue/queue.hpp"

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <thread>
#include <map>
#include <set>
#include <string>
#include <cstring>
#include <memory>
#include <optional>
#include <algorithm>
#include <csignal>

// C Standard Library
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <signal.h>
#include <unistd.h>

// System / Network Headers
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <net/if_arp.h>
#include <netpacket/packet.h>
#include <linux/if_link.h>

/*
{
    "interfaces": [
    
        {
            "name": "", // 인터페이스 명
            "index": 0, // 인터페이스 식별자
            "ip"   : "", // 인터페이스 ip
            "netmask": 0, //정수형 서브넷마스크
        }
    
    ]
}
*/

struct InterfaceSetting{
    std::optional<std::string> name;
    std::optional<unsigned long> ifndex;
    std::optional<std::string> ip;
    std::optional<unsigned long> netmask;
    std::optional<bool> is_dhcp_alloc; // ip 자동할당 받았는가
    std::optional<bool> is_wan;
};

// 모르는 값이면 null 설정.
json DEFATUL_SETTINGS = {
    {"interfaces", json::array({
        {
            { "name", nullptr },     // name을 모르는경우 null
            { "index", 2 },     // 인덱스는 적어도 타게팅 되어야한다 (대부분 1은 loopback임)
            { "ip", nullptr },       // 설정할 {ip} 값. 단, null인경우 dhcp 가 true여야한다. 
            {"netmask", nullptr},   // 설정할 {netmask} 값. 단, null인경우 dhcp 가 true여야한다. 
            {"is_dhcp_alloc", true},
            {"is_wan", nullptr} // waw인지 모르는 경우
        },
        {
            { "name", nullptr },     // name을 모르는경우
            { "index", 3 },     // 인덱스는 적어도 타게팅 되어야한다 (대부분 1은 loopback임)
            { "ip", "172.30.1.1" },       // 설정할 {ip} 값. 단, null인경우 dhcp 가 true여야한다. 
            {"netmask", 24 },   // 설정할 {netmask} 값. 단, null인경우 dhcp 가 true여야한다. 
            {"is_dhcp_alloc", false},
            {"is_wan", nullptr} // waw인지 모르는 경우
        }
    })}
};


enum interface_type { UNKNOWN, WAN, LAN, lo };
struct interfaceinfo
{
    bool is_enable;
    int  ifindex;
    unsigned int ipv4;
    unsigned int subnetmask;
    unsigned char mac_addr[6];
    enum interface_type interface_type;

    unsigned int gw_ipv4;
    unsigned char gw_mac_addr[6];

    std::string interface_name;

};


// Helper Structs

struct host_information{
    unsigned int host_ip;           // big endian
    unsigned char host_mac[6];           // big endian

    struct
    {
        std::string host_ip;        // string (little endian)
        std::string host_mac;         // string (little endian)
        
    }to_string;

    unsigned int gw_ip; // system interface ip
    unsigned char gw_mac[6];
};

struct interface_information {
    interfaceinfo interface;
    std::vector<host_information> hosts;

    bool IsIpInSubnet(unsigned int ipv4) // 빅엔디언
    {
        return (ipv4 & interface.subnetmask) == (interface.ipv4 & interface.subnetmask);
    }
};
struct GW_INFO {
    std::string interface;
    unsigned int gw_ip;
    unsigned char gw_mac[6];
};

class InterfaceManager{


public:
    InterfaceManager()
    {
        InterfaceInfos = __load_interfaces();
    }

    std::map<int, interface_information> LOAD_INTERFACES( bool with_update_field = true )
    {

        auto TMPInterfaceInfos = __load_interfaces();

        if( with_update_field )
            InterfaceInfos = TMPInterfaceInfos;
        
        return TMPInterfaceInfos;
    }

    std::map<int, interface_information> GET_INTERFACES()
    {
        return InterfaceInfos;
    }

    std::vector<interfaceinfo> GET_INTERFACE_INFOS()
    {
        std::vector<interfaceinfo> output;
        for( auto& [ifindex, info] : GET_INTERFACES() )
            output.push_back( info.interface );

        return output;
    }


    bool Update_Interface_Info(){return true;}
    bool Update_Gateway_Info(){return true;}

private:
    std::map<int, interface_information> InterfaceInfos;

    bool is_running_worker_thread = false;
    std::thread loop_update_worker_thread;
    
    void loop_update_worker()
    {
        /*
            - 업데이트 원칙

            1. 인터페이스 맥주소는 변경하지 않는다.
            2. ip+subnetmask 및 gateway 변경가능 ( 이는 외부자가 변경시도할 때만 업데이트. )
            3. 지속 업데이트 MAC주소는 호스트에 따라 다르며, 환경에 따라 변수적이므로 항상 업데이트 진행 ( here thread )
        */
        while(is_running_worker_thread)
        {

            std::this_thread::sleep_for(std::chrono::seconds(3));


            // MAC 주소 지속 업데이트


        }
    }

    std::vector<GW_INFO> ___getGateways() {
        std::vector<GW_INFO> gateways;
        std::ifstream routeFile("/proc/net/route");
        std::string line;
        if(!routeFile.is_open()) return gateways;
        std::getline(routeFile, line); // Skip header

        while (std::getline(routeFile, line)) {
            std::stringstream ss(line);
            std::string iface, dest, gateway;
            ss >> iface >> dest >> gateway;

            if (dest == "00000000") { // Default Gateway
                GW_INFO gw_info;
                gw_info.interface = iface;
                unsigned int addr;
                std::stringstream sshex; sshex << std::hex << gateway; sshex >> addr;
                struct in_addr in; in.s_addr = addr;
                gw_info.gw_ip = in.s_addr;

                // Resolve MAC using IOCTL
                int fd = socket(AF_INET, SOCK_DGRAM, 0);
                if (fd >= 0) {
                    struct arpreq req;
                    memset(&req, 0, sizeof(req));
                    struct sockaddr_in *sin = (struct sockaddr_in *)&req.arp_pa;
                    sin->sin_family = AF_INET;
                    sin->sin_addr = in;
                    strncpy(req.arp_dev, iface.c_str(), IFNAMSIZ-1);
                    if (ioctl(fd, SIOCGARP, &req) != -1) {
                        memcpy(gw_info.gw_mac, req.arp_ha.sa_data, 6);
                    }
                    close(fd);
                }
                gateways.push_back(gw_info);
            }
        }
        return gateways;
    }

    // Helper: Load Interface Details (IP, MAC, Mask)
    std::map<int, interface_information> __load_interfaces() {
        std::map<int, interface_information> output;
        auto gateways = ___getGateways();
        struct ifaddrs *ifaddr, *ifa;

        if (getifaddrs(&ifaddr) == -1) return output;

        for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
            if (!ifa->ifa_addr || !ifa->ifa_name) continue;
            
            int ifindex = (int)if_nametoindex(ifa->ifa_name);
            if (ifindex <= 0) continue;

            interface_information &target_info = output[ifindex];
            target_info.interface.ifindex = ifindex;
            target_info.interface.is_enable = (ifa->ifa_flags & IFF_UP);
            target_info.interface.interface_name = ifa->ifa_name;
            
            std::string ifname(ifa->ifa_name);
            if (ifname == "lo") target_info.interface.interface_type = lo;
            else {
                // Determine WAN/LAN based on Gateway presence
                target_info.interface.interface_type =LAN;
                for(auto& gw : gateways) {
                    if(gw.interface == ifname) {
                        target_info.interface.interface_type = WAN;
                        break;
                    }
                }
            }

            // Fill IP/Mask
            if (ifa->ifa_addr->sa_family == AF_INET) {
                target_info.interface.ipv4 = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr;
                target_info.interface.subnetmask = ((struct sockaddr_in *)ifa->ifa_netmask)->sin_addr.s_addr;

            } 
            // Fill MAC
            else if (ifa->ifa_addr->sa_family == AF_PACKET) {
                struct sockaddr_ll *s = (struct sockaddr_ll *)ifa->ifa_addr;
                memcpy(target_info.interface.mac_addr, s->sll_addr, 6);
            }

            // Fill Gateway Info for this interface
            target_info.interface.gw_ipv4 = 0;
            memset(target_info.interface.gw_mac_addr, 0, 6);
            for(auto& gw : gateways) {
                if(gw.interface == ifname) {
                    target_info.interface.gw_ipv4 = gw.gw_ip;
                    memcpy(target_info.interface.gw_mac_addr, gw.gw_mac, 6);
                }
            }
        }
        freeifaddrs(ifaddr);


        // 후속처리

        //// ARP 정보설정
        auto Arps = ___GetArpTable();
        for( auto&[ ifindex, value ]  : output)
        {
            for( auto& arp : Arps )
            {
                if( value.interface.ipv4 == arp.raw.ip_be ) break;

                if( ifindex == arp.raw.interface_index )
                {
                    host_information info;

                    info.host_ip = arp.raw.ip_be;
                    memcpy(info.host_mac, arp.raw.mac, 6 );

                    info.gw_ip = value.interface.ipv4 ;
                    memcpy(info.gw_mac, value.interface.mac_addr, 6 );

                    info.to_string.host_ip = arp.ip;
                    info.to_string.host_mac = arp.mac;


                    value.hosts.push_back(info);
                }
 
            }

        }


        return output;
    }

    

    std::vector<host_information> __load_hosts_by_interface( const unsigned int& gw_ip,  const unsigned char* gw_mac,  const unsigned int& gw_subnetmask )
    {
        std::vector<host_information> hosts{};

        // 호스트 주소들 구하기 (유효한것만)
        std::vector<std::thread> threads_;
        auto host_ips = ___get_host_ips( gw_ip, gw_subnetmask );
        for( const auto& host_ip : host_ips )
        {
            
            if( host_ip == gw_ip ) continue;

            for( const auto& arp_table : ___GetArpTable() )
            {
                if(host_ip == arp_table.raw.ip_be )
                {
                    host_information info;
                    info.host_ip = host_ip;
                    memcpy(info.host_mac, arp_table.raw.mac, 6 );
                    info.gw_ip = gw_ip;
                    memcpy(info.gw_mac, gw_mac, 6 );
                    info.to_string.host_ip = arp_table.ip;
                    info.to_string.host_mac = arp_table.mac;

                    hosts.push_back(info);

                    break;
                }
                    
            }

        }

        return hosts;
    }




    std::vector<unsigned int> ___get_host_ips(const unsigned int& ipv4, const unsigned int& subnetmask)
    {
        std::vector<unsigned int> hosts;

        unsigned int network   = ipv4 & subnetmask;
        unsigned int broadcast = network | ~subnetmask;

        // 호스트가 없는 경우 (/31, /32)
        if (broadcast - network <= 1)
            return hosts;

        for (unsigned int ip = network + 1; ip < broadcast; ++ip)
        {
            hosts.push_back(ip);
        }

        return hosts;
    }

    struct ArpEntry
    {
        // 기존 표현용 필드
        std::string ip;
        std::string mac;
        std::string device;

        // 내부 처리용 필드
        struct 
        {
            uint32_t ip_be;          // IPv4 (big-endian)
            uint8_t  mac[6];         // MAC address
            int      interface_index;   // ifindex
        } raw;
    };

    std::vector<ArpEntry> ___GetArpTable()
    {
        std::vector<ArpEntry> table;
        std::ifstream file("/proc/net/arp");
        std::string line;

        std::getline(file, line); // 헤더 스킵 ->>> IP address       HW type     Flags       HW address            Mask     Device

        /*
            IP address       HW type     Flags       HW address            Mask     Device
            192.168.1.205    0x1         0x2         00:0c:29:7a:0d:42     *        ens36
            192.168.0.1      0x1         0x2         00:0c:29:cd:0c:aa     *        ens36
            192.168.1.201    0x1         0x2         62:5c:33:26:7b:8e     *        ens36
            192.168.1.101    0x1         0x2         9c:6b:00:2b:0c:48     *        ens36
            192.168.1.1      0x1         0x2         30:16:9d:4d:30:51     *        ens36
            172.30.1.100     0x1         0x2         00:0c:29:90:53:f1     *        ens160
            192.168.1.202    0x1         0x2         88:f4:da:a1:ec:58     *        ens36
            192.168.1.200    0x1         0x2         68:1d:ef:4d:f0:86     *        ens36
        */
        while (std::getline(file, line))
        {
            std::istringstream iss(line);
            ArpEntry entry;
            std::string hwType, flags, mask;

            iss >> entry.ip >> hwType >> flags >> entry.mac >> mask >> entry.device;

            // IP (big-endian)
            inet_pton(AF_INET, entry.ip.c_str(), &entry.raw.ip_be);

            // MAC
            unsigned int m[6];
            sscanf(entry.mac.c_str(),
                "%x:%x:%x:%x:%x:%x",
                &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]);
            for (int i = 0; i < 6; ++i)
                entry.raw.mac[i] = static_cast<uint8_t>(m[i]);

            // device index
            entry.raw.interface_index = if_nametoindex(entry.device.c_str());

            table.push_back(entry);
        }

        return table;
    }
};

#endif