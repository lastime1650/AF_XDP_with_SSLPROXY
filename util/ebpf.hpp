#ifndef EBPF_H
#define EBPF_H

#include <iostream>
#include <string>
#include <stdexcept>
#include <memory>
#include <csignal>
#include <cerrno>
#include <cstring>   // strerror
#include <net/if.h>  // if_nametoindex
#include <ifaddrs.h>
#include <vector>
#include <thread> 
#include <tuple>
#include <unordered_map>
#include <cstdlib>
#include <chrono>    // C++11 chrono 라이브러리
#include <cstdint>   // uint64_t를 위해
#include <atomic>
#include <fmt/core.h>


namespace NDR
{
    namespace Util
    {
        namespace eBPF
        {
            //#define MAX_PKT_SIZE 9216
            #define MAX_PKT_SIZE 1524
            enum interface_type { UNKNOWN, WAN, LAN, lo, SSL_Dummy };
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

            } __attribute__((packed));

            struct Network_event {
                int ifindex;
                unsigned int pkt_len;
                int version;
                int protocol;
                unsigned char macSrc[6];
                unsigned char macDst[6];
                unsigned int ipSrc;
                unsigned int portSrc;
                unsigned int ipDst;
                unsigned int portDst;
                bool is_wan;
                int is_internal_going_to_internet;

                unsigned char RawPacket[MAX_PKT_SIZE];
            } __attribute__((packed));

            namespace QueueStruct
            {
                struct EbpfPacketQueueStruct
                {
                    unsigned long long timestamp;
                    unsigned long long RawPacketSize;

                    
                    unsigned char* PacketEvent; // Network_event_for_XDP
                };
            }
        }
    }
    
}

#endif