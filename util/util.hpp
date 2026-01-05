#ifndef UTIL_HPP
#define UTIL_HPP

#include <map>

#include "json.hpp"
#include "Queue/queue.hpp"
#include "Tcp/Client.hpp"
#include "base64/base64.hpp"
#include "File/file.hpp"
#include "Timestamp/timestamp.hpp"
#include "ebpf.hpp"
#include "Hash/hash.hpp"
#include <sys/wait.h> // WIFEXITED, WEXITSTATUS
#include <sys/utsname.h>
#include <fstream>
#include <sstream> // stringstream을 사용하기 위해 필요
#include <pwd.h>
#include <grp.h>
#include <future>
#include  <pcapplusplus/Packet.h>
#include "Syslog/SyslogManager.hpp"
#include "InterfaceManager.hpp"
using namespace nlohmann;



namespace NDR
{
    namespace Util
    {
        // { "a", "b" } -> "a,b"
        inline std::string VectorToCommaString(const std::vector<std::string>& vec) 
        {
            if (vec.empty()) return "";

            std::string result;
            for (size_t i = 0; i < vec.size(); ++i) {
                result += vec[i];
                if (i + 1 < vec.size()) result += ",";
            }
            return result;
        }

        namespace interface
        {
            int get_rx_queue_count(int ifindex) {
                
                char ifname[IF_NAMESIZE];
                if (!if_indextoname(ifindex, ifname)) {
                    std::cerr << "인터페이스 이름 변환 실패\n";
                    return -1;
                }

                /*
                    [root@localhost IPS]# cat /sys/class/net/ens160/queues/
                    rx-0/ rx-1/ rx-2/ rx-3/ tx-0/ tx-1/ tx-2/ tx-3/
                */
                std::filesystem::path queues_path = std::filesystem::path("/sys/class/net") / ifname / "queues";

                if (!std::filesystem::exists(queues_path)) {
                    std::cerr << "queues 디렉토리를 찾을 수 없음\n";
                    return 1; // RSS 미지원으로 RX 큐 1로 고정
                }

                int rx_count = 0;
                for (const auto& entry : std::filesystem::directory_iterator(queues_path)) {
                    if (entry.is_directory() && entry.path().filename().string().rfind("rx-", 0) == 0) {
                        ++rx_count;
                    }
                }

                return (rx_count == 0) ? 1 : rx_count; // RSS 미지원 시 1
            }



            struct InterfaceInfo {
                std::string name;
                std::optional<std::string> ip;      // 값이 없을 수 있음
                std::optional<std::string> mask;    // 값이 없을 수 있음
                std::optional<std::string> gateway; // 값이 없을 수 있음
                int interfaceindex;
                bool is_up;
            };

            // 16진수 IP를 "192.168.0.1" 형태로 변환
            std::string hexToIp(const std::string& hex) {
                if (hex.length() != 8) return "0.0.0.0";
                unsigned int addr;
                std::stringstream ss;
                ss << std::hex << hex;
                ss >> addr;

                struct in_addr in;
                in.s_addr = addr;
                return std::string(inet_ntoa(in));
            }

            // 게이트웨이 정보 수집
            std::map<std::string, std::string> getGateways() {
                std::map<std::string, std::string> gateways;
                std::ifstream routeFile("/proc/net/route");
                if (!routeFile.is_open()) return gateways;

                std::string line;
                std::getline(routeFile, line); // Header skip

                while (std::getline(routeFile, line)) {
                    std::stringstream ss(line);
                    std::string iface, dest, gateway;
                    ss >> iface >> dest >> gateway;

                    if (dest == "00000000") {
                        gateways[iface] = hexToIp(gateway);
                    }
                }
                return gateways;
            }

            std::vector<InterfaceInfo> getAllInterfaces() {
                std::map<std::string, InterfaceInfo> ifaceMap;
                struct ifaddrs *ifaddr, *ifa;
                auto gateways = getGateways();

                if (getifaddrs(&ifaddr) == -1) {
                    return {};
                }

                for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
                    std::string name = ifa->ifa_name;

                    // 1. 신규 인터페이스 발견 시 초기화
                    if (ifaceMap.find(name) == ifaceMap.end()) {
                        InterfaceInfo info;
                        info.name = name;
                        info.interfaceindex = if_nametoindex(name.c_str());
                        
                        // 게이트웨이가 있는 경우에만 할당
                        if (gateways.count(name)) {
                            info.gateway = gateways[name];
                        }
                        
                        ifaceMap[name] = info;
                    }

                    // 2. IPv4 상세 정보 업데이트
                    if (ifa->ifa_addr != nullptr && ifa->ifa_addr->sa_family == AF_INET) {
                        char ipStr[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr, ipStr, INET_ADDRSTRLEN);
                        ifaceMap[name].ip = std::string(ipStr);

                        if (ifa->ifa_netmask != nullptr) {
                            char maskStr[INET_ADDRSTRLEN];
                            inet_ntop(AF_INET, &((struct sockaddr_in *)ifa->ifa_netmask)->sin_addr, maskStr, INET_ADDRSTRLEN);
                            ifaceMap[name].mask = std::string(maskStr);
                        }
                    }

                    // 3. 인터페이스 상태 (UP/DOWN) 업데이트
                    ifaceMap[name].is_up = (ifa->ifa_flags & IFF_UP) && (ifa->ifa_flags & IFF_RUNNING);
                }

                freeifaddrs(ifaddr);

                std::vector<InterfaceInfo> result;
                for (auto& [name, info] : ifaceMap) {
                    result.push_back(std::move(info));
                }
                return result;
            }
        }

        namespace hardware
        {
            // SMBIOS Type 1 (System Information) 데이터를 저장할 구조체
            struct SystemInfo {
                std::string manufacturer;
                std::string productName;
                std::string version;
                std::string serialNumber;
                std::string uuid;
            };

            // SMBIOS Type 2 (Baseboard Information) 데이터를 저장할 구조체
            struct BaseboardInfo {
                std::string manufacturer;
                std::string productName;
                std::string version;
                std::string serialNumber;
                std::string assetTag;
            };

            std::string get_sys_version()
            {
                struct utsname u; 
                uname(&u); 
                std::cout << u.sysname << " " << u.release << std::endl;

                return u.release;
            }

            std::string readSysfsFile(const std::string& path) {
                std::ifstream file(path);
                if (!file.is_open()) {
                    return "Not Available";
                }
                std::string content;
                std::getline(file, content);
                // 파일 끝에 개행 문자가 있을 수 있으므로 제거
                if (!content.empty() && content.back() == '\n') {
                    content.pop_back();
                }
                return content;
            }

            std::pair<SystemInfo, BaseboardInfo> getSmbiosSystemAndBoardInfo() {
                const std::string basePath = "/sys/class/dmi/id/";
                
                SystemInfo sysInfo;
                BaseboardInfo boardInfo;

                // --- 타입 1: 시스템 정보 조회 ---
                sysInfo.manufacturer = readSysfsFile(basePath + "sys_vendor");
                sysInfo.productName  = readSysfsFile(basePath + "product_name");
                sysInfo.version      = readSysfsFile(basePath + "product_version");
                sysInfo.serialNumber = readSysfsFile(basePath + "product_serial");
                sysInfo.uuid         = readSysfsFile(basePath + "product_uuid");

                // --- 타입 2: 베이스보드 정보 조회 ---
                boardInfo.manufacturer = readSysfsFile(basePath + "board_vendor");
                boardInfo.productName  = readSysfsFile(basePath + "board_name");
                boardInfo.version      = readSysfsFile(basePath + "board_version");
                boardInfo.serialNumber = readSysfsFile(basePath + "board_serial");
                boardInfo.assetTag     = readSysfsFile(basePath + "board_asset_tag");

                return {sysInfo, boardInfo};
            }


            std::string Get_Hardware_hash()
            {
                auto [system, board] = getSmbiosSystemAndBoardInfo();

                std::ostringstream hardware_s;
                hardware_s << system.manufacturer << system.productName << system.serialNumber << system.uuid << system.version << std::endl;
                hardware_s << board.assetTag << board.manufacturer << board.productName << board.serialNumber << board.version << std::endl;

                std::string hardware = hardware_s.str();
                

                return NDR::Util::hash::sha256FromString(hardware);
            }


            
        }

        std::vector<std::string> GetFullProtocolStack(const pcpp::Packet& pkt)
        {
            std::vector<std::string> result;

            // 첫 번째 계층(L2, 보통 Ethernet)부터 시작 
            for (pcpp::Layer* layer = pkt.getFirstLayer(); layer != nullptr; layer = layer->getNextLayer())
            {
                switch (layer->getProtocol())
                {
                    // L2
                    case pcpp::Ethernet:      result.emplace_back("ethernet"); break;
                    case pcpp::VLAN:          result.emplace_back("vlan"); break;
                    case pcpp::ARP:           result.emplace_back("arp"); break;
                    case pcpp::MPLS:          result.emplace_back("mpls"); break;
                    case pcpp::PPPoE:         result.emplace_back("pppoe"); break;

                    // L3
                    case pcpp::IPv4:          result.emplace_back("ipv4"); break;
                    case pcpp::IPv6:          result.emplace_back("ipv6"); break;
                    case pcpp::ICMP:          result.emplace_back("icmp"); break;
                    case pcpp::ICMPv6:        result.emplace_back("icmpv6"); break;
                    case pcpp::IGMP:          result.emplace_back("igmp"); break;
                    case pcpp::GRE:           result.emplace_back("gre"); break;

                    // L4
                    case pcpp::TCP:           result.emplace_back("tcp"); break;
                    case pcpp::UDP:           result.emplace_back("udp"); break;

                    // L7 - Common
                    case pcpp::HTTP:          result.emplace_back("http"); break;
                    case pcpp::SSL:           result.emplace_back("ssl"); break; // TLS/SSL
                    case pcpp::DNS:           result.emplace_back("dns"); break;
                    case pcpp::DHCP:          result.emplace_back("dhcp"); break;
                    case pcpp::FTP:           result.emplace_back("ftp"); break;
                    case pcpp::SSH:           result.emplace_back("ssh"); break;
                    case pcpp::SMTP:          result.emplace_back("smtp"); break;
                    case pcpp::NTP:           result.emplace_back("ntp"); break;
                    case pcpp::Telnet:        result.emplace_back("telnet"); break;

                    // L7 - Industrial / Misc
                    case pcpp::SIP:           result.emplace_back("sip"); break;
                    case pcpp::SDP:           result.emplace_back("sdp"); break;
                    case pcpp::STP:           result.emplace_back("stp"); break;
                    case pcpp::BGP:           result.emplace_back("bgp"); break;
                    case pcpp::Radius:        result.emplace_back("radius"); break;
                    case pcpp::GTP:           result.emplace_back("gtp"); break;

                    // Payload / Unknown
                    case pcpp::GenericPayload: result.emplace_back("payload"); break;

                    default:
                        result.emplace_back("unknown_" + std::to_string(layer->getProtocol())); 
                        break;
                }
            }

            return result;
        }


        std::string ProtocolToString(int protocol) {
            switch (protocol) {
            case 0:   return "hopopt";
            case 1:   return "icmp";
            case 2:   return "igmp";
            case 3:   return "ggp";
            case 4:   return "ipv4";
            case 5:   return "st";
            case 6:   return "tcp";
            case 7:   return "cbt";
            case 8:   return "egp";
            case 9:   return "igp";
            case 10:  return "bbn-rcc-mon";
            case 11:  return "nvp-ii";
            case 12:  return "pup";
            case 13:  return "argus";
            case 14:  return "emcon";
            case 15:  return "xnet";
            case 16:  return "chaos";
            case 17:  return "udp";
            case 18:  return "mux";
            case 19:  return "dcn-meas";
            case 20:  return "hmp";
            case 21:  return "prm";
            case 22:  return "xns-idp";
            case 23:  return "trunk-1";
            case 24:  return "trunk-2";
            case 25:  return "leaf-1";
            case 26:  return "leaf-2";
            case 27:  return "rdp";
            case 28:  return "irtp";
            case 29:  return "iso-tp4";
            case 30:  return "netblt";
            case 31:  return "mfe-nsp";
            case 32:  return "merit-inp";
            case 33:  return "dccp";
            case 34:  return "3pc";
            case 35:  return "idpr";
            case 36:  return "xtp";
            case 37:  return "ddp";
            case 38:  return "idpr-cmtp";
            case 39:  return "tp++";
            case 40:  return "il";
            case 41:  return "ipv6";
            case 42:  return "sdrp";
            case 43:  return "ipv6-route";
            case 44:  return "ipv6-frag";
            case 45:  return "idrp";
            case 46:  return "rsvp";
            case 47:  return "gre";
            case 48:  return "dsn";
            case 49:  return "iatp";
            case 50:  return "stp";
            case 51:  return "srp";
            case 52:  return "uti";
            case 53:  return "swipe";
            case 54:  return "narp";
            case 55:  return "mobile";
            case 56:  return "ipv6";
            case 57:  return "cftp";
            case 58:  return "cal";
            case 59:  return "mtp";
            case 60:  return "ax.25";
            case 61:  return "os";
            case 62:  return "micp";
            case 63:  return "scc-sp";
            case 64:  return "etherip";
            case 65:  return "encap";
            case 66:  return "private";
            case 67:  return "gmtp";
            case 68:  return "ifmp";
            case 69:  return "pnni";
            case 70:  return "pim";
            case 71:  return "aris";
            case 72:  return "scps";
            case 73:  return "qnx";
            case 74:  return "a/n";
            case 75:  return "ipcomp";
            case 76:  return "snp";
            case 77:  return "compaq-peer";
            case 78:  return "ipx-in-ip";
            case 79:  return "vrrp";
            case 80:  return "pgm";
            case 81:  return "any";
            case 82:  return "l2tp";
            case 83:  return "ddx";
            case 84:  return "iatp";
            case 85:  return "stp";
            case 86:  return "srp";
            case 87:  return "uti";
            case 88:  return "swipe";
            case 89:  return "narp";
            case 90:  return "mobile";
            case 91:  return "ipv6";
            case 92:  return "cftp";
            case 93:  return "cal";
            case 94:  return "mtp";
            case 95:  return "ax.25";
            case 96:  return "os";
            case 97:  return "micp";
            case 98:  return "scc-sp";
            case 99:  return "etherip";
            case 100: return "encap";
            case 101: return "private";
            case 102: return "gmtp";
            case 103: return "ifmp";
            case 104: return "pnni";
            case 105: return "pim";
            case 106: return "aris";
            case 107: return "scps";
            case 108: return "qnx";
            case 109: return "a/n";
            case 110: return "ipcomp";
            case 111: return "snp";
            case 112: return "compaq-peer";
            case 113: return "ipx-in-ip";
            case 114: return "vrrp";
            case 115: return "pgm";
            case 116: return "any";
            case 117: return "l2tp";
            case 118: return "ddx";
            case 119: return "iatp";
            case 255: return "reserved";
            default:  return "unknown";
            }
        }
    }
}

#endif