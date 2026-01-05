#ifndef SSL_MANAGER_HPP
#define SSL_MANAGER_HPP

#include "global.hpp"

// ==========================================
// [DEBUG] 로그 매크로
// ==========================================
#include <cstdio>
#include <cstdarg>
#include <ctime>
#include <string>

static inline void LOG_DEBUG(const char* tag, const char* fmt, ...) {
    char buffer[4096];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    printf("\033[1;33m[%02d:%02d:%02d]\033[0m \033[1;36m[%-15s]\033[0m %s\n", 
        t->tm_hour, t->tm_min, t->tm_sec, tag, buffer);
}

// --- Headers ---
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/PayloadLayer.h>
#include <shared_mutex>
#include <unordered_map>
#include <map>
#include <vector>
#include <chrono>
#include <cstring>
#include <iostream>
#include <random>
#include <atomic>
#include <mutex>
#include <memory>
#include <algorithm>

static const size_t MAX_TCP_PAYLOAD = 1440;
static const int SSL_SESSION_TIMEOUT_SEC = 300;
static const int TCP_WINDOW_SIZE = 65535;

// --- Helper Functions ---
static std::string get_openssl_error() {
    char buf[256];
    unsigned long err = ERR_get_error();
    if (err == 0) return "No Error";
    ERR_error_string_n(err, buf, sizeof(buf));
    return std::string(buf);
}

static std::string ip_to_str(uint32_t ip) {
    char buf[INET_ADDRSTRLEN];
    struct in_addr ia; ia.s_addr = ip; // Already Network Byte Order if coming from packet, but let's assume Host Order for Logic
    // pcpp returns Host Order usually? Let's check. pcpp::IPv4Address::toInt() returns Host Byte Order.
    // inet_ntop expects Network Byte Order.
    ia.s_addr = htonl(ip);
    inet_ntop(AF_INET, &ia, buf, INET_ADDRSTRLEN);
    return std::string(buf);
}

enum class TcpState {
    CLOSED, LISTEN, SYN_SENT, SYN_RECEIVED, ESTABLISHED,
    FIN_WAIT_1, FIN_WAIT_2, CLOSE_WAIT, CLOSING, LAST_ACK, TIME_WAIT
};

enum class SslMitmState {
    INITIAL, 
    WAIT_CLIENT_HELLO,      
    CONNECTING_TO_SERVER,   
    SERVER_HANDSHAKE_START, 
    SERVER_HANDSHAKE_DONE,  
    CLIENT_HANDSHAKE_PROCEED, 
    ESTABLISHED,            
    TEARDOWN
};

struct TxPacket {
    std::vector<uint8_t> raw_data;
    interface_information_for_XDP* target_interface;
};

struct FlowKey {
    uint32_t sip, dip;
    uint16_t sport, dport;
    bool operator==(const FlowKey& o) const {
        return sip == o.sip && dip == o.dip && sport == o.sport && dport == o.dport;
    }
};

struct FlowKeyHash {
    size_t operator()(const FlowKey& k) const {
        return k.sip ^ k.dip ^ k.sport ^ k.dport;
    }
};

struct TcpContext {
    TcpState state = TcpState::CLOSED;
    uint32_t send_next = 0; 
    uint32_t send_una = 0;  
    uint32_t recv_next = 0; 
    uint32_t start_seq = 0;
    uint16_t send_window = TCP_WINDOW_SIZE;
    uint16_t recv_window = TCP_WINDOW_SIZE;
    
    std::map<uint32_t, std::vector<uint8_t>> reassembly_buffer;
    
    uint32_t local_ip;
    uint32_t remote_ip;
    uint16_t local_port;
    uint16_t remote_port;
    uint8_t local_mac[6];
    uint8_t remote_mac[6];
    
    interface_information_for_XDP* out_interface = nullptr;
};

struct SslSession {
    FlowKey key_client_side; 
    FlowKey key_server_side; 
    
    SslMitmState mitm_state = SslMitmState::INITIAL;
    std::recursive_mutex session_mutex;
    std::chrono::steady_clock::time_point last_activity;
    bool marked_for_deletion = false;

    SSL* ssl_client = nullptr; 
    SSL* ssl_server = nullptr; 
    BIO* c_rbio = nullptr; BIO* c_wbio = nullptr;
    BIO* s_rbio = nullptr; BIO* s_wbio = nullptr;

    TcpContext client_tcp; 
    TcpContext server_tcp;

    std::string sni_hostname;
    X509* server_real_cert = nullptr; 

    bool sni_parsed = false;
    bool server_tcp_connected = false;
    bool server_ssl_handshake_done = false;
    bool client_ssl_handshake_done = false;
    bool server_ssl_sni_set = false;

    ~SslSession() {
        if (ssl_client) SSL_free(ssl_client);
        if (ssl_server) SSL_free(ssl_server);
        if (server_real_cert) X509_free(server_real_cert);
    }
};

class SSL_MANAGER {
public:
    SSL_MANAGER() {
        _init_openssl();
        _start_gc_thread();
    }

    ~SSL_MANAGER() {
        _stop_gc = true;
        if (gc_thread.joinable()) gc_thread.join();
        if (ctx_server_base) SSL_CTX_free(ctx_server_base);
        if (ctx_client) SSL_CTX_free(ctx_client);
        if (ca_cert) X509_free(ca_cert);
        if (ca_key) EVP_PKEY_free(ca_key);
        if (shared_forging_key) EVP_PKEY_free(shared_forging_key);
        
        std::lock_guard<std::mutex> lock(cert_cache_mutex);
        for(auto& pair : cert_cache) {
            X509_free(pair.second.cert);
            EVP_PKEY_free(pair.second.key);
        }
    }

    bool LoadConfig(const std::string& caCertPath, const std::string& caKeyPath) {
        FILE* f = fopen(caCertPath.c_str(), "r");
        if (!f) { LOG_DEBUG("INIT", "Failed to open CA Cert"); return false; }
        ca_cert = PEM_read_X509(f, NULL, NULL, NULL);
        fclose(f);

        f = fopen(caKeyPath.c_str(), "r");
        if (!f) { LOG_DEBUG("INIT", "Failed to open CA Key"); return false; }
        ca_key = PEM_read_PrivateKey(f, NULL, NULL, NULL);
        fclose(f);
        
        return (ca_cert && ca_key);
    }

    std::vector<TxPacket> ProcessPacket(
        pcpp::Packet* packet, 
        interface_information_for_XDP& ingress_info, 
        std::vector<interface_information_for_XDP>& interfaces) 
    {
        std::vector<TxPacket> out_packets;

        pcpp::IPv4Layer* ipLayer = packet->getLayerOfType<pcpp::IPv4Layer>();
        pcpp::TcpLayer* tcpLayer = packet->getLayerOfType<pcpp::TcpLayer>();

        if (!ipLayer || !tcpLayer) return out_packets;

        uint32_t src_ip = ipLayer->getSrcIPv4Address().toInt();
        uint32_t dst_ip = ipLayer->getDstIPv4Address().toInt();
        uint16_t src_port = ntohs(tcpLayer->getTcpHeader()->portSrc);
        uint16_t dst_port = ntohs(tcpLayer->getTcpHeader()->portDst);

        // [DEBUG] 패킷 수신 확인 로그 (매우 중요)
        // 서버로부터 오는 SYN/ACK (SrcPort 443)가 보이는지 확인
        if (src_port == 443) {
            // LOG_DEBUG("RX", "Packet from Server: %s:%d -> %s:%d [Flags: %s%s]", 
            //     ip_to_str(src_ip).c_str(), src_port, ip_to_str(dst_ip).c_str(), dst_port,
            //     tcpLayer->getTcpHeader()->synFlag ? "SYN " : "",
            //     tcpLayer->getTcpHeader()->ackFlag ? "ACK " : "");
        }

        SslSession* session = _get_session(src_ip, src_port, dst_ip, dst_port);
        bool from_client = false;

        if (!session) {
            // 새 세션은 Client -> Proxy (Dst Port 443) SYN 만 허용
            if (tcpLayer->getTcpHeader()->synFlag && !tcpLayer->getTcpHeader()->ackFlag) {
                if (dst_port == 443) { 
                    LOG_DEBUG("SESSION", "New Client Connection: %s:%d -> %s:%d", 
                        ip_to_str(src_ip).c_str(), src_port, ip_to_str(dst_ip).c_str(), dst_port);
                    
                    session = _create_session(src_ip, src_port, dst_ip, dst_port, packet, ingress_info, interfaces);
                    if (!session) return out_packets; 
                    from_client = true;
                } else {
                    return out_packets; 
                }
            } else {
                // 세션이 없는데 중간 패킷(ACK 등)이 오면 무시 (또는 Pass through)
                return out_packets; 
            }
        } else {
            FlowKey current_key = {src_ip, dst_ip, src_port, dst_port};
            if (current_key == session->key_client_side) {
                from_client = true;
            } else if (current_key == session->key_server_side) {
                from_client = false;
                // LOG_DEBUG("RX", "Matched Server Session Packet!");
            } else {
                return out_packets;
            }
        }

        std::lock_guard<std::recursive_mutex> sess_lock(session->session_mutex);
        session->last_activity = std::chrono::steady_clock::now();

        if (from_client) {
            _handle_tcp_input(session, &session->client_tcp, &session->server_tcp, packet, out_packets, true);
        } else {
            _handle_tcp_input(session, &session->server_tcp, &session->client_tcp, packet, out_packets, false);
        }

        return out_packets;
    }

private:
    std::unordered_map<FlowKey, SslSession*, FlowKeyHash> session_map;
    std::shared_mutex session_map_mutex;

    SSL_CTX *ctx_server_base = nullptr;
    SSL_CTX *ctx_client = nullptr;
    X509* ca_cert = nullptr;
    EVP_PKEY* ca_key = nullptr;
    EVP_PKEY* shared_forging_key = nullptr; 

    struct CertCacheEntry {
        X509* cert;
        EVP_PKEY* key;
        std::chrono::steady_clock::time_point created_at;
    };
    std::map<std::string, CertCacheEntry> cert_cache;
    std::mutex cert_cache_mutex;

    std::thread gc_thread;
    std::atomic<bool> _stop_gc{false};

    void _init_openssl() {
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();
        ERR_load_BIO_strings();
        shared_forging_key = EVP_RSA_gen(2048);
        
        ctx_server_base = SSL_CTX_new(TLS_server_method());
        SSL_CTX_set_options(ctx_server_base, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION);
        SSL_CTX_set_client_hello_cb(ctx_server_base, _client_hello_cb, this);
        SSL_CTX_set_session_cache_mode(ctx_server_base, SSL_SESS_CACHE_OFF);

        ctx_client = SSL_CTX_new(TLS_client_method());
        SSL_CTX_set_options(ctx_client, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
        SSL_CTX_set_verify(ctx_client, SSL_VERIFY_NONE, NULL); 
        SSL_CTX_set_session_cache_mode(ctx_client, SSL_SESS_CACHE_OFF);
    }

    static int _client_hello_cb(SSL *s, int *al, void *arg) {
        SslSession* sess = (SslSession*)SSL_get_app_data(s);
        if (!sess) return SSL_CLIENT_HELLO_ERROR;

        if (sess->mitm_state == SslMitmState::CLIENT_HANDSHAKE_PROCEED || sess->server_real_cert != nullptr) {
            return SSL_CLIENT_HELLO_SUCCESS;
        }

        if (!sess->sni_parsed) {
            const unsigned char *p;
            size_t len;
            if (SSL_client_hello_get0_ext(s, TLSEXT_TYPE_server_name, &p, &len)) {
                if (len >= 2) {
                    uint16_t list_len = (p[0] << 8) | p[1];
                    p += 2;
                    if (list_len + 2 <= len) {
                        while (list_len > 0) {
                            uint8_t type = p[0];
                            uint16_t name_len = (p[1] << 8) | p[2];
                            p += 3;
                            if (type == 0 && name_len > 0) {
                                sess->sni_hostname = std::string((const char*)p, name_len);
                                sess->sni_parsed = true;
                                LOG_DEBUG("CALLBACK", "SNI Parsed: %s", sess->sni_hostname.c_str());
                                break;
                            }
                            p += name_len;
                            list_len -= (3 + name_len);
                        }
                    }
                }
            }
            sess->sni_parsed = true; 
        }

        if (sess->mitm_state == SslMitmState::WAIT_CLIENT_HELLO || sess->mitm_state == SslMitmState::INITIAL) {
            // LOG_DEBUG("CALLBACK", "Pausing for Server Connection");
            sess->mitm_state = SslMitmState::CONNECTING_TO_SERVER;
        }

        return SSL_CLIENT_HELLO_RETRY; 
    }

    std::pair<X509*, EVP_PKEY*> _get_forged_credentials(X509* real_cert, const std::string& hostname) {
        std::lock_guard<std::mutex> lock(cert_cache_mutex);
        std::string lookup = hostname.empty() ? "unknown" : hostname;
        auto it = cert_cache.find(lookup);
        if (it != cert_cache.end()) return {it->second.cert, it->second.key};

        EVP_PKEY* pkey = shared_forging_key;
        EVP_PKEY_up_ref(pkey); 

        X509* x509 = X509_new();
        
        // [1] 시리얼 번호 생성 (Random Large Integer)
        // rand() 대신 BIGNUM을 사용하여 긴 시리얼 번호 생성 (브라우저 필수)
        BIGNUM* bn = BN_new();
        ASN1_INTEGER* serial = X509_get_serialNumber(x509);
        BN_rand(bn, 159, 0, 0); // 159 bits random
        BN_to_ASN1_INTEGER(bn, serial);
        BN_free(bn);

        // [2] 유효 기간 설정 (현재 시간보다 24시간 전으로 설정하여 시간 오차 방지)
        X509_gmtime_adj(X509_get_notBefore(x509), -86400); 
        X509_gmtime_adj(X509_get_notAfter(x509), 31536000L); // 1년

        X509_set_pubkey(x509, pkey);
        
        // Subject Name 설정
        X509_NAME* name = X509_get_subject_name(x509);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)lookup.c_str(), -1, -1, 0);
        // Organization 등을 추가하면 더 진짜 같아 보임
        X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)"Secure Proxy", -1, -1, 0);

        // Issuer Name 설정 (CA 인증서의 Subject를 가져옴)
        X509_set_issuer_name(x509, X509_get_subject_name(ca_cert));

        // [3] 필수 확장 필드 추가 (순서 중요)
        
        // 3-1. Basic Constraints (End Entity)
        _add_ext(x509, ca_cert, NID_basic_constraints, "critical,CA:FALSE");
        
        // 3-2. Key Usage (서명 및 키 암호화 용도)
        _add_ext(x509, ca_cert, NID_key_usage, "digitalSignature,keyEncipherment");
        
        // 3-3. Extended Key Usage (서버 인증 필수 - TLS 1.3)
        _add_ext(x509, ca_cert, NID_ext_key_usage, "serverAuth");
        
        // 3-4. Subject Key Identifier (Hash)
        _add_ext(x509, ca_cert, NID_subject_key_identifier, "hash");
        
        // 3-5. Authority Key Identifier (CA의 Key ID를 참조 - 체인 검증 핵심)
        _add_ext(x509, ca_cert, NID_authority_key_identifier, "keyid:always");

        // [4] SAN (Subject Alternative Name) 처리
        // 실제 인증서에서 SAN을 가져오거나, 없으면 SNI 기반으로 생성
        bool san_added = false;
        if (real_cert) {
            int san_pos = X509_get_ext_by_NID(real_cert, NID_subject_alt_name, -1);
            if (san_pos >= 0) {
                X509_EXTENSION* ext = X509_get_ext(real_cert, san_pos);
                if (ext) {
                    X509_add_ext(x509, ext, -1);
                    san_added = true;
                }
            }
        } 
        
        if (!san_added) {
             // Real cert에서 가져오지 못했으면 SNI로 직접 생성
             std::string san = "DNS:" + lookup;
             _add_ext(x509, ca_cert, NID_subject_alt_name, san.c_str());
        }
        
        // 서명
        X509_sign(x509, ca_key, EVP_sha256());
        
        cert_cache[lookup] = {x509, pkey, std::chrono::steady_clock::now()};
        return {x509, pkey};
    }

    SslSession* _get_session(uint32_t sip, uint16_t sport, uint32_t dip, uint16_t dport) {
        std::shared_lock<std::shared_mutex> lock(session_map_mutex);
        FlowKey key = {sip, dip, sport, dport};
        auto it = session_map.find(key);
        if (it != session_map.end()) return it->second;
        return nullptr;
    }

    SslSession* _create_session(uint32_t sip, uint16_t sport, uint32_t dip, uint16_t dport,
                                pcpp::Packet* pkt, 
                                interface_information_for_XDP& ingress_info, 
                                std::vector<interface_information_for_XDP>& ifaces) 
    {
        std::unique_lock<std::shared_mutex> lock(session_map_mutex);
        SslSession* s = new SslSession();
        s->key_client_side = {sip, dip, sport, dport};
        s->last_activity = std::chrono::steady_clock::now();

        pcpp::EthLayer* eth = pkt->getLayerOfType<pcpp::EthLayer>();
        
        // --- Client TCP Setup ---
        s->client_tcp.remote_ip = sip; s->client_tcp.remote_port = sport;
        s->client_tcp.local_ip = dip;  s->client_tcp.local_port = dport;
        if(eth) {
            memcpy(s->client_tcp.remote_mac, eth->getSourceMac().getRawData(), 6);
            memcpy(s->client_tcp.local_mac, eth->getDestMac().getRawData(), 6);
        }

        // --- Interface Selection & Server TCP Setup ---
        // WAN/LAN 구분 및 Outbound Interface 찾기
        if (ingress_info.interface_info.interface.interface_type == interface_type::WAN) {
            s->server_tcp.out_interface = &ingress_info;
            memcpy(s->server_tcp.local_mac, ingress_info.interface_info.interface.mac_addr, 6);
            memcpy(s->server_tcp.remote_mac, ingress_info.interface_info.interface.gw_mac_addr, 6);
        } else {
            s->client_tcp.out_interface = &ingress_info;
        }

        for(auto& iface : ifaces) {
            if(iface.interface_info.interface.interface_type == interface_type::WAN && !s->server_tcp.out_interface) {
                s->server_tcp.out_interface = &iface;
                memcpy(s->server_tcp.local_mac, iface.interface_info.interface.mac_addr, 6);
                memcpy(s->server_tcp.remote_mac, iface.interface_info.interface.gw_mac_addr, 6);
            }
            if(iface.interface_info.interface.interface_type == interface_type::LAN && !s->client_tcp.out_interface) {
                s->client_tcp.out_interface = &iface;
            }
        }

        if (!s->server_tcp.out_interface || !s->client_tcp.out_interface) {
             delete s; return nullptr; 
        }

        // --- SNAT (Source NAT) 적용 ---
        // 서버 연결 시 Client IP가 아닌 Proxy WAN IP를 사용해야 리턴 패킷을 받을 수 있음
        // Transparent Proxy (Spoofing)가 작동하려면 Gateway에서 라우팅이 설정되어 있어야 함.
        // 일반적인 테스트 환경에서는 SNAT가 필수.
        
        s->server_tcp.remote_ip = dip; // Real Server IP
        s->server_tcp.remote_port = dport; // 443
        
        // [수정된 부분] Proxy의 WAN IP 사용 (SNAT)
        s->server_tcp.local_ip = s->server_tcp.out_interface->interface_info.interface.ipv4; 
        s->server_tcp.local_port = sport; // Port는 Client Port 재사용 (충돌 가능성 있지만 테스트용으론 OK)

        LOG_DEBUG("SESSION", "SNAT Applied: Proxy(%s:%d) -> Server(%s:%d)", 
            ip_to_str(s->server_tcp.local_ip).c_str(), s->server_tcp.local_port,
            ip_to_str(s->server_tcp.remote_ip).c_str(), s->server_tcp.remote_port);

        // --- Key Registration ---
        session_map[s->key_client_side] = s;
        
        // Server Side Key: Server -> Proxy
        // 리턴 패킷의 Dest IP는 Proxy WAN IP가 됨
        s->key_server_side = {
            s->server_tcp.remote_ip, // Src: Server
            s->server_tcp.local_ip,  // Dst: Proxy WAN IP
            s->server_tcp.remote_port, // SrcPort: 443
            s->server_tcp.local_port   // DstPort: Client Port (reused)
        };
        session_map[s->key_server_side] = s;

        // --- SSL Objects ---
        s->ssl_client = SSL_new(ctx_server_base);
        s->c_rbio = BIO_new(BIO_s_mem());
        s->c_wbio = BIO_new(BIO_s_mem());
        SSL_set_bio(s->ssl_client, s->c_rbio, s->c_wbio);
        SSL_set_accept_state(s->ssl_client);
        SSL_set_app_data(s->ssl_client, s);

        s->ssl_server = SSL_new(ctx_client);
        s->s_rbio = BIO_new(BIO_s_mem());
        s->s_wbio = BIO_new(BIO_s_mem());
        SSL_set_bio(s->ssl_server, s->s_rbio, s->s_wbio);
        SSL_set_connect_state(s->ssl_server);
        SSL_set_app_data(s->ssl_server, s);

        return s;
    }

    void _handle_tcp_input(SslSession* sess, TcpContext* in_tcp, TcpContext* out_tcp,
                           pcpp::Packet* pkt, std::vector<TxPacket>& out_pkts, bool is_client_side) 
    {
        pcpp::TcpLayer* tcp = pkt->getLayerOfType<pcpp::TcpLayer>();
        pcpp::tcphdr* hdr = tcp->getTcpHeader();
        
        uint32_t seq = ntohl(hdr->sequenceNumber);
        uint32_t ack_seq = ntohl(hdr->ackNumber);
        uint32_t payload_len = tcp->getLayerPayloadSize();
        uint8_t* payload = tcp->getLayerPayload();
        
        if (hdr->rstFlag) {
            LOG_DEBUG("TCP", "RST Received. Closing.");
            in_tcp->state = TcpState::CLOSED;
            out_tcp->state = TcpState::CLOSED;
            sess->marked_for_deletion = true;
            return;
        }

        switch (in_tcp->state) {
            case TcpState::CLOSED:
                if (hdr->synFlag) {
                    in_tcp->recv_next = seq + 1;
                    std::random_device rd; std::mt19937 gen(rd());
                    std::uniform_int_distribution<uint32_t> dis(100000, 99999999);
                    in_tcp->start_seq = dis(gen);
                    in_tcp->send_next = in_tcp->start_seq;
                    
                    in_tcp->state = TcpState::SYN_RECEIVED;
                    _send_tcp_packet(in_tcp, out_pkts, TH_SYN | TH_ACK, NULL, 0);
                    //in_tcp->send_next++;(제거확정.)
                }
                break;

            case TcpState::SYN_SENT: // Proxy -> Real Server
                if (hdr->synFlag && hdr->ackFlag) {
                    LOG_DEBUG("TCP", "Server Connected (SYN/ACK Recv)");
                    in_tcp->recv_next = seq + 1;
                    in_tcp->send_una = ack_seq;
                    in_tcp->state = TcpState::ESTABLISHED;
                    sess->server_tcp_connected = true;
                    
                    _send_tcp_packet(in_tcp, out_pkts, TH_ACK, NULL, 0);
                    _process_ssl_data(sess, out_pkts);
                }
                break;

            case TcpState::SYN_RECEIVED: 
                if (hdr->ackFlag) {
                    if (ack_seq == in_tcp->send_next) {
                        in_tcp->state = TcpState::ESTABLISHED;
                        in_tcp->send_una = ack_seq;
                        if (is_client_side) sess->mitm_state = SslMitmState::WAIT_CLIENT_HELLO;
                    }
                }
                [[fallthrough]]; 

            case TcpState::ESTABLISHED:
                in_tcp->send_window = ntohs(hdr->windowSize);
                if (hdr->ackFlag && ack_seq > in_tcp->send_una) in_tcp->send_una = ack_seq;

                if (hdr->finFlag) {
                    in_tcp->recv_next = seq + payload_len + 1;
                    in_tcp->state = TcpState::CLOSE_WAIT;
                    _send_tcp_packet(in_tcp, out_pkts, TH_ACK, NULL, 0);
                    _send_tcp_packet(out_tcp, out_pkts, TH_FIN | TH_ACK, NULL, 0);
                    //out_tcp->send_next++; (제거확정.)
                    return;
                }

                if (payload_len > 0) {
                    if (seq == in_tcp->recv_next) {
                         _handle_tcp_payload(sess, in_tcp, payload, payload_len, is_client_side, out_pkts);
                         
                         auto it = in_tcp->reassembly_buffer.begin();
                         while (it != in_tcp->reassembly_buffer.end()) {
                             if (it->first == in_tcp->recv_next) {
                                 _handle_tcp_payload(sess, in_tcp, it->second.data(), it->second.size(), is_client_side, out_pkts);
                                 it = in_tcp->reassembly_buffer.erase(it);
                             } else break;
                         }
                         _send_tcp_packet(in_tcp, out_pkts, TH_ACK, NULL, 0);
                         _process_ssl_data(sess, out_pkts);
                    } else if (seq > in_tcp->recv_next) {
                        in_tcp->reassembly_buffer[seq] = std::vector<uint8_t>(payload, payload + payload_len);
                        _send_tcp_packet(in_tcp, out_pkts, TH_ACK, NULL, 0);
                    } else {
                        _send_tcp_packet(in_tcp, out_pkts, TH_ACK, NULL, 0);
                    }
                } 
                break;
            default: break;
        }
    }

    void _handle_tcp_payload(SslSession* sess, TcpContext* tcp, uint8_t* data, size_t len, bool is_client, std::vector<TxPacket>& out_pkts) {
        if (is_client) BIO_write(sess->c_rbio, data, len);
        else           BIO_write(sess->s_rbio, data, len);
        tcp->recv_next += len;
    }

    void _process_ssl_data(SslSession* sess, std::vector<TxPacket>& out_pkts) {
        char buf[16384];
        int n;
        bool progress = true;
        int loop_count = 0;

        while (progress && loop_count++ < 20) {
            progress = false;

            // 1. Client Side (Proxy as Server)
            if (!sess->client_ssl_handshake_done) {
                ERR_clear_error();
                int ret = SSL_accept(sess->ssl_client);

                if (ret == 1) {
                    LOG_DEBUG("SSL", "Client Handshake DONE (Cipher: %s)", SSL_get_cipher_name(sess->ssl_client));
                    sess->client_ssl_handshake_done = true;
                    sess->mitm_state = SslMitmState::ESTABLISHED;
                    progress = true;
                } else {
                    int err = SSL_get_error(sess->ssl_client, ret);
                    
                    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                        // 정상적인 대기 상태
                    } 
                    else if (err == SSL_ERROR_WANT_CLIENT_HELLO_CB) {
                        if (sess->mitm_state == SslMitmState::CONNECTING_TO_SERVER) {
                            if (sess->server_tcp.state == TcpState::CLOSED) {
                                _initiate_server_connection(sess, out_pkts);
                            }
                        }
                    }
                    else
                    {
                        LOG_DEBUG("SSL_ERR", "SSL_accept failed. ErrCode: %d, Msg: %s", err, get_openssl_error().c_str());
                    }
                    
                    if (BIO_ctrl_pending(sess->c_wbio) > 0) {
                        _flush_bio(sess->c_wbio, &sess->client_tcp, out_pkts);
                    }
                }
            }

            // 2. Server Side (Proxy as Client)
            if (sess->server_tcp_connected && !sess->server_ssl_handshake_done) {
                if (!sess->server_ssl_sni_set) {
                    if (!sess->sni_hostname.empty()) 
                        SSL_set_tlsext_host_name(sess->ssl_server, sess->sni_hostname.c_str());
                    sess->server_ssl_sni_set = true;
                }

                ERR_clear_error();
                int ret = SSL_connect(sess->ssl_server);
                
                if (ret == 1) {
                    LOG_DEBUG("SSL", "Server Handshake DONE");
                    sess->server_ssl_handshake_done = true;
                    sess->mitm_state = SslMitmState::SERVER_HANDSHAKE_DONE;

                    X509* cert = SSL_get_peer_certificate(sess->ssl_server);
                    if (cert) sess->server_real_cert = cert; 

                    std::string hostname = sess->sni_hostname.empty() ? "unknown" : sess->sni_hostname;
                    auto [fake_cert, fake_key] = _get_forged_credentials(sess->server_real_cert, hostname);
                    
                    SSL_use_certificate(sess->ssl_client, fake_cert);
                    SSL_use_PrivateKey(sess->ssl_client, fake_key);

                    sess->mitm_state = SslMitmState::CLIENT_HANDSHAKE_PROCEED;
                    progress = true; 
                } 
                
                if (BIO_ctrl_pending(sess->s_wbio) > 0) {
                    _flush_bio(sess->s_wbio, &sess->server_tcp, out_pkts);
                    progress = true;
                }
            }

            // 3. Established
            if (sess->client_ssl_handshake_done && sess->server_ssl_handshake_done) {
                // Client -> Server
                while ((n = SSL_read(sess->ssl_client, buf, sizeof(buf))) > 0) {
                    SSL_write(sess->ssl_server, buf, n);
                    progress = true;
                }
                if (BIO_ctrl_pending(sess->s_wbio) > 0) _flush_bio(sess->s_wbio, &sess->server_tcp, out_pkts); 

                // Server -> Client
                while ((n = SSL_read(sess->ssl_server, buf, sizeof(buf))) > 0) {
                    SSL_write(sess->ssl_client, buf, n);
                    progress = true;
                }
                if (BIO_ctrl_pending(sess->c_wbio) > 0) _flush_bio(sess->c_wbio, &sess->client_tcp, out_pkts); 
            }
        }
    }

    void _initiate_server_connection(SslSession* sess, std::vector<TxPacket>& out_pkts) {
        if (sess->server_tcp.state != TcpState::CLOSED) return;

        LOG_DEBUG("TCP", "Sending SYN to Server %s", sess->sni_hostname.c_str());
        sess->server_tcp.state = TcpState::SYN_SENT;
        std::random_device rd; std::mt19937 gen(rd());
        std::uniform_int_distribution<uint32_t> dis(1000, 99999999);
        sess->server_tcp.start_seq = dis(gen);
        sess->server_tcp.send_next = sess->server_tcp.start_seq;

        _send_tcp_packet(&sess->server_tcp, out_pkts, TH_SYN, NULL, 0);
        //sess->server_tcp.send_next++;
    }

    void _flush_bio(BIO* bio, TcpContext* tcp, std::vector<TxPacket>& out_pkts) {
        if (!bio || !tcp->out_interface) return;
        char buf[MAX_TCP_PAYLOAD]; 
        int n;
        while ((n = BIO_read(bio, buf, sizeof(buf))) > 0) {
            _send_tcp_packet(tcp, out_pkts, TH_PUSH | TH_ACK, (uint8_t*)buf, n);
        }
    }

    void _send_tcp_packet(TcpContext* tcp, std::vector<TxPacket>& out_pkts, 
                      uint8_t flags, uint8_t* payload, size_t payload_len) 
{
    if (!tcp->out_interface) {
        return;
    }

    // Create layers on heap - PcapPlusPlus will manage their lifetime
    pcpp::EthLayer* ethLayer = new pcpp::EthLayer(
        pcpp::MacAddress(tcp->local_mac), 
        pcpp::MacAddress(tcp->remote_mac), 
        PCPP_ETHERTYPE_IP
    );
    
    pcpp::IPv4Layer* ipLayer = new pcpp::IPv4Layer(
        pcpp::IPv4Address(tcp->local_ip), 
        pcpp::IPv4Address(tcp->remote_ip)
    );
    ipLayer->getIPv4Header()->timeToLive = 64;
    ipLayer->getIPv4Header()->ipId = htons(rand() & 0xFFFF);
    ipLayer->getIPv4Header()->fragmentOffset = 0x40;

    pcpp::TcpLayer* tcpLayer = new pcpp::TcpLayer(tcp->local_port, tcp->remote_port);
    pcpp::tcphdr* h = tcpLayer->getTcpHeader();
    h->sequenceNumber = htonl(tcp->send_next);
    h->ackNumber = htonl(tcp->recv_next);
    h->synFlag = (flags & TH_SYN) ? 1 : 0;
    h->ackFlag = (flags & TH_ACK) ? 1 : 0;
    h->pshFlag = (flags & TH_PUSH) ? 1 : 0;
    h->finFlag = (flags & TH_FIN) ? 1 : 0;
    h->rstFlag = (flags & TH_RST) ? 1 : 0;
    h->windowSize = htons(tcp->recv_window);

    pcpp::Packet newPacket;
    newPacket.addLayer(ethLayer, true);   // true = take ownership
    newPacket.addLayer(ipLayer, true);
    newPacket.addLayer(tcpLayer, true);

    if (payload && payload_len > 0) {
        pcpp::PayloadLayer* payloadLayer = new pcpp::PayloadLayer(payload, payload_len);
        newPacket.addLayer(payloadLayer, true);
    }

    // Now safe to compute fields
    newPacket.computeCalculateFields();

    // Update sequence numbers
    if (flags & TH_SYN || flags & TH_FIN) tcp->send_next++;
    tcp->send_next += payload_len;

    pcpp::RawPacket* raw = newPacket.getRawPacket();
    std::vector<uint8_t> data(raw->getRawData(), raw->getRawData() + raw->getRawDataLen());
    
    out_pkts.push_back({data, tcp->out_interface});
}

    void _start_gc_thread() {
        gc_thread = std::thread([this]() {
            while (!_stop_gc) {
                std::this_thread::sleep_for(std::chrono::seconds(10));
                _garbage_collect_sessions();
            }
        });
    }

    void _garbage_collect_sessions() {
        std::unique_lock<std::shared_mutex> lock(session_map_mutex);
        auto now = std::chrono::steady_clock::now();
        for (auto it = session_map.begin(); it != session_map.end(); ) {
            SslSession* s = it->second;
            bool remove = false;
            auto dur = std::chrono::duration_cast<std::chrono::seconds>(now - s->last_activity).count();
            if (dur > SSL_SESSION_TIMEOUT_SEC || s->marked_for_deletion) remove = true;

            if (remove) {
                if (it->first == s->key_client_side) delete s; 
                it = session_map.erase(it);
            } else ++it;
        }
    }

    // 헬퍼 함수 추가 (클래스 내부 또는 상단에 정의)
     bool _add_ext(X509 *cert, X509 *issuer, int nid, const char *value) {
        X509_EXTENSION *ex;
        X509V3_CTX ctx;
        // Context 설정: (Issuer, Subject, Request, CRL, Flags)
        X509V3_set_ctx(&ctx, issuer, cert, NULL, NULL, 0);
        
        ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, (char*)value);
        if (!ex) return false;
        
        X509_add_ext(cert, ex, -1);
        X509_EXTENSION_free(ex);
        return true;
    }

    
};

#endif
