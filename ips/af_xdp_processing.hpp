#ifndef AF_XDP_SYSTEM_HPP
#define AF_XDP_SYSTEM_HPP

#include "global.hpp"
#include "nat_manager.hpp"
#include "ssl_manager.hpp"

// --- Configuration ---
// Must be power of 2
static const int NUM_FRAMES = 4096; 
static const int FRAME_SIZE = XSK_UMEM__DEFAULT_FRAME_SIZE;
static const int BATCH_SIZE = 64;

// 절반은 RX용(FQ), 절반은 TX 포워딩용(Copy Target)
static const int NUM_RX_FRAMES = NUM_FRAMES / 2;

struct af_xdp_processing_ctx
{
    SSL_MANAGER Ssl_Manager;
    NAT_MANAGER Nat_Manager;
};

std::atomic<bool> g_stop(false);

// CPU Worker Packet (Optional usage)
struct Packet {
    std::vector<uint8_t> data; 
    uint32_t len;
    uint32_t session_hash; 
};

// CPU Worker
class CPUWorker {
public:
    CPUWorker(int cpu_id) : cpu_id(cpu_id) {}
    void start() { thread_ = std::thread(&CPUWorker::worker_loop, this); }
    void join() { if (thread_.joinable()) thread_.join(); }

private:
    int cpu_id;
    std::thread thread_;
    std::mutex queue_mutex;
    std::condition_variable cv;
    std::queue<Packet> packet_queue;

    void worker_loop() {
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(cpu_id, &cpuset);
        pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
        while (!g_stop) {
            std::unique_lock<std::mutex> lock(queue_mutex);
            cv.wait(lock, [this] { return !packet_queue.empty() || g_stop; });
            if (g_stop && packet_queue.empty()) break;
            while (!packet_queue.empty()) {
                packet_queue.pop(); // Process stub
            }
        }
    }
};

// XskSocket: Manages UMEM and Rings
class XskSocket {
public:
    XskSocket(const std::string& ifname, int queue_id, int xsk_map_fd, unsigned int XDP_MODE) 
        : ifname(ifname), queue_id(queue_id) 
    {
        umem_info = std::make_unique<xsk_umem_info>();
        if (posix_memalign(&umem_info->buffer, getpagesize(), NUM_FRAMES * FRAME_SIZE)) {
            throw std::runtime_error("UMEM allocation failed");
        }

        struct xsk_umem_config umem_cfg = {
            .fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
            .comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
            .frame_size = FRAME_SIZE,
            .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
            .flags = 0
        };

        if (xsk_umem__create(&umem_info->umem, umem_info->buffer, NUM_FRAMES * FRAME_SIZE, 
                             &umem_info->fq, &umem_info->cq, &umem_cfg)) {
            free(umem_info->buffer);
            throw std::runtime_error("xsk_umem__create failed");
        }

        xsk_info = std::make_unique<xsk_socket_info>();
        xsk_info->umem = umem_info.get();

        struct xsk_socket_config xsk_cfg;
        memset(&xsk_cfg, 0, sizeof(xsk_cfg));
        xsk_cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
        xsk_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
        xsk_cfg.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;
        xsk_cfg.xdp_flags = XDP_MODE | XDP_ZEROCOPY;
        xsk_cfg.bind_flags = XDP_USE_NEED_WAKEUP ;  

        if (xsk_socket__create(&xsk_info->xsk, ifname.c_str(), queue_id, umem_info->umem, 
                       &xsk_info->rx, &xsk_info->tx, &xsk_cfg)) {
            throw std::runtime_error("xsk_socket__create failed");
        }

        int sock_fd = xsk_socket__fd(xsk_info->xsk);
        bpf_map_update_elem(xsk_map_fd, &queue_id, &sock_fd, BPF_ANY);

        // 4. Fill Ring Init (Only HALF for RX)
        uint32_t idx;
        xsk_ring_prod__reserve(&umem_info->fq, NUM_RX_FRAMES, &idx);
        for (int i = 0; i < NUM_RX_FRAMES; i++) {
            *xsk_ring_prod__fill_addr(&umem_info->fq, idx++) = i * FRAME_SIZE;
        }
        xsk_ring_prod__submit(&umem_info->fq, NUM_RX_FRAMES);

        // Init TX Free List (Upper Half)
        for(int i = NUM_RX_FRAMES; i < NUM_FRAMES; i++) {
            free_tx_frames.push_back(i * FRAME_SIZE);
        }
    }

    ~XskSocket() {
        if (xsk_info && xsk_info->xsk) xsk_socket__delete(xsk_info->xsk);
        if (umem_info && umem_info->umem) xsk_umem__delete(umem_info->umem);
        if (umem_info && umem_info->buffer) free(umem_info->buffer);
    }

    xsk_socket_info* get_sock() { return xsk_info.get(); }
    xsk_umem_info* get_umem() { return umem_info.get(); }
    int get_queue_id() {return queue_id; }

    // TX Frame Allocation (Thread-Safe)
    uint64_t get_tx_frame() {
        std::lock_guard<std::mutex> lock(tx_frames_mutex);
        if(free_tx_frames.empty()) return UINT64_MAX;
        uint64_t addr = free_tx_frames.back();
        free_tx_frames.pop_back();
        return addr;
    }

    void release_tx_frame(uint64_t addr) {
        std::lock_guard<std::mutex> lock(tx_frames_mutex);
        free_tx_frames.push_back(addr);
    }

public:
    std::mutex tx_frames_mutex;
    std::vector<uint64_t> free_tx_frames;
    std::unique_ptr<xsk_umem_info> umem_info;
    std::unique_ptr<xsk_socket_info> xsk_info;
    std::string ifname;
    int queue_id;
};


// AF_XDP_CONTROLLER
class AF_XDP_CONTROLLER
{
public:
    AF_XDP_CONTROLLER( interface_information& interface_info, const std::vector<std::unique_ptr<CPUWorker>>& workers, af_xdp_processing_ctx& ctx )
    : interface_info(interface_info), workers_ref(workers), ctx(ctx)
    {
        // cleanup prev config
        bpf_xdp_detach(interface_info.interface.ifindex, XDP_FLAGS_DRV_MODE, nullptr);
        bpf_xdp_detach(interface_info.interface.ifindex, XDP_FLAGS_SKB_MODE, nullptr);
        
        skel = xdp_prog_bpf__open();
        if (!skel || xdp_prog_bpf__load(skel)) throw std::runtime_error("BPF load failed");
        xsks_map_fd = bpf_map__fd(skel->maps.xsks_map);

        int prog_fd = bpf_program__fd(skel->progs.xdp_packet_handler);
        unsigned int XDP_MODE = XDP_FLAGS_DRV_MODE;
        if (bpf_xdp_attach(interface_info.interface.ifindex, prog_fd, XDP_MODE , nullptr) < 0) {
            XDP_MODE = XDP_FLAGS_SKB_MODE; // Fallback
            if (bpf_xdp_attach(interface_info.interface.ifindex, prog_fd, XDP_MODE, nullptr) < 0)
                throw std::runtime_error("XDP attach failed");
        }

        int interface_rx_queues = 1; // Simplification (Should fetch real count)
        for (int i = 0; i < interface_rx_queues; i++) {
            sockets.push_back(std::make_unique<XskSocket>(interface_info.interface.interface_name, i, xsks_map_fd, XDP_MODE));
        }
    }
    
    ~AF_XDP_CONTROLLER() {
        bpf_xdp_detach(interface_info.interface.ifindex, XDP_FLAGS_UPDATE_IF_NOEXIST, nullptr);
        for (auto& t : pollers) if (t.joinable()) t.join();
        xdp_prog_bpf__destroy(skel);
    }

    void Run() {
        for( auto& socket : sockets) {
            pollers.emplace_back(std::thread([this, &socket](){
                poller_loop(socket->get_queue_id(), socket.get());
            }));
        }
    }

    interface_information_for_XDP Get_Interface_with_Socket_Info() {
        std::vector<XskSocket*> Tx_sockets_ptrs;
        for(auto& s : sockets) Tx_sockets_ptrs.push_back(s.get());
        return interface_information_for_XDP{interface_info, Tx_sockets_ptrs};
    }

    void Add_Other_Interface_with_Socket_Infos( std::vector<interface_information_for_XDP> infos ) {
        other_socket_infos = infos;
    }

private:
    interface_information interface_info;
    std::vector<interface_information_for_XDP> other_socket_infos;
    af_xdp_processing_ctx& ctx;
    xdp_prog_bpf* skel;
    int xsks_map_fd;
    const std::vector<std::unique_ptr<CPUWorker>>& workers_ref;
    std::vector<std::unique_ptr<XskSocket>> sockets;
    std::vector<std::thread> pollers;

    void poller_loop(int queue_id, XskSocket* sock_wrapper) 
    {
        auto xsk = sock_wrapper->get_sock();
        auto umem = sock_wrapper->get_umem();

        interface_information_for_XDP current_interface_xdp_info = Get_Interface_with_Socket_Info();
        
        while (!g_stop) {
            uint32_t idx_rx, idx_fq, idx_cq;

            // 1. Clean CQ (Completion Queue)
            unsigned int completed = xsk_ring_cons__peek(&umem->cq, BATCH_SIZE, &idx_cq);
            if (completed > 0) {
                // Separate buffers: RX frames go back to FQ, TX frames go back to Free List
                std::vector<uint64_t> rx_frames_to_recycle;
                
                for (unsigned int i = 0; i < completed; i++) {
                    uint64_t addr = *xsk_ring_cons__comp_addr(&umem->cq, idx_cq++);
                    // Check if addr belongs to RX pool (0 ~ NUM_RX_FRAMES * FRAME_SIZE)
                    if (addr < (uint64_t)NUM_RX_FRAMES * FRAME_SIZE) {
                        rx_frames_to_recycle.push_back(addr);
                    } else {
                        // It was a TX allocated frame (forwarding source), return to pool
                        sock_wrapper->release_tx_frame(addr);
                    }
                }
                xsk_ring_cons__release(&umem->cq, completed);

                // Push RX frames back to FQ
                if (!rx_frames_to_recycle.empty()) {
                    if (xsk_ring_prod__reserve(&umem->fq, rx_frames_to_recycle.size(), &idx_fq) == rx_frames_to_recycle.size()) {
                        for (uint64_t addr : rx_frames_to_recycle) {
                            *xsk_ring_prod__fill_addr(&umem->fq, idx_fq++) = addr;
                        }
                        xsk_ring_prod__submit(&umem->fq, rx_frames_to_recycle.size());
                    }
                }
            }

            // 2. RX Processing
            unsigned int rcvd = xsk_ring_cons__peek(&xsk->rx, BATCH_SIZE, &idx_rx);
            if (!rcvd) {
                if (xsk_ring_prod__needs_wakeup(&umem->fq)) {
                     sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
                }
                continue; 
            }

            std::vector<uint64_t> fq_recycle_addrs;
            std::vector<struct xdp_desc> local_tx_batch;
            
            for (unsigned int i = 0; i < rcvd; i++) {
                const struct xdp_desc* desc = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++);
                uint64_t addr = desc->addr;
                uint32_t len = desc->len;
                uint8_t* pkt_data = (uint8_t*)xsk_umem__get_data(umem->buffer, addr);

                pcpp::RawPacket rawPacket(pkt_data, len, timeval{0, 0}, false, pcpp::LINKTYPE_ETHERNET);
                pcpp::Packet packet(&rawPacket);

                pcpp::TcpLayer* tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
                if( tcpLayer && ( tcpLayer->getSrcPort() == 443 || tcpLayer->getDstPort() == 443 ) )
                {
                    // DEBUG: Received HTTPS packet
                    // LOG_DEBUG("AF_XDP", "RX HTTPS Packet len=%u", len);

                    auto tx_packets = ctx.Ssl_Manager.ProcessPacket(&packet, current_interface_xdp_info, other_socket_infos);
                    
                    for (auto& pkt : tx_packets) {
                        if (pkt.target_interface->Tx_sockets.empty()) continue;

                        XskSocket* target_sock = pkt.target_interface->Tx_sockets[0];
                        uint64_t target_addr = target_sock->get_tx_frame();

                        if (target_addr != UINT64_MAX) {
                            uint8_t* target_buf = (uint8_t*)xsk_umem__get_data(target_sock->umem_info->buffer, target_addr);
                            memcpy(target_buf, pkt.raw_data.data(), pkt.raw_data.size());

                            uint32_t tx_idx;
                            auto target_xsk = target_sock->get_sock();
                            if (xsk_ring_prod__reserve(&target_xsk->tx, 1, &tx_idx) == 1) {
                                struct xdp_desc* tx_desc = xsk_ring_prod__tx_desc(&target_xsk->tx, tx_idx);
                                tx_desc->addr = target_addr;
                                tx_desc->len = pkt.raw_data.size();
                                xsk_ring_prod__submit(&target_xsk->tx, 1);
                                
                                // LOG_DEBUG("AF_XDP", "TX HTTPS Packet len=%lu to %s", 
                                //    pkt.raw_data.size(), pkt.target_interface->interface_info.interface.interface_name.c_str());

                                if (xsk_ring_prod__needs_wakeup(&target_xsk->tx)) 
                                    sendto(xsk_socket__fd(target_xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
                            } else {
                                target_sock->release_tx_frame(target_addr);
                            }
                        }
                    }
                    fq_recycle_addrs.push_back(addr); // Drop original
                    continue; 
                }

                {
                    auto* goto_tx = ctx.Nat_Manager.NAT_PROCESSING(&packet, interface_info, other_socket_infos);

                    if (!goto_tx) {
                        // DROP -> recycle RX buffer
                        fq_recycle_addrs.push_back(addr);
                        continue;
                    }

                    // Check Dest Interface
                    if (goto_tx->interface_info.interface.ifindex == interface_info.interface.ifindex) {
                        // [Local TX] Zero-Copy Echo
                        struct xdp_desc d;
                        d.addr = addr;
                        d.len = len; 
                        d.options = 0;
                        local_tx_batch.push_back(d);
                    } 
                    else {
                        // [Remote TX] Forwarding -> Copy to Target UMEM
                        // Assuming using Queue 0 of target for simplicity
                        if (goto_tx->Tx_sockets.empty()) { fq_recycle_addrs.push_back(addr); continue; }
                        
                        XskSocket* target_sock = goto_tx->Tx_sockets[0];
                        uint64_t target_addr = target_sock->get_tx_frame();
                        
                        if (target_addr != UINT64_MAX) {
                            // Copy Data
                            uint8_t* target_buf = (uint8_t*)xsk_umem__get_data(target_sock->umem_info->buffer, target_addr);
                            memcpy(target_buf, pkt_data, len);

                            // Submit to Target Ring
                            uint32_t tx_idx;
                            auto target_xsk = target_sock->get_sock();
                            if (xsk_ring_prod__reserve(&target_xsk->tx, 1, &tx_idx) == 1) {
                                struct xdp_desc* tx_desc = xsk_ring_prod__tx_desc(&target_xsk->tx, tx_idx);
                                tx_desc->addr = target_addr;
                                tx_desc->len = len;
                                xsk_ring_prod__submit(&target_xsk->tx, 1);
                                
                                if (xsk_ring_prod__needs_wakeup(&target_xsk->tx)) 
                                    sendto(xsk_socket__fd(target_xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
                            } else {
                                // Fail to reserve -> Release Buffer
                                target_sock->release_tx_frame(target_addr);
                            }
                        } 
                        // Source buffer is now free (data copied), recycle it
                        fq_recycle_addrs.push_back(addr);
                    }
                }
            }
            xsk_ring_cons__release(&xsk->rx, rcvd);

            // 3. Submit Local TX
            if (!local_tx_batch.empty()) {
                uint32_t idx_tx;
                if (xsk_ring_prod__reserve(&xsk->tx, local_tx_batch.size(), &idx_tx) == local_tx_batch.size()) {
                    for (const auto& desc : local_tx_batch) {
                        *xsk_ring_prod__tx_desc(&xsk->tx, idx_tx++) = desc;
                    }
                    xsk_ring_prod__submit(&xsk->tx, local_tx_batch.size());
                    
                    if (xsk_ring_prod__needs_wakeup(&xsk->tx)) {
                        sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
                    }
                } else {
                    // Ring Full -> Drop and Recycle
                    for(const auto& d : local_tx_batch) fq_recycle_addrs.push_back(d.addr);
                }
            }

            // 4. Recycle RX Buffers to FQ
            if (!fq_recycle_addrs.empty()) {
                uint32_t idx_fq_r;
                if (xsk_ring_prod__reserve(&umem->fq, fq_recycle_addrs.size(), &idx_fq_r) == fq_recycle_addrs.size()) {
                    for (uint64_t addr : fq_recycle_addrs) {
                        *xsk_ring_prod__fill_addr(&umem->fq, idx_fq_r++) = addr;
                    }
                    xsk_ring_prod__submit(&umem->fq, fq_recycle_addrs.size());
                }
            }
        }
    }
};

class AF_XDP_MANAGER
{
public:
    AF_XDP_MANAGER( InterfaceManager& interfaceM ) : interfaceM(interfaceM)
    {
        unsigned int cpu_count = std::thread::hardware_concurrency();
        for(unsigned int i = 0; i < cpu_count; i++ ) CpuWorkers.emplace_back(std::make_unique<CPUWorker>(i));
        for(auto& w : CpuWorkers) w->start();
        _init();
    }
    ~AF_XDP_MANAGER() {
        g_stop = true;
        for(auto& w : CpuWorkers) w->join();
    }
private:
    InterfaceManager& interfaceM;
    std::vector<std::unique_ptr<CPUWorker>> CpuWorkers;
    std::vector<std::unique_ptr<AF_XDP_CONTROLLER>> controllers;
    af_xdp_processing_ctx CTX;
    
    bool _init()
    {
        //test
        CTX.Ssl_Manager.LoadConfig( "/root/VATEX/NDR_SENSOR/Certs/default_sensor_cert.crt", "/root/VATEX/NDR_SENSOR/Certs/default_sensor_private.key" );

        auto interfaces = interfaceM.LOAD_INTERFACES();
        for(auto&[ifindex, info] : interfaces)
        {
            if( info.interface.interface_type == interface_type::lo || info.interface.interface_type == interface_type::UNKNOWN || info.interface.interface_name == "docker0" ) continue;
            controllers.emplace_back(std::make_unique<AF_XDP_CONTROLLER>(info, CpuWorkers, CTX));
        }

        for( auto& controller : controllers)
        {
            std::vector<interface_information_for_XDP> OtherInfos;
            for( auto& otherController : controllers) {
                if( otherController->Get_Interface_with_Socket_Info().interface_info.interface.ifindex == controller->Get_Interface_with_Socket_Info().interface_info.interface.ifindex )
                    continue;
                OtherInfos.push_back(otherController->Get_Interface_with_Socket_Info());
            }
            controller->Add_Other_Interface_with_Socket_Infos(OtherInfos);
            controller->Run();
        }   
        return true;
    }
};

#endif