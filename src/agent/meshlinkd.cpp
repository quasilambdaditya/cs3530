#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <sched.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "common.h"
#include "meshlink.skel.h"

#ifndef IFF_LOWER_UP
#define IFF_LOWER_UP 0x10000
#endif

static std::atomic<bool> g_stop{false};
static void on_signal(int) { g_stop = true; }

struct ContainerConfig {
    std::string veth_name;
    std::string ip_str;
    std::string mac_str;
    std::string gw_mac_str;
};

struct PeerConfig {
    std::string remote_subnet;      // e.g. "10.100.2.0"
    uint32_t prefixlen;             // e.g. 24
    std::string local_underlay_a;   // e.g. "10.10.1.11"
    std::string peer_underlay_a;    // e.g. "10.10.1.12"
    std::string local_underlay_b;   // e.g. "10.20.1.11"
    std::string peer_underlay_b;    // e.g. "10.20.1.12"
    std::string local_ua0_mac;
    std::string peer_ua0_mac;
    std::string local_ub0_mac;
    std::string peer_ub0_mac;
    uint32_t peer_id;               // 0..MAX_PEERS-1
};

struct PathHealth {
    bool carrier_up = true;
    uint32_t state = PATH_UP;       // PATH_UP, PATH_DEGRADED, PATH_DOWN
    double loss_rate = 0.0;
    uint32_t consecutive_misses = 0;
    uint32_t consecutive_healthy = 0;
    uint64_t last_rx_pkts = 0;
    uint64_t last_lost_pkts = 0;
};

static bool parse_mac(const char *str, unsigned char mac[6]) {
    return std::sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                       &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6;
}

static bool get_iface_mac(const char *ifname, unsigned char mac[6]) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return false;
    struct ifreq ifr{};
    std::strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        close(fd);
        return false;
    }
    close(fd);
    std::memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    return true;
}

static bool switch_netns(const std::string &ns_name) {
    std::string path = "/var/run/netns/" + ns_name;
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) {
        std::fprintf(stderr, "Could not open netns %s: %s\n", path.c_str(), std::strerror(errno));
        return false;
    }
    if (setns(fd, CLONE_NEWNET) != 0) {
        std::fprintf(stderr, "setns failed for %s: %s\n", ns_name.c_str(), std::strerror(errno));
        close(fd);
        return false;
    }
    close(fd);
    std::printf("[meshlinkd] Switched to network namespace '%s'\n", ns_name.c_str());
    return true;
}

struct TcAttachment {
    bpf_link *tcx_link = nullptr;
    bpf_tc_hook tc_hook{};
    bpf_tc_opts tc_opts{};
    bool is_tc = false;
    bool hook_created = false;

    bool attach(bpf_program *prog, int ifindex) {
        bpf_program__set_expected_attach_type(prog, BPF_TCX_INGRESS);
        tcx_link = bpf_program__attach_tcx(prog, ifindex, NULL);
        if (tcx_link && !libbpf_get_error(tcx_link)) {
            return true;
        }
        tcx_link = nullptr;

        tc_hook.sz = sizeof(tc_hook);
        tc_hook.ifindex = ifindex;
        tc_hook.attach_point = BPF_TC_INGRESS;
        int err = bpf_tc_hook_create(&tc_hook);
        if (err == 0) hook_created = true;
        else if (err != -EEXIST) {
            std::fprintf(stderr, "bpf_tc_hook_create failed for ifindex %d: %s\n",
                         ifindex, std::strerror(-err));
            return false;
        }

        tc_opts.sz = sizeof(tc_opts);
        tc_opts.prog_fd = bpf_program__fd(prog);
        tc_opts.handle = 1;
        tc_opts.priority = 1;
        err = bpf_tc_attach(&tc_hook, &tc_opts);
        if (err) {
            std::fprintf(stderr, "bpf_tc_attach failed for ifindex %d: %s\n",
                         ifindex, std::strerror(-err));
            if (hook_created) bpf_tc_hook_destroy(&tc_hook);
            return false;
        }
        is_tc = true;
        return true;
    }

    void detach() {
        if (tcx_link) {
            bpf_link__destroy(tcx_link);
            tcx_link = nullptr;
        }
        if (is_tc) {
            tc_opts.prog_fd = 0;
            bpf_tc_detach(&tc_hook, &tc_opts);
            if (hook_created) bpf_tc_hook_destroy(&tc_hook);
            is_tc = false;
        }
    }
};


class MeshlinkDaemon {
public:
    MeshlinkDaemon(const std::string &host_name,
                   const PeerConfig &peer_cfg,
                   const std::vector<ContainerConfig> &cont_cfgs)
        : host_name_(host_name), peer_cfg_(peer_cfg), cont_cfgs_(cont_cfgs) {}

    ~MeshlinkDaemon() {
        stop();
    }

    bool init() {
        // Resolve interfaces
        ua0_idx_ = if_nametoindex("ua0");
        if (!ua0_idx_) {
            std::fprintf(stderr, "Failed to resolve ua0 in namespace\n");
            return false;
        }
        ub0_idx_ = if_nametoindex("ub0");

        // Parse MAC addresses
        if (!get_iface_mac("ua0", local_ua0_mac_)) {
            parse_mac(peer_cfg_.local_ua0_mac.c_str(), local_ua0_mac_);
        }
        parse_mac(peer_cfg_.peer_ua0_mac.c_str(), peer_ua0_mac_);

        if (ub0_idx_) {
            if (!get_iface_mac("ub0", local_ub0_mac_)) {
                parse_mac(peer_cfg_.local_ub0_mac.c_str(), local_ub0_mac_);
            }
            parse_mac(peer_cfg_.peer_ub0_mac.c_str(), peer_ub0_mac_);
        }

        // Open and load BPF skeleton
        skel_ = meshlink_bpf__open_and_load();
        if (!skel_) {
            std::fprintf(stderr, "Failed to open and load meshlink BPF skeleton\n");
            return false;
        }

        // Map FDs
        peer_tbl_fd_ = bpf_map__fd(skel_->maps.peer_tbl);
        veth_tbl_fd_ = bpf_map__fd(skel_->maps.veth_tbl);
        ctl_map_fd_ = bpf_map__fd(skel_->maps.ctl_map);
        path_tbl_fd_ = bpf_map__fd(skel_->maps.path_tbl);
        stats_path_fd_ = bpf_map__fd(skel_->maps.stats_path);
        peer_ip_to_id_fd_ = bpf_map__fd(skel_->maps.peer_ip_to_id);
        event_count_fd_ = bpf_map__fd(skel_->maps.event_count);

        // 1. Populate peer_tbl
        struct ipv4_lpm_key pkey{};
        pkey.prefixlen = peer_cfg_.prefixlen;
        pkey.addr = inet_addr(peer_cfg_.remote_subnet.c_str());

        struct peer_info pinfo{};
        pinfo.local_ip = inet_addr(peer_cfg_.local_underlay_a.c_str());
        pinfo.peer_ip = inet_addr(peer_cfg_.peer_underlay_a.c_str());
        std::memcpy(pinfo.src_mac, local_ua0_mac_, 6);
        std::memcpy(pinfo.dst_mac, peer_ua0_mac_, 6);
        pinfo.ua0_ifindex = ua0_idx_;
        pinfo.peer_id = peer_cfg_.peer_id;

        bpf_map_update_elem(peer_tbl_fd_, &pkey, &pinfo, BPF_ANY);

        // 2. Populate peer_ip_to_id
        uint32_t pip_a = inet_addr(peer_cfg_.peer_underlay_a.c_str());
        uint32_t pid = peer_cfg_.peer_id;
        bpf_map_update_elem(peer_ip_to_id_fd_, &pip_a, &pid, BPF_ANY);

        if (ub0_idx_) {
            uint32_t pip_b = inet_addr(peer_cfg_.peer_underlay_b.c_str());
            bpf_map_update_elem(peer_ip_to_id_fd_, &pip_b, &pid, BPF_ANY);
        }

        // 3. Populate path_tbl (both slots version 0 and 1)
        active_ver_ = 0;
        uint32_t ctl_k = 0;
        bpf_map_update_elem(ctl_map_fd_, &ctl_k, &active_ver_, BPF_ANY);

        // Setup initial paths
        path_health_[0].state = PATH_UP;
        path_health_[0].carrier_up = true;
        path_health_[1].state = ub0_idx_ ? PATH_UP : PATH_DOWN;
        path_health_[1].carrier_up = (ub0_idx_ != 0);

        write_path_table_version(0, 0 /* primary path: 0 */);
        write_path_table_version(1, 0 /* primary path: 0 */);

        // 4. Attach container egress
        for (const auto &cc : cont_cfgs_) {
            unsigned int veth_idx = if_nametoindex(cc.veth_name.c_str());
            if (!veth_idx) continue;

            struct veth_info vinfo{};
            vinfo.veth_ifindex = veth_idx;
            parse_mac(cc.mac_str.c_str(), vinfo.container_mac);
            parse_mac(cc.gw_mac_str.c_str(), vinfo.gw_mac);

            uint32_t c_ip = inet_addr(cc.ip_str.c_str());
            bpf_map_update_elem(veth_tbl_fd_, &c_ip, &vinfo, BPF_ANY);

            TcAttachment egress_att;
            if (egress_att.attach(skel_->progs.egress_encap, veth_idx)) {
                egress_attachments_.push_back(egress_att);
                std::printf("[%s] Attached egress_encap to %s (ifindex %u)\n",
                            host_name_.c_str(), cc.veth_name.c_str(), veth_idx);
            }
        }

        // 5. Attach underlay ingress
        if (!ua0_ingress_att_.attach(skel_->progs.ingress_decap, ua0_idx_)) {
            std::fprintf(stderr, "Failed to attach ingress_decap to ua0\n");
            return false;
        }
        std::printf("[%s] Attached ingress_decap to ua0 (ifindex %u)\n", host_name_.c_str(), ua0_idx_);

        if (ub0_idx_) {
            if (ub0_ingress_att_.attach(skel_->progs.ingress_decap, ub0_idx_)) {
                std::printf("[%s] Attached ingress_decap to ub0 (ifindex %u)\n", host_name_.c_str(), ub0_idx_);
            }
        }

        return true;
    }

    void start() {
        std::printf("[%s] Starting meshlinkd control plane daemon...\n", host_name_.c_str());
        netlink_thread_ = std::thread(&MeshlinkDaemon::netlink_monitor_loop, this);
        telemetry_thread_ = std::thread(&MeshlinkDaemon::telemetry_loop, this);
        prober_thread_ = std::thread(&MeshlinkDaemon::prober_loop, this);
    }

    void wait() {
        if (netlink_thread_.joinable()) netlink_thread_.join();
        if (telemetry_thread_.joinable()) telemetry_thread_.join();
        if (prober_thread_.joinable()) prober_thread_.join();
    }

    void stop() {
        g_stop = true;
        if (netlink_thread_.joinable()) netlink_thread_.join();
        if (telemetry_thread_.joinable()) telemetry_thread_.join();
        if (prober_thread_.joinable()) prober_thread_.join();

        ua0_ingress_att_.detach();
        if (ub0_idx_) ub0_ingress_att_.detach();
        for (auto &att : egress_attachments_) att.detach();
        egress_attachments_.clear();

        if (skel_) {
            meshlink_bpf__destroy(skel_);
            skel_ = nullptr;
        }
    }

private:
    void write_path_table_version(uint32_t ver, uint32_t primary_path) {
        uint32_t pid = peer_cfg_.peer_id;

        // Path 0 (Plane A)
        struct path_entry pe_a{};
        pe_a.ifindex = ua0_idx_;
        pe_a.src_ip = inet_addr(peer_cfg_.local_underlay_a.c_str());
        pe_a.dst_ip = inet_addr(peer_cfg_.peer_underlay_a.c_str());
        std::memcpy(pe_a.src_mac, local_ua0_mac_, 6);
        std::memcpy(pe_a.dst_mac, peer_ua0_mac_, 6);
        pe_a.state = path_health_[0].state;
        pe_a.path_id = 0;
        pe_a.is_primary = (primary_path == 0) ? 1 : 0;

        uint32_t key_a = PATH_TBL_KEY(ver, pid, 0);
        bpf_map_update_elem(path_tbl_fd_, &key_a, &pe_a, BPF_ANY);

        // Path 1 (Plane B)
        if (ub0_idx_) {
            struct path_entry pe_b{};
            pe_b.ifindex = ub0_idx_;
            pe_b.src_ip = inet_addr(peer_cfg_.local_underlay_b.c_str());
            pe_b.dst_ip = inet_addr(peer_cfg_.peer_underlay_b.c_str());
            std::memcpy(pe_b.src_mac, local_ub0_mac_, 6);
            std::memcpy(pe_b.dst_mac, peer_ub0_mac_, 6);
            pe_b.state = path_health_[1].state;
            pe_b.path_id = 1;
            pe_b.is_primary = (primary_path == 1) ? 1 : 0;

            uint32_t key_b = PATH_TBL_KEY(ver, pid, 1);
            bpf_map_update_elem(path_tbl_fd_, &key_b, &pe_b, BPF_ANY);
        }
    }

    void evaluate_and_failover(const char *reason) {
        std::lock_guard<std::mutex> lock(sync_mutex_);

        // Determine health state of Path 0
        if (!path_health_[0].carrier_up || path_health_[0].consecutive_misses >= 3) {
            path_health_[0].state = PATH_DOWN;
            path_health_[0].consecutive_healthy = 0;
        } else if (path_health_[0].loss_rate > 0.05) {
            path_health_[0].state = PATH_DEGRADED;
            path_health_[0].consecutive_healthy = 0;
        } else {
            path_health_[0].consecutive_healthy++;
            if (path_health_[0].consecutive_healthy >= 3) {
                path_health_[0].state = PATH_UP;
            }
        }

        // Determine health state of Path 1
        if (ub0_idx_) {
            if (!path_health_[1].carrier_up || path_health_[1].consecutive_misses >= 3) {
                path_health_[1].state = PATH_DOWN;
                path_health_[1].consecutive_healthy = 0;
            } else if (path_health_[1].loss_rate > 0.05) {
                path_health_[1].state = PATH_DEGRADED;
                path_health_[1].consecutive_healthy = 0;
            } else {
                path_health_[1].consecutive_healthy++;
                if (path_health_[1].consecutive_healthy >= 3) {
                    path_health_[1].state = PATH_UP;
                }
            }
        } else {
            path_health_[1].state = PATH_DOWN;
        }

        // Decision logic
        uint32_t new_primary = current_primary_;
        if (path_health_[0].state == PATH_UP) {
            new_primary = 0; // Prefer Plane A when UP
        } else if (path_health_[1].state == PATH_UP) {
            new_primary = 1; // Switch to Plane B if Plane A down/degraded
        } else if (path_health_[0].state == PATH_DEGRADED && path_health_[1].state == PATH_DOWN) {
            new_primary = 0;
        } else if (path_health_[1].state == PATH_DEGRADED) {
            new_primary = 1;
        }

        if (new_primary != current_primary_ ||
            path_health_[0].state != last_published_state_[0] ||
            path_health_[1].state != last_published_state_[1]) {

            std::printf("\n[DecisionEngine] Trigger: %s | Primary: Path %u -> %u | "
                        "P0 state: %u, P1 state: %u\n",
                        reason, current_primary_, new_primary,
                        path_health_[0].state, path_health_[1].state);

            // Double-buffered RCU-style atomic flip
            uint32_t inactive_ver = 1 - (active_ver_ & 1);
            write_path_table_version(inactive_ver, new_primary);

            uint32_t ctl_k = 0;
            bpf_map_update_elem(ctl_map_fd_, &ctl_k, &inactive_ver, BPF_ANY);
            active_ver_ = inactive_ver;

            // Mirror to active version
            write_path_table_version(active_ver_, new_primary);

            current_primary_ = new_primary;
            last_published_state_[0] = path_health_[0].state;
            last_published_state_[1] = path_health_[1].state;
        }
    }

    void netlink_monitor_loop() {
        int nl_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
        if (nl_fd < 0) {
            std::perror("netlink socket");
            return;
        }

        sockaddr_nl sa{};
        sa.nl_family = AF_NETLINK;
        sa.nl_groups = RTMGRP_LINK;
        if (bind(nl_fd, reinterpret_cast<sockaddr *>(&sa), sizeof(sa)) < 0) {
            std::perror("netlink bind");
            close(nl_fd);
            return;
        }

        // Set non-blocking with select / timeout
        char buf[4096];
        while (!g_stop) {
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(nl_fd, &rfds);
            struct timeval tv{0, 200000}; // 200ms

            int ret = select(nl_fd + 1, &rfds, nullptr, nullptr, &tv);
            if (ret <= 0) continue;

            ssize_t len = recv(nl_fd, buf, sizeof(buf), 0);
            if (len <= 0) continue;

            bool change = false;
            for (auto *nh = reinterpret_cast<struct nlmsghdr *>(buf);
                 NLMSG_OK(nh, static_cast<size_t>(len));
                 nh = NLMSG_NEXT(nh, len)) {

                if (nh->nlmsg_type == NLMSG_DONE) break;
                if (nh->nlmsg_type != RTM_NEWLINK) continue;

                auto *ifi = reinterpret_cast<struct ifinfomsg *>(NLMSG_DATA(nh));
                unsigned int ifidx = static_cast<unsigned int>(ifi->ifi_index);
                bool carrier_up = (ifi->ifi_flags & IFF_UP) &&
                                  (ifi->ifi_flags & IFF_RUNNING) &&
                                  (ifi->ifi_flags & IFF_LOWER_UP);

                if (ifidx == ua0_idx_) {
                    if (path_health_[0].carrier_up != carrier_up) {
                        path_health_[0].carrier_up = carrier_up;
                        change = true;
                    }
                } else if (ub0_idx_ && ifidx == ub0_idx_) {
                    if (path_health_[1].carrier_up != carrier_up) {
                        path_health_[1].carrier_up = carrier_up;
                        change = true;
                    }
                }
            }

            if (change) {
                evaluate_and_failover("Netlink Link Carrier Event");
            }
        }

        close(nl_fd);
    }

    void telemetry_loop() {
        int ncpus = libbpf_num_possible_cpus();
        if (ncpus <= 0) ncpus = 1;
        std::vector<struct path_stats> stats_buf(ncpus);

        while (!g_stop) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));

            for (uint32_t p = 0; p < (ub0_idx_ ? 2u : 1u); ++p) {
                uint32_t k = PATH_KEY(peer_cfg_.peer_id, p);
                if (bpf_map_lookup_elem(stats_path_fd_, &k, stats_buf.data()) == 0) {
                    uint64_t total_rx = 0;
                    uint64_t total_lost = 0;
                    for (const auto &s : stats_buf) {
                        total_rx += s.rx_packets;
                        total_lost += s.seq_lost_pkts;
                    }

                    uint64_t d_rx = total_rx - path_health_[p].last_rx_pkts;
                    uint64_t d_lost = total_lost - path_health_[p].last_lost_pkts;
                    path_health_[p].last_rx_pkts = total_rx;
                    path_health_[p].last_lost_pkts = total_lost;

                    if (d_rx + d_lost > 20) {
                        path_health_[p].loss_rate = static_cast<double>(d_lost) / (d_rx + d_lost);
                    } else {
                        path_health_[p].loss_rate = 0.0;
                    }
                }
            }

            evaluate_and_failover("Telemetry Periodic Tick");
        }
    }

    void prober_loop() {
        // Lightweight prober interval
        while (!g_stop) {
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
            // In a full environment, probe packets are sent/echoed via UDP port 6082.
            // For synthetic health check, we keep consecutive_misses at 0 unless carrier down.
            for (uint32_t p = 0; p < 2; ++p) {
                if (!path_health_[p].carrier_up) {
                    path_health_[p].consecutive_misses++;
                } else {
                    path_health_[p].consecutive_misses = 0;
                }
            }
        }
    }

    std::string host_name_;
    PeerConfig peer_cfg_;
    std::vector<ContainerConfig> cont_cfgs_;

    unsigned int ua0_idx_ = 0;
    unsigned int ub0_idx_ = 0;
    unsigned char local_ua0_mac_[6]{};
    unsigned char peer_ua0_mac_[6]{};
    unsigned char local_ub0_mac_[6]{};
    unsigned char peer_ub0_mac_[6]{};

    meshlink_bpf *skel_ = nullptr;
    int peer_tbl_fd_ = -1;
    int veth_tbl_fd_ = -1;
    int ctl_map_fd_ = -1;
    int path_tbl_fd_ = -1;
    int stats_path_fd_ = -1;
    int peer_ip_to_id_fd_ = -1;
    int event_count_fd_ = -1;

    uint32_t active_ver_ = 0;
    uint32_t current_primary_ = 0;
    uint32_t last_published_state_[2] = {PATH_UP, PATH_UP};
    PathHealth path_health_[2];

    std::mutex sync_mutex_;
    std::thread netlink_thread_;
    std::thread telemetry_thread_;
    std::thread prober_thread_;

    TcAttachment ua0_ingress_att_;
    TcAttachment ub0_ingress_att_;
    std::vector<TcAttachment> egress_attachments_;
};

int main(int argc, char **argv) {
    std::string host_name = "vh1";
    std::string ns_name = "";

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--netns" && i + 1 < argc) {
            ns_name = argv[++i];
        } else if (arg == "vh1" || arg == "vh2") {
            host_name = arg;
        } else {
            std::fprintf(stderr, "Usage: %s [vh1|vh2] [--netns <name>]\n", argv[0]);
            return 1;
        }
    }

    if (ns_name.empty()) {
        ns_name = host_name; // Default to host_name as netns name if not already inside
    }

    // Attempt namespace switch if /var/run/netns/<ns> exists
    std::string ns_path = "/var/run/netns/" + ns_name;
    if (access(ns_path.c_str(), R_OK) == 0) {
        if (!switch_netns(ns_name)) {
            return 1;
        }
    }

    PeerConfig peer_cfg;
    std::vector<ContainerConfig> cont_configs;

    if (host_name == "vh1") {
        peer_cfg = {
            .remote_subnet = "10.100.2.0",
            .prefixlen = 24,
            .local_underlay_a = "10.10.1.11",
            .peer_underlay_a = "10.10.1.12",
            .local_underlay_b = "10.20.1.11",
            .peer_underlay_b = "10.20.1.12",
            .local_ua0_mac = "02:00:0a:0a:01:11",
            .peer_ua0_mac = "02:00:0a:0a:01:12",
            .local_ub0_mac = "02:00:0a:14:01:11",
            .peer_ub0_mac = "02:00:0a:14:01:12",
            .peer_id = 0,
        };
        cont_configs = {
            {"h11", "10.100.1.2", "02:00:0a:64:01:02", "02:00:0a:64:01:01"},
            {"h12", "10.100.1.3", "02:00:0a:64:01:03", "02:00:0a:64:01:01"},
            {"h13", "10.100.1.4", "02:00:0a:64:01:04", "02:00:0a:64:01:01"},
        };
    } else {
        peer_cfg = {
            .remote_subnet = "10.100.1.0",
            .prefixlen = 24,
            .local_underlay_a = "10.10.1.12",
            .peer_underlay_a = "10.10.1.11",
            .local_underlay_b = "10.20.1.12",
            .peer_underlay_b = "10.20.1.11",
            .local_ua0_mac = "02:00:0a:0a:01:12",
            .peer_ua0_mac = "02:00:0a:0a:01:11",
            .local_ub0_mac = "02:00:0a:14:01:12",
            .peer_ub0_mac = "02:00:0a:14:01:11",
            .peer_id = 0,
        };
        cont_configs = {
            {"h21", "10.100.2.2", "02:00:0a:64:02:02", "02:00:0a:64:02:01"},
            {"h22", "10.100.2.3", "02:00:0a:64:02:03", "02:00:0a:64:02:01"},
            {"h23", "10.100.2.4", "02:00:0a:64:02:04", "02:00:0a:64:02:01"},
        };
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    MeshlinkDaemon daemon(host_name, peer_cfg, cont_configs);
    if (!daemon.init()) {
        std::fprintf(stderr, "Failed to initialize MeshlinkDaemon\n");
        return 1;
    }

    daemon.start();

    std::printf("[meshlinkd] Running on %s. Press Ctrl-C to terminate.\n", host_name.c_str());
    while (!g_stop) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    std::printf("\n[meshlinkd] Shutting down...\n");
    daemon.stop();
    std::printf("[meshlinkd] Clean exit.\n");

    return 0;
}
