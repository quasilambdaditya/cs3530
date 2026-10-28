#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "common.h"
#include "meshlink.skel.h"

static volatile sig_atomic_t stop = 0;
static void on_signal(int) { stop = 1; }

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

struct ContainerConfig {
    std::string veth_name;
    std::string ip_str;
    std::string mac_str;
    std::string gw_mac_str;
};

struct PeerConfig {
    std::string remote_subnet;  // e.g. "10.100.2.0"
    uint32_t prefixlen;         // e.g. 24
    std::string local_underlay_ip;
    std::string peer_underlay_ip;
    std::string local_ua0_mac;
    std::string peer_ua0_mac;
    uint32_t peer_id;           // dense index for this peer (0..MAX_PEERS-1)
};

struct TcAttachment {
    bpf_link *tcx_link = nullptr;
    bpf_tc_hook tc_hook{};
    bpf_tc_opts tc_opts{};
    bool is_tc = false;
    bool hook_created = false;

    bool attach(bpf_program *prog, int ifindex) {
        // Try TCX first (kernel >= 6.6, libbpf >= 1.3)
        bpf_program__set_expected_attach_type(prog, BPF_TCX_INGRESS);
        tcx_link = bpf_program__attach_tcx(prog, ifindex, NULL);
        if (tcx_link && !libbpf_get_error(tcx_link)) {
            return true;
        }
        tcx_link = nullptr;

        // Fallback to classic TC clsact hook
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

static uint64_t get_counter_sum(int map_fd, uint32_t key) {
    int ncpus = libbpf_num_possible_cpus();
    if (ncpus <= 0) return 0;
    std::vector<uint64_t> vals(static_cast<size_t>(ncpus), 0);
    if (bpf_map_lookup_elem(map_fd, &key, vals.data()) != 0) {
        return 0;
    }
    uint64_t total = 0;
    for (uint64_t v : vals) total += v;
    return total;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        std::fprintf(stderr, "Usage: %s <vh1|vh2>\n", argv[0]);
        std::fprintf(stderr, "Run inside the host namespace: ip netns exec <vh> %s <vh>\n", argv[0]);
        return 1;
    }

    std::string host_name = argv[1];
    if (host_name != "vh1" && host_name != "vh2") {
        std::fprintf(stderr, "Error: Host must be 'vh1' or 'vh2' (got '%s')\n", host_name.c_str());
        return 1;
    }

    PeerConfig peer_cfg;
    std::vector<ContainerConfig> cont_configs;

    if (host_name == "vh1") {
        peer_cfg = {
            .remote_subnet = "10.100.2.0",
            .prefixlen = 24,
            .local_underlay_ip = "10.10.1.11",
            .peer_underlay_ip = "10.10.1.12",
            .local_ua0_mac = "02:00:0a:0a:01:11",
            .peer_ua0_mac = "02:00:0a:0a:01:12",
            .peer_id = 0,   // vh2 is peer 0 as seen from vh1
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
            .local_underlay_ip = "10.10.1.12",
            .peer_underlay_ip = "10.10.1.11",
            .local_ua0_mac = "02:00:0a:0a:01:12",
            .peer_ua0_mac = "02:00:0a:0a:01:11",
            .peer_id = 0,   // vh1 is peer 0 as seen from vh2
        };
        cont_configs = {
            {"h21", "10.100.2.2", "02:00:0a:64:02:02", "02:00:0a:64:02:01"},
            {"h22", "10.100.2.3", "02:00:0a:64:02:03", "02:00:0a:64:02:01"},
            {"h23", "10.100.2.4", "02:00:0a:64:02:04", "02:00:0a:64:02:01"},
        };
    }

    // Resolve local ua0 interface
    unsigned int ua0_idx = if_nametoindex("ua0");
    if (!ua0_idx) {
        std::perror("if_nametoindex ua0 (are you running in the correct namespace?)");
        return 1;
    }

    // Query actual MAC of ua0 if present, otherwise use configured static MAC
    unsigned char local_ua0_mac[6];
    if (!get_iface_mac("ua0", local_ua0_mac)) {
        parse_mac(peer_cfg.local_ua0_mac.c_str(), local_ua0_mac);
    }
    unsigned char peer_ua0_mac[6];
    parse_mac(peer_cfg.peer_ua0_mac.c_str(), peer_ua0_mac);

    // Open and load BPF skeleton
    meshlink_bpf *skel = meshlink_bpf__open_and_load();
    if (!skel) {
        std::fprintf(stderr, "Failed to open and load meshlink BPF skeleton\n");
        return 1;
    }

    int peer_tbl_fd = bpf_map__fd(skel->maps.peer_tbl);
    int veth_tbl_fd = bpf_map__fd(skel->maps.veth_tbl);
    int event_count_fd = bpf_map__fd(skel->maps.event_count);

    // Populate peer_tbl (Remote Subnet -> Tunnel Metadata)
    struct ipv4_lpm_key pkey{};
    pkey.prefixlen = peer_cfg.prefixlen;
    pkey.addr = inet_addr(peer_cfg.remote_subnet.c_str());

    struct peer_info pinfo{};
    pinfo.local_ip = inet_addr(peer_cfg.local_underlay_ip.c_str());
    pinfo.peer_ip = inet_addr(peer_cfg.peer_underlay_ip.c_str());
    std::memcpy(pinfo.src_mac, local_ua0_mac, 6);
    std::memcpy(pinfo.dst_mac, peer_ua0_mac, 6);
    pinfo.ua0_ifindex = ua0_idx;
    pinfo.peer_id = peer_cfg.peer_id;  // agent assigns a unique index per remote subnet

    if (bpf_map_update_elem(peer_tbl_fd, &pkey, &pinfo, BPF_ANY) != 0) {
        std::perror("bpf_map_update_elem peer_tbl");
        meshlink_bpf__destroy(skel);
        return 1;
    }
    std::printf("[%s] Configured peer route: %s/%u via peer IP %s (ua0 ifindex %u)\n",
            host_name.c_str(), peer_cfg.remote_subnet.c_str(), peer_cfg.prefixlen,
            peer_cfg.peer_underlay_ip.c_str(), ua0_idx);

    // Initialize ctl_map and path_tbl for M3 multipath
    int ctl_map_fd = bpf_map__fd(skel->maps.ctl_map);
    int path_tbl_fd = bpf_map__fd(skel->maps.path_tbl);
    int peer_ip_to_id_fd = bpf_map__fd(skel->maps.peer_ip_to_id);

    // Populate peer_ip_to_id: map peer underlay IP(s) → local peer_id
    // so ingress can identify the sender from the outer source IP.
    {
        uint32_t pip = inet_addr(peer_cfg.peer_underlay_ip.c_str());
        uint32_t pid = peer_cfg.peer_id;
        bpf_map_update_elem(peer_ip_to_id_fd, &pip, &pid, BPF_ANY);
    }

    uint32_t active_ver = 0;
    uint32_t ctl_k = 0;
    bpf_map_update_elem(ctl_map_fd, &ctl_k, &active_ver, BPF_ANY);

    uint32_t peer_id = 0;
    struct path_entry pe_a{};
    pe_a.ifindex = ua0_idx;
    pe_a.src_ip = pinfo.local_ip;
    pe_a.dst_ip = pinfo.peer_ip;
    std::memcpy(pe_a.src_mac, local_ua0_mac, 6);
    std::memcpy(pe_a.dst_mac, peer_ua0_mac, 6);
    pe_a.state = PATH_UP;
    pe_a.path_id = 0;
    pe_a.is_primary = 1;

    for (uint32_t v = 0; v < 2; ++v) {
        uint32_t k = PATH_TBL_KEY(v, peer_id, 0);
        bpf_map_update_elem(path_tbl_fd, &k, &pe_a, BPF_ANY);
    }

    // Check if ub0 (Plane B) exists and initialize path entry
    unsigned int ub0_idx = if_nametoindex("ub0");
    TcAttachment ub0_ingress_attachment;
    if (ub0_idx) {
        unsigned char local_ub0_mac[6]{};
        get_iface_mac("ub0", local_ub0_mac);
        std::string local_b_ip = (host_name == "vh1") ? "10.20.1.11" : "10.20.1.12";
        std::string peer_b_ip  = (host_name == "vh1") ? "10.20.1.12" : "10.20.1.11";

        struct path_entry pe_b{};
        pe_b.ifindex = ub0_idx;
        pe_b.src_ip = inet_addr(local_b_ip.c_str());
        pe_b.dst_ip = inet_addr(peer_b_ip.c_str());
        std::memcpy(pe_b.src_mac, local_ub0_mac, 6);
        std::memcpy(pe_b.dst_mac, peer_ua0_mac, 6); // initial outer peer MAC
        pe_b.state = PATH_UP;
        pe_b.path_id = 1;
        pe_b.is_primary = 0;

        for (uint32_t v = 0; v < 2; ++v) {
            uint32_t k = PATH_TBL_KEY(v, peer_id, 1);
            bpf_map_update_elem(path_tbl_fd, &k, &pe_b, BPF_ANY);
        }

        // Also map peer's Plane B underlay IP → same local peer_id
        {
            uint32_t pb_ip = inet_addr(peer_b_ip.c_str());
            bpf_map_update_elem(peer_ip_to_id_fd, &pb_ip, &peer_id, BPF_ANY);
        }

        if (ub0_ingress_attachment.attach(skel->progs.ingress_decap, ub0_idx)) {
            std::printf("[%s] Attached ingress_decap to ub0 (ifindex %u)\n", host_name.c_str(), ub0_idx);
        }
    }

    // Populate veth_tbl (Local Container IP -> Veth ifindex & MACs)
    std::vector<TcAttachment> egress_attachments;
    for (const auto &cc : cont_configs) {
        unsigned int veth_idx = if_nametoindex(cc.veth_name.c_str());
        if (!veth_idx) {
            std::fprintf(stderr, "Warning: interface %s not found, skipping\n", cc.veth_name.c_str());
            continue;
        }

        struct veth_info vinfo{};
        vinfo.veth_ifindex = veth_idx;
        parse_mac(cc.mac_str.c_str(), vinfo.container_mac);
        parse_mac(cc.gw_mac_str.c_str(), vinfo.gw_mac);

        uint32_t c_ip = inet_addr(cc.ip_str.c_str());
        if (bpf_map_update_elem(veth_tbl_fd, &c_ip, &vinfo, BPF_ANY) != 0) {
            std::fprintf(stderr, "Failed to update veth_tbl for %s: %s\n",
                    cc.ip_str.c_str(), std::strerror(errno));
            continue;
        }

        // Attach egress_encap to the container's host-side veth
        TcAttachment tc_egress;
        if (tc_egress.attach(skel->progs.egress_encap, veth_idx)) {
            egress_attachments.push_back(tc_egress);
            std::printf("[%s] Attached egress_encap to %s (ifindex %u) for container IP %s\n",
                    host_name.c_str(), cc.veth_name.c_str(), veth_idx, cc.ip_str.c_str());
        }
    }

    // Attach ingress_decap to underlay ua0
    TcAttachment ingress_attachment;
    if (!ingress_attachment.attach(skel->progs.ingress_decap, ua0_idx)) {
        std::fprintf(stderr, "Failed to attach ingress_decap to ua0\n");
        for (auto &att : egress_attachments) att.detach();
        if (ub0_idx) ub0_ingress_attachment.detach();
        meshlink_bpf__destroy(skel);
        return 1;
    }
    std::printf("[%s] Attached ingress_decap to ua0 (ifindex %u)\n", host_name.c_str(), ua0_idx);

    // 6. Handle shutdown cleanly
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    std::printf("\n[%s] MeshLink M2/M3 agent active. Press Ctrl-C to detach and exit.\n", host_name.c_str());
    std::printf("%-8s | %-12s %-12s | %-10s %-10s %-10s\n",
            "Host", "Ingress OK", "Egress OK", "No Peer", "No Veth", "Parse Drop");
    std::printf("----------------------------------------------------------------------\n");

    while (!stop) {
        sleep(1);
        uint64_t in_ok = get_counter_sum(event_count_fd, OK_INGRESS);
        uint64_t eg_ok = get_counter_sum(event_count_fd, OK_EGRESS);
        uint64_t drop_peer = get_counter_sum(event_count_fd, DROP_NO_PEER);
        uint64_t drop_veth = get_counter_sum(event_count_fd, DROP_NO_VETH);
        uint64_t drop_parse = get_counter_sum(event_count_fd, DROP_PARSE_FAIL);

        std::printf("%-8s | %-12llu %-12llu | %-10llu %-10llu %-10llu\r",
                host_name.c_str(),
                static_cast<unsigned long long>(in_ok),
                static_cast<unsigned long long>(eg_ok),
                static_cast<unsigned long long>(drop_peer),
                static_cast<unsigned long long>(drop_veth),
                static_cast<unsigned long long>(drop_parse));
        std::fflush(stdout);
    }

    std::printf("\nShutting down and detaching BPF programs...\n");
    ingress_attachment.detach();
    if (ub0_idx) ub0_ingress_attachment.detach();
    for (auto &att : egress_attachments) {
        att.detach();
    }
    meshlink_bpf__destroy(skel);
    std::printf("Clean shutdown complete.\n");

    return 0;
}
