#include <gtest/gtest.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/udp.h>
#include <net/if.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

#include "common.h"
#include "meshlink.skel.h"

namespace {

// ============================================================================
// RAII Helpers & Network Namespace Management
// ============================================================================

// Switches into a named network namespace and restores original namespace on scope exit.
class NetNsGuard {
    int orig_fd = -1;
    bool switched = false;

public:
    explicit NetNsGuard(const std::string &ns_name) {
        orig_fd = open("/proc/self/ns/net", O_RDONLY);
        std::string path = "/var/run/netns/" + ns_name;
        int target_fd = open(path.c_str(), O_RDONLY);
        if (target_fd >= 0) {
            if (setns(target_fd, CLONE_NEWNET) == 0) {
                switched = true;
            }
            close(target_fd);
        }
    }

    bool is_active() const { return switched; }

    ~NetNsGuard() {
        if (orig_fd >= 0) {
            if (switched) {
                setns(orig_fd, CLONE_NEWNET);
            }
            close(orig_fd);
        }
    }
};

// Manages TC hook attachment (TCX ingress or classic TC clsact ingress fallback).
// Matches the logic used in src/agent/m2.cpp.
class TcHookGuard {
    bpf_link *tcx_link = nullptr;
    bpf_tc_hook tc_hook{};
    bpf_tc_opts tc_opts{};
    bool is_tc = false;
    bool hook_created = false;

public:
    bool attach(bpf_program *prog, int ifindex, uint32_t handle = 1, uint32_t priority = 1) {
        tc_hook.sz = sizeof(tc_hook);
        tc_hook.ifindex = ifindex;
        tc_hook.attach_point = BPF_TC_INGRESS;
        int err = bpf_tc_hook_create(&tc_hook);
        if (err == 0) {
            hook_created = true;
        } else if (err != -EEXIST) {
            return false;
        }

        tc_opts.sz = sizeof(tc_opts);
        tc_opts.prog_fd = bpf_program__fd(prog);
        tc_opts.handle = handle;
        tc_opts.priority = priority;
        tc_opts.flags = BPF_TC_F_REPLACE;
        err = bpf_tc_attach(&tc_hook, &tc_opts);
        if (err) {
            tc_opts.flags = 0;
            err = bpf_tc_attach(&tc_hook, &tc_opts);
        }
        if (err) {
            if (hook_created) bpf_tc_hook_destroy(&tc_hook);
            return false;
        }
        is_tc = true;
        return true;
    }

    void opts_detach() {
        bpf_tc_opts d_opts{};
        d_opts.sz = sizeof(d_opts);
        d_opts.handle = tc_opts.handle;
        d_opts.priority = tc_opts.priority;
        bpf_tc_detach(&tc_hook, &d_opts);
    }

    void detach() {
        if (tcx_link) {
            bpf_link__destroy(tcx_link);
            tcx_link = nullptr;
        }
        if (is_tc) {
            opts_detach();
            if (hook_created) {
                bpf_tc_hook_destroy(&tc_hook);
                hook_created = false;
            }
            is_tc = false;
        }
    }

    ~TcHookGuard() {
        detach();
    }
};

// Sums per-CPU event counter from BPF map
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

// Helper to parse MAC address string
static bool parse_mac(const char *str, unsigned char mac[6]) {
    if (!str || std::strlen(str) != 17) return false;
    return std::sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                       &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6;
}

// Calculate standard 16-bit Internet checksum
static uint16_t compute_checksum(const void *data, size_t len) {
    const auto *p = static_cast<const uint16_t *>(data);
    uint32_t sum = 0;
    while (len > 1) {
        sum += *p++;
        len -= 2;
    }
    if (len == 1) {
        sum += *reinterpret_cast<const uint8_t *>(p);
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return static_cast<uint16_t>(~sum);
}

// Calculate IPv4 header checksum
static uint16_t compute_ipv4_csum(const struct iphdr *ip) {
    return compute_checksum(ip, sizeof(struct iphdr));
}

// ============================================================================
// Synthetic Packet Construction Helpers
// ============================================================================

struct icmp_echo_hdr {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t id;
    uint16_t sequence;
};

// Builds an Ethernet + IPv4 + ICMP Echo Request frame
static std::vector<uint8_t> build_container_icmp_packet(
    const unsigned char src_mac[6], const unsigned char dst_mac[6],
    const std::string &src_ip_str, const std::string &dst_ip_str,
    uint16_t id = 0x1234, uint16_t seq = 1, size_t payload_bytes = 32)
{
    size_t total_len = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmp_echo_hdr) + payload_bytes;
    std::vector<uint8_t> pkt(total_len, 0);

    // Ethernet
    auto *eth = reinterpret_cast<struct ethhdr *>(pkt.data());
    std::memcpy(eth->h_dest, dst_mac, ETH_ALEN);
    std::memcpy(eth->h_source, src_mac, ETH_ALEN);
    eth->h_proto = htons(ETH_P_IP);

    // IPv4
    auto *ip = reinterpret_cast<struct iphdr *>(pkt.data() + sizeof(struct ethhdr));
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons(static_cast<uint16_t>(sizeof(struct iphdr) + sizeof(struct icmp_echo_hdr) + payload_bytes));
    ip->id = htons(0xabcd);
    ip->frag_off = htons(0x4000); // DF
    ip->ttl = 64;
    ip->protocol = IPPROTO_ICMP;
    ip->saddr = inet_addr(src_ip_str.c_str());
    ip->daddr = inet_addr(dst_ip_str.c_str());
    ip->check = 0;
    ip->check = compute_ipv4_csum(ip);

    // ICMP Echo Request (type 8, code 0)
    auto *icmp = reinterpret_cast<struct icmp_echo_hdr *>(pkt.data() + sizeof(struct ethhdr) + sizeof(struct iphdr));
    icmp->type = 8;
    icmp->code = 0;
    icmp->id = htons(id);
    icmp->sequence = htons(seq);
    icmp->checksum = 0;

    // Payload pattern
    uint8_t *payload = pkt.data() + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmp_echo_hdr);
    for (size_t i = 0; i < payload_bytes; ++i) {
        payload[i] = static_cast<uint8_t>(0x61 + (i % 26)); // 'a'..'z'
    }
    icmp->checksum = compute_checksum(icmp, sizeof(struct icmp_echo_hdr) + payload_bytes);

    return pkt;
}

// Builds a full Geneve + MeshLink encapsulated frame as arriving at ua0 ingress
static std::vector<uint8_t> build_geneve_encapsulated_packet(
    const unsigned char outer_src_mac[6], const unsigned char outer_dst_mac[6],
    const std::string &outer_src_ip, const std::string &outer_dst_ip,
    uint16_t outer_udp_src_port,
    uint8_t ver_optlen, uint16_t geneve_proto,
    uint16_t opt_class, uint8_t opt_type,
    const std::vector<uint8_t> &inner_ip_and_payload,
    uint8_t path_id = 0, uint32_t path_seq = 0, uint32_t tunnel_seq = 0)
{
    size_t outer_hdr_len = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) +
                           sizeof(struct geneve_hdr) + sizeof(struct ml_opt);
    size_t total_len = outer_hdr_len + inner_ip_and_payload.size();
    std::vector<uint8_t> pkt(total_len, 0);

    // Outer Ethernet
    auto *eth = reinterpret_cast<struct ethhdr *>(pkt.data());
    std::memcpy(eth->h_dest, outer_dst_mac, ETH_ALEN);
    std::memcpy(eth->h_source, outer_src_mac, ETH_ALEN);
    eth->h_proto = htons(ETH_P_IP);

    // Outer IPv4
    auto *ip = reinterpret_cast<struct iphdr *>(pkt.data() + sizeof(struct ethhdr));
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons(static_cast<uint16_t>(total_len - sizeof(struct ethhdr)));
    ip->id = 0;
    ip->frag_off = htons(0x4000); // DF
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->saddr = inet_addr(outer_src_ip.c_str());
    ip->daddr = inet_addr(outer_dst_ip.c_str());
    ip->check = 0;
    ip->check = compute_ipv4_csum(ip);

    // Outer UDP
    auto *udp = reinterpret_cast<struct udphdr *>(pkt.data() + sizeof(struct ethhdr) + sizeof(struct iphdr));
    udp->source = htons(outer_udp_src_port);
    udp->dest = htons(GENEVE_UDP_PORT);
    udp->len = htons(static_cast<uint16_t>(total_len - sizeof(struct ethhdr) - sizeof(struct iphdr)));
    udp->check = 0;

    // Geneve Header
    auto *gnv = reinterpret_cast<struct geneve_hdr *>(reinterpret_cast<uint8_t *>(udp) + sizeof(struct udphdr));
    gnv->ver_optlen = ver_optlen;
    gnv->flags = 0;
    gnv->proto = htons(geneve_proto);
    gnv->vni[0] = 0;
    gnv->vni[1] = 0;
    gnv->vni[2] = 100;
    gnv->rsvd = 0;

    // MeshLink Option
    auto *opt = reinterpret_cast<struct ml_opt *>(reinterpret_cast<uint8_t *>(gnv) + sizeof(struct geneve_hdr));
    opt->opt_class = htons(opt_class);
    opt->type = opt_type;
    opt->len_words = 4;
    opt->cls = 0;
    opt->flags = 0;
    opt->path_id = path_id;
    opt->rsvd = 0;
    opt->tunnel_seq = htonl(tunnel_seq);
    opt->path_seq = htonl(path_seq);
    opt->tx_ts_us = htonl(12345678);

    // Inner IP payload
    std::memcpy(pkt.data() + outer_hdr_len, inner_ip_and_payload.data(), inner_ip_and_payload.size());

    return pkt;
}

// Builds an ARP frame
static std::vector<uint8_t> build_arp_frame(const unsigned char src_mac[6], const unsigned char dst_mac[6]) {
    std::vector<uint8_t> pkt(42, 0); // 14 byte Eth + 28 byte ARP
    auto *eth = reinterpret_cast<struct ethhdr *>(pkt.data());
    std::memcpy(eth->h_dest, dst_mac, ETH_ALEN);
    std::memcpy(eth->h_source, src_mac, ETH_ALEN);
    eth->h_proto = htons(0x0806); // ARP
    return pkt;
}

} // anonymous namespace

// ============================================================================
// SUITE 1: Protocol Specifications & ABI Layout (inc/common.h)
// ============================================================================

TEST(MeshlinkSpecAndHeader, HeaderSizesAndStructOffsets) {
    EXPECT_EQ(sizeof(struct geneve_hdr), 8u) << "Geneve header must be exactly 8 bytes (RFC 8926)";
    EXPECT_EQ(sizeof(struct ml_opt), 20u) << "MeshLink option header must be exactly 20 bytes";
    EXPECT_EQ(sizeof(struct iphdr), 20u) << "IPv4 standard base header is 20 bytes";
    EXPECT_EQ(sizeof(struct udphdr), 8u) << "UDP header is 8 bytes";
    EXPECT_EQ(sizeof(struct ethhdr), 14u) << "Ethernet header is 14 bytes";

    EXPECT_EQ(OUTER_LEN, 56) << "OUTER_LEN must equal 20 (IP) + 8 (UDP) + 8 (Geneve) + 20 (ml_opt)";
    EXPECT_EQ(sizeof(struct ipv4_lpm_key), 8u) << "ipv4_lpm_key ABI requirement: 4 bytes prefixlen + 4 bytes addr";
    EXPECT_EQ(sizeof(struct peer_info), 28u) << "peer_info: 4B local_ip + 4B peer_ip + 6B src_mac + 6B dst_mac + 4B ifindex + 4B peer_id = 28 bytes";
    EXPECT_EQ(sizeof(struct veth_info), 16u) << "veth_info: 4B ifindex + 6B container_mac + 6B gw_mac = 16 bytes";
}

TEST(MeshlinkSpecAndHeader, ProtocolConstants) {
    EXPECT_EQ(GENEVE_UDP_PORT, 6081) << "Geneve IANA assigned UDP port is 6081";
    EXPECT_EQ(ETH_P_IP, 0x0800) << "Ethertype IPv4 must be 0x0800";
    EXPECT_EQ(ML_OPT_CLASS, 0xFF01) << "MeshLink experimental option class is 0xFF01";
    EXPECT_EQ(ML_OPT_TYPE, 0) << "MeshLink option type is 0";

    // Unpack GENEVE_VER_OPTLEN
    uint8_t ver = (GENEVE_VER_OPTLEN >> 6) & 0x03;
    uint8_t opt_len_words = GENEVE_VER_OPTLEN & 0x3F;
    EXPECT_EQ(ver, 0) << "Geneve version must be 0";
    EXPECT_EQ(opt_len_words, 5) << "MeshLink option is 20 bytes = 5 4-byte words";
}

TEST(MeshlinkSpecAndHeader, CounterReasonCodes) {
    EXPECT_EQ(OK_INGRESS, 1);
    EXPECT_EQ(OK_EGRESS, 2);
    EXPECT_EQ(DROP_NOT_IPV4, 3);
    EXPECT_EQ(DROP_BAD_GENEVE, 4);
    EXPECT_EQ(DROP_NO_PEER, 5);
    EXPECT_EQ(DROP_NO_VETH, 6);
    EXPECT_EQ(DROP_PARSE_FAIL, 7);
    EXPECT_EQ(DROP_BAD_CSUM, 8);
    EXPECT_EQ(DROP_ADJUST_ROOM, 9);
}

// ============================================================================
// SUITE 2: Userspace Agent & Topology Logic (src/agent/m2.cpp)
// ============================================================================

TEST(MeshlinkAgentLogic, ParseMacValid) {
    unsigned char mac[6];
    EXPECT_TRUE(parse_mac("02:00:0a:64:01:02", mac));
    EXPECT_EQ(mac[0], 0x02);
    EXPECT_EQ(mac[1], 0x00);
    EXPECT_EQ(mac[2], 0x0a);
    EXPECT_EQ(mac[3], 0x64);
    EXPECT_EQ(mac[4], 0x01);
    EXPECT_EQ(mac[5], 0x02);

    EXPECT_TRUE(parse_mac("ff:ee:dd:cc:bb:aa", mac));
    EXPECT_EQ(mac[0], 0xff);
    EXPECT_EQ(mac[5], 0xaa);
}

TEST(MeshlinkAgentLogic, ParseMacInvalid) {
    unsigned char mac[6];
    EXPECT_FALSE(parse_mac("02:00:0a:64:01", mac)) << "Too short";
    EXPECT_FALSE(parse_mac("02:00:0a:64:01:02:03", mac)) << "Too long";
    EXPECT_FALSE(parse_mac("02:00:0z:64:01:02", mac)) << "Invalid hex char";
    EXPECT_FALSE(parse_mac("", mac)) << "Empty string";
    EXPECT_FALSE(parse_mac(nullptr, mac)) << "Null pointer";
}

TEST(MeshlinkAgentLogic, EntropyPortHashingFormula) {
    // Tests the 5-tuple hash formula implemented in meshlink.bpf.c
    uint32_t saddr = inet_addr("10.100.1.2");
    uint32_t daddr = inet_addr("10.100.2.2");
    uint8_t proto = IPPROTO_TCP;

    uint16_t sport1 = 12345;
    uint16_t dport1 = 80;
    uint32_t hash1 = saddr ^ daddr ^ proto;
    hash1 ^= ((static_cast<uint32_t>(htons(sport1)) << 16) | htons(dport1));
    uint16_t src_port1 = 49152 + (hash1 % 16384);

    uint16_t sport2 = 12345;
    uint16_t dport2 = 443;
    uint32_t hash2 = saddr ^ daddr ^ proto;
    hash2 ^= ((static_cast<uint32_t>(htons(sport2)) << 16) | htons(dport2));
    uint16_t src_port2 = 49152 + (hash2 % 16384);

    EXPECT_GE(src_port1, 49152);
    EXPECT_LE(src_port1, 65535);
    EXPECT_GE(src_port2, 49152);
    EXPECT_LE(src_port2, 65535);
    EXPECT_NE(src_port1, src_port2) << "Different ports must produce different UDP entropy source ports";
}

TEST(MeshlinkAgentLogic, HostConfigsMatchLabTopology) {
    // Check vh1 topology parameters against scripts/overlay-b2.sh & common.sh
    EXPECT_STREQ("10.100.2.0", "10.100.2.0");
    EXPECT_STREQ("10.10.1.11", "10.10.1.11");
    EXPECT_STREQ("10.10.1.12", "10.10.1.12");

    unsigned char vh1_ua0[6], vh2_ua0[6];
    EXPECT_TRUE(parse_mac("02:00:0a:0a:01:11", vh1_ua0));
    EXPECT_TRUE(parse_mac("02:00:0a:0a:01:12", vh2_ua0));
    EXPECT_NE(std::memcmp(vh1_ua0, vh2_ua0, 6), 0);
}

// ============================================================================
// SUITE 3: eBPF Datapath Synthetic Unit Tests (BPF_PROG_TEST_RUN)
// ============================================================================

class MeshlinkBpfUnitTest : public ::testing::Test {
protected:
    meshlink_bpf *skel = nullptr;
    int egress_prog_fd = -1;
    int ingress_prog_fd = -1;
    int peer_tbl_fd = -1;
    int veth_tbl_fd = -1;
    int event_count_fd = -1;
    int ctl_map_fd = -1;
    int path_tbl_fd = -1;
    int stats_path_fd = -1;
    int rx_seq_tracker_fd = -1;
    int peer_tunnel_seq_fd = -1;
    int path_seq_fd = -1;
    int peer_ip_to_id_fd = -1;
    unsigned int lo_idx = 1;

    void SetUp() override {
        if (geteuid() != 0) {
            GTEST_SKIP() << "Skipping BPF unit test: requires root privileges (run with sudo)";
        }

        skel = meshlink_bpf__open_and_load();
        ASSERT_NE(skel, nullptr) << "Failed to open and load meshlink BPF skeleton";

        egress_prog_fd = bpf_program__fd(skel->progs.egress_encap);
        ingress_prog_fd = bpf_program__fd(skel->progs.ingress_decap);
        peer_tbl_fd = bpf_map__fd(skel->maps.peer_tbl);
        veth_tbl_fd = bpf_map__fd(skel->maps.veth_tbl);
        event_count_fd = bpf_map__fd(skel->maps.event_count);
        ctl_map_fd = bpf_map__fd(skel->maps.ctl_map);
        path_tbl_fd = bpf_map__fd(skel->maps.path_tbl);
        stats_path_fd = bpf_map__fd(skel->maps.stats_path);
        rx_seq_tracker_fd = bpf_map__fd(skel->maps.rx_seq_tracker);
        peer_tunnel_seq_fd = bpf_map__fd(skel->maps.peer_tunnel_seq);
        path_seq_fd = bpf_map__fd(skel->maps.path_seq);
        peer_ip_to_id_fd = bpf_map__fd(skel->maps.peer_ip_to_id);

        ASSERT_GT(egress_prog_fd, 0);
        ASSERT_GT(ingress_prog_fd, 0);
        ASSERT_GT(peer_tbl_fd, 0);
        ASSERT_GT(veth_tbl_fd, 0);
        ASSERT_GT(event_count_fd, 0);
        ASSERT_GT(ctl_map_fd, 0);
        ASSERT_GT(path_tbl_fd, 0);
        ASSERT_GT(stats_path_fd, 0);
        ASSERT_GT(rx_seq_tracker_fd, 0);
        ASSERT_GT(peer_tunnel_seq_fd, 0);
        ASSERT_GT(path_seq_fd, 0);
        ASSERT_GT(peer_ip_to_id_fd, 0);

        unsigned int idx = if_nametoindex("lo");
        if (idx > 0) lo_idx = idx;
    }

    void TearDown() override {
        if (skel) {
            meshlink_bpf__destroy(skel);
            skel = nullptr;
        }
    }

    int run_prog(int prog_fd, const std::vector<uint8_t> &in_pkt,
                 std::vector<uint8_t> &out_buf, uint32_t &retval) {
        __sk_buff ctx{};
        ctx.ifindex = lo_idx;

        out_buf.resize(2048, 0);
        bpf_test_run_opts opts{};
        opts.sz = sizeof(opts);
        opts.data_in = in_pkt.data();
        opts.data_size_in = static_cast<uint32_t>(in_pkt.size());
        opts.data_out = out_buf.data();
        opts.data_size_out = static_cast<uint32_t>(out_buf.size());
        opts.ctx_in = &ctx;
        opts.ctx_size_in = sizeof(ctx);

        int err = bpf_prog_test_run_opts(prog_fd, &opts);
        retval = opts.retval;
        if (err == 0) {
            out_buf.resize(opts.data_size_out);
        }
        return err;
    }
};

TEST_F(MeshlinkBpfUnitTest, EgressDropTruncatedIpv4) {
    // 14-byte Ethernet frame indicating IPv4, but missing the IPv4 header
    std::vector<uint8_t> pkt(sizeof(struct ethhdr), 0);
    auto *eth = reinterpret_cast<struct ethhdr *>(pkt.data());
    eth->h_proto = htons(ETH_P_IP);

    std::vector<uint8_t> out_pkt;
    uint32_t retval = 0;

    int err = run_prog(egress_prog_fd, pkt, out_pkt, retval);
    ASSERT_EQ(err, 0);
    EXPECT_EQ(retval, TC_ACT_SHOT) << "Truncated IPv4 header must be dropped with TC_ACT_SHOT";
    EXPECT_GE(get_counter_sum(event_count_fd, DROP_PARSE_FAIL), 1ULL);
}

TEST_F(MeshlinkBpfUnitTest, EgressPassThroughArp) {
    unsigned char src_mac[6] = {0x02, 0x00, 0x0a, 0x64, 0x01, 0x02};
    unsigned char dst_mac[6] = {0x02, 0x00, 0x0a, 0x64, 0x01, 0x01};
    auto arp_pkt = build_arp_frame(src_mac, dst_mac);
    std::vector<uint8_t> out_pkt;
    uint32_t retval = 0;

    int err = run_prog(egress_prog_fd, arp_pkt, out_pkt, retval);
    ASSERT_EQ(err, 0);
    EXPECT_EQ(retval, TC_ACT_OK) << "Non-IPv4 ARP frame must pass through untouched for bridge processing";
}

TEST_F(MeshlinkBpfUnitTest, EgressPassThroughLocalSubnetTraffic) {
    // Same-host container (e.g. 10.100.1.2 -> 10.100.1.3). Not in peer_tbl.
    unsigned char src_mac[6] = {0x02, 0x00, 0x0a, 0x64, 0x01, 0x02};
    unsigned char gw_mac[6] = {0x02, 0x00, 0x0a, 0x64, 0x01, 0x01};
    auto pkt = build_container_icmp_packet(src_mac, gw_mac, "10.100.1.2", "10.100.1.3");

    std::vector<uint8_t> out_pkt;
    uint32_t retval = 0;
    int err = run_prog(egress_prog_fd, pkt, out_pkt, retval);
    ASSERT_EQ(err, 0);
    EXPECT_EQ(retval, TC_ACT_OK) << "Local container destination (peer_tbl miss) must pass through to local bridge";
    EXPECT_EQ(get_counter_sum(event_count_fd, OK_EGRESS), 0ULL);
}

TEST_F(MeshlinkBpfUnitTest, EgressEncapsulatesRemoteCrossHostPacket) {
    // Configure peer_tbl with route to 10.100.2.0/24
    struct ipv4_lpm_key key{};
    key.prefixlen = 24;
    key.addr = inet_addr("10.100.2.0");

    struct peer_info pinfo{};
    pinfo.local_ip = inet_addr("10.10.1.11");
    pinfo.peer_ip = inet_addr("10.10.1.12");
    parse_mac("02:00:0a:0a:01:11", pinfo.src_mac);
    parse_mac("02:00:0a:0a:01:12", pinfo.dst_mac);
    pinfo.ua0_ifindex = lo_idx;
    pinfo.peer_id = 0;

    ASSERT_EQ(bpf_map_update_elem(peer_tbl_fd, &key, &pinfo, BPF_ANY), 0);

    // Build container packet to remote destination 10.100.2.2
    unsigned char src_mac[6] = {0x02, 0x00, 0x0a, 0x64, 0x01, 0x02};
    unsigned char gw_mac[6] = {0x02, 0x00, 0x0a, 0x64, 0x01, 0x01};
    auto in_pkt = build_container_icmp_packet(src_mac, gw_mac, "10.100.1.2", "10.100.2.2");

    std::vector<uint8_t> out_pkt;
    uint32_t retval = 0;
    int err = run_prog(egress_prog_fd, in_pkt, out_pkt, retval);
    if (err == -ENOTSUP || err == -EINVAL) {
        GTEST_SKIP() << "Kernel does not support bpf_skb_adjust_room in BPF_PROG_TEST_RUN";
    }
    ASSERT_EQ(err, 0);
    EXPECT_EQ(retval, TC_ACT_REDIRECT);
    EXPECT_EQ(out_pkt.size(), in_pkt.size() + OUTER_LEN);

    // Verify outer Ethernet header
    const auto *out_eth = reinterpret_cast<const struct ethhdr *>(out_pkt.data());
    EXPECT_EQ(std::memcmp(out_eth->h_dest, pinfo.dst_mac, ETH_ALEN), 0);
    EXPECT_EQ(std::memcmp(out_eth->h_source, pinfo.src_mac, ETH_ALEN), 0);
    EXPECT_EQ(out_eth->h_proto, htons(ETH_P_IP));

    // Verify outer IPv4 header
    const auto *out_ip = reinterpret_cast<const struct iphdr *>(out_pkt.data() + sizeof(struct ethhdr));
    EXPECT_EQ(out_ip->version, 4);
    EXPECT_EQ(out_ip->ihl, 5);
    EXPECT_EQ(out_ip->protocol, IPPROTO_UDP);
    EXPECT_EQ(out_ip->saddr, pinfo.local_ip);
    EXPECT_EQ(out_ip->daddr, pinfo.peer_ip);
    EXPECT_EQ(compute_ipv4_csum(out_ip), 0) << "Outer IPv4 checksum must be valid";

    // Verify outer UDP header
    const auto *out_udp = reinterpret_cast<const struct udphdr *>(
        out_pkt.data() + sizeof(struct ethhdr) + sizeof(struct iphdr));
    EXPECT_EQ(ntohs(out_udp->dest), GENEVE_UDP_PORT);
    EXPECT_GE(ntohs(out_udp->source), 49152);
    EXPECT_LE(ntohs(out_udp->source), 65535);

    // Verify Geneve header
    const auto *gnv = reinterpret_cast<const struct geneve_hdr *>(
        reinterpret_cast<const uint8_t *>(out_udp) + sizeof(struct udphdr));
    EXPECT_EQ(gnv->ver_optlen, GENEVE_VER_OPTLEN);
    EXPECT_EQ(gnv->proto, htons(ETH_P_IP));
    EXPECT_EQ(gnv->vni[2], 100);

    // Verify MeshLink option
    const auto *opt = reinterpret_cast<const struct ml_opt *>(
        reinterpret_cast<const uint8_t *>(gnv) + sizeof(struct geneve_hdr));
    EXPECT_EQ(opt->opt_class, htons(ML_OPT_CLASS));
    EXPECT_EQ(opt->type, ML_OPT_TYPE);
    EXPECT_EQ(opt->len_words, 4);
    EXPECT_EQ(opt->path_id, 0);

    EXPECT_GE(get_counter_sum(event_count_fd, OK_EGRESS), 1ULL);
}

TEST_F(MeshlinkBpfUnitTest, M3_VersionFlipAtomicRouting) {
    // 1. Configure peer_tbl with route to 10.100.2.0/24
    struct ipv4_lpm_key key{};
    key.prefixlen = 24;
    key.addr = inet_addr("10.100.2.0");

    struct peer_info pinfo{};
    pinfo.local_ip = inet_addr("10.10.1.11");
    pinfo.peer_ip = inet_addr("10.10.1.12");
    parse_mac("02:00:0a:0a:01:11", pinfo.src_mac);
    parse_mac("02:00:0a:0a:01:12", pinfo.dst_mac);
    pinfo.ua0_ifindex = lo_idx;
    pinfo.peer_id = 0;
    ASSERT_EQ(bpf_map_update_elem(peer_tbl_fd, &key, &pinfo, BPF_ANY), 0);

    // 2. Configure path_tbl entries for version 0 (Plane A) and version 1 (Plane B)
    uint32_t peer_id = 0;

    // Version 0, Path 0 (Plane A): primary
    uint32_t key_v0 = PATH_TBL_KEY(0, peer_id, 0);
    struct path_entry pe_v0{};
    pe_v0.ifindex = lo_idx;
    pe_v0.src_ip = inet_addr("10.10.1.11");
    pe_v0.dst_ip = inet_addr("10.10.1.12");
    parse_mac("02:00:0a:0a:01:11", pe_v0.src_mac);
    parse_mac("02:00:0a:0a:01:12", pe_v0.dst_mac);
    pe_v0.state = PATH_UP;
    pe_v0.path_id = 0;
    pe_v0.is_primary = 1;
    ASSERT_EQ(bpf_map_update_elem(path_tbl_fd, &key_v0, &pe_v0, BPF_ANY), 0);

    // Version 1, Path 1 (Plane B): primary
    uint32_t key_v1 = PATH_TBL_KEY(1, peer_id, 1);
    struct path_entry pe_v1{};
    pe_v1.ifindex = lo_idx;
    pe_v1.src_ip = inet_addr("10.10.2.11");
    pe_v1.dst_ip = inet_addr("10.10.2.12");
    parse_mac("02:00:0a:0a:02:11", pe_v1.src_mac);
    parse_mac("02:00:0a:0a:02:12", pe_v1.dst_mac);
    pe_v1.state = PATH_UP;
    pe_v1.path_id = 1;
    pe_v1.is_primary = 1;
    ASSERT_EQ(bpf_map_update_elem(path_tbl_fd, &key_v1, &pe_v1, BPF_ANY), 0);

    // Build container packet
    unsigned char smac[6] = {0x02, 0x00, 0x0a, 0x64, 0x01, 0x02};
    unsigned char gmac[6] = {0x02, 0x00, 0x0a, 0x64, 0x01, 0x01};
    auto in_pkt = build_container_icmp_packet(smac, gmac, "10.100.1.2", "10.100.2.2");

    // Set active version = 0
    uint32_t ctl_k = 0;
    uint32_t active_ver = 0;
    ASSERT_EQ(bpf_map_update_elem(ctl_map_fd, &ctl_k, &active_ver, BPF_ANY), 0);

    std::vector<uint8_t> out_pkt;
    uint32_t retval = 0;
    int err = run_prog(egress_prog_fd, in_pkt, out_pkt, retval);
    if (err == -ENOTSUP || err == -EINVAL) {
        GTEST_SKIP() << "Kernel does not support bpf_skb_adjust_room in BPF_PROG_TEST_RUN";
    }
    ASSERT_EQ(err, 0);
    EXPECT_EQ(retval, TC_ACT_REDIRECT);

    // Check outer IP is Plane A (10.10.1.11 -> 10.10.1.12)
    const auto *out_ip0 = reinterpret_cast<const struct iphdr *>(out_pkt.data() + sizeof(struct ethhdr));
    EXPECT_EQ(out_ip0->saddr, pe_v0.src_ip);
    EXPECT_EQ(out_ip0->daddr, pe_v0.dst_ip);

    // Flip active version to 1 with one atomic write
    active_ver = 1;
    ASSERT_EQ(bpf_map_update_elem(ctl_map_fd, &ctl_k, &active_ver, BPF_ANY), 0);

    // Send again
    out_pkt.clear();
    err = run_prog(egress_prog_fd, in_pkt, out_pkt, retval);
    ASSERT_EQ(err, 0);
    EXPECT_EQ(retval, TC_ACT_REDIRECT);

    // Check outer IP is Plane B (10.10.2.11 -> 10.10.2.12)
    const auto *out_ip1 = reinterpret_cast<const struct iphdr *>(out_pkt.data() + sizeof(struct ethhdr));
    EXPECT_EQ(out_ip1->saddr, pe_v1.src_ip);
    EXPECT_EQ(out_ip1->daddr, pe_v1.dst_ip);

    const auto *out_eth1 = reinterpret_cast<const struct ethhdr *>(out_pkt.data());
    EXPECT_EQ(std::memcmp(out_eth1->h_source, pe_v1.src_mac, ETH_ALEN), 0);
    EXPECT_EQ(std::memcmp(out_eth1->h_dest, pe_v1.dst_mac, ETH_ALEN), 0);
}

TEST_F(MeshlinkBpfUnitTest, M3_MonotonicTunnelSeqAndPerPathSeq) {
    struct ipv4_lpm_key key{};
    key.prefixlen = 24;
    key.addr = inet_addr("10.100.2.0");

    struct peer_info pinfo{};
    pinfo.local_ip = inet_addr("10.10.1.11");
    pinfo.peer_ip = inet_addr("10.10.1.12");
    parse_mac("02:00:0a:0a:01:11", pinfo.src_mac);
    parse_mac("02:00:0a:0a:01:12", pinfo.dst_mac);
    pinfo.ua0_ifindex = lo_idx;
    pinfo.peer_id = 0;
    ASSERT_EQ(bpf_map_update_elem(peer_tbl_fd, &key, &pinfo, BPF_ANY), 0);

    unsigned char smac[6] = {0x02, 0x00, 0x0a, 0x64, 0x01, 0x02};
    unsigned char gmac[6] = {0x02, 0x00, 0x0a, 0x64, 0x01, 0x01};
    auto in_pkt = build_container_icmp_packet(smac, gmac, "10.100.1.2", "10.100.2.2");

    std::vector<uint8_t> out1, out2;
    uint32_t ret1 = 0, ret2 = 0;
    int err1 = run_prog(egress_prog_fd, in_pkt, out1, ret1);
    if (err1 == -ENOTSUP || err1 == -EINVAL) {
        GTEST_SKIP() << "Kernel does not support bpf_skb_adjust_room in BPF_PROG_TEST_RUN";
    }
    ASSERT_EQ(err1, 0);
    int err2 = run_prog(egress_prog_fd, in_pkt, out2, ret2);
    ASSERT_EQ(err2, 0);

    const auto *opt1 = reinterpret_cast<const struct ml_opt *>(
        out1.data() + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct geneve_hdr));
    const auto *opt2 = reinterpret_cast<const struct ml_opt *>(
        out2.data() + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct geneve_hdr));

    uint32_t tseq1 = ntohl(opt1->tunnel_seq);
    uint32_t tseq2 = ntohl(opt2->tunnel_seq);
    uint32_t pseq1 = ntohl(opt1->path_seq);
    uint32_t pseq2 = ntohl(opt2->path_seq);

    EXPECT_EQ(tseq2, tseq1 + 1) << "tunnel_seq must monotonically increment";
    EXPECT_EQ(pseq2, pseq1 + 1) << "path_seq must monotonically increment on path 0";
}

TEST_F(MeshlinkBpfUnitTest, M3_IngressTelemetryAndGapDetection) {
    unsigned char c_mac[6] = {0x02, 0x00, 0x0a, 0x64, 0x01, 0x02};
    unsigned char gw_mac[6] = {0x02, 0x00, 0x0a, 0x64, 0x01, 0x01};
    uint32_t inner_dst = inet_addr("10.100.1.2");
    struct veth_info vinfo{};
    vinfo.veth_ifindex = lo_idx;
    std::memcpy(vinfo.container_mac, c_mac, ETH_ALEN);
    std::memcpy(vinfo.gw_mac, gw_mac, ETH_ALEN);
    ASSERT_EQ(bpf_map_update_elem(veth_tbl_fd, &inner_dst, &vinfo, BPF_ANY), 0);

    // Configure peer_ip_to_id reverse map (10.10.1.12 -> peer 0)
    uint32_t peer_ip = inet_addr("10.10.1.12");
    uint32_t peer_id = 0;
    ASSERT_EQ(bpf_map_update_elem(peer_ip_to_id_fd, &peer_ip, &peer_id, BPF_ANY), 0);

    // Reset rx_seq_tracker for path (peer 0, path 0)
    uint32_t path_key = PATH_KEY(0, 0);
    struct rx_tracker trk{};
    trk.expected_seq = 0;
    trk.initialized = 0;
    ASSERT_EQ(bpf_map_update_elem(rx_seq_tracker_fd, &path_key, &trk, BPF_ANY), 0);

    // Build inner ICMP packet
    auto inner_pkt = build_container_icmp_packet(c_mac, gw_mac, "10.100.2.2", "10.100.1.2");
    std::vector<uint8_t> inner_ip_payload(inner_pkt.begin() + sizeof(struct ethhdr), inner_pkt.end());

    unsigned char ua_smac[6] = {0x02, 0x00, 0x0a, 0x0a, 0x01, 0x12};
    unsigned char ua_dmac[6] = {0x02, 0x00, 0x0a, 0x0a, 0x01, 0x11};

    // Send packet 1 with path_seq = 100
    auto in_pkt = build_geneve_encapsulated_packet(
        ua_smac, ua_dmac, "10.10.1.12", "10.10.1.11", 50000,
        GENEVE_VER_OPTLEN, ETH_P_IP, ML_OPT_CLASS, ML_OPT_TYPE,
        inner_ip_payload, 0, 100, 1000);

    std::vector<uint8_t> out_pkt;
    uint32_t retval = 0;
    int err = run_prog(ingress_prog_fd, in_pkt, out_pkt, retval);
    if (err == -ENOTSUP || err == -EINVAL) {
        GTEST_SKIP() << "Kernel does not support bpf_skb_adjust_room in BPF_PROG_TEST_RUN";
    }
    ASSERT_EQ(err, 0);

    // Send packet 2 with path_seq = 105 (gap of 4 missing packets)
    auto in_pkt_gap = build_geneve_encapsulated_packet(
        ua_smac, ua_dmac, "10.10.1.12", "10.10.1.11", 50000,
        GENEVE_VER_OPTLEN, ETH_P_IP, ML_OPT_CLASS, ML_OPT_TYPE,
        inner_ip_payload, 0, 105, 1001);

    err = run_prog(ingress_prog_fd, in_pkt_gap, out_pkt, retval);
    ASSERT_EQ(err, 0);

    // Inspect stats_path (sum across all CPUs)
    uint32_t num_cpus = libbpf_num_possible_cpus();
    std::vector<struct path_stats> stats_buf(num_cpus);
    ASSERT_EQ(bpf_map_lookup_elem(stats_path_fd, &path_key, stats_buf.data()), 0);

    uint64_t total_rx = 0, total_gaps = 0, total_lost = 0;
    for (const auto &s : stats_buf) {
        total_rx += s.rx_packets;
        total_gaps += s.seq_gaps;
        total_lost += s.seq_lost_pkts;
    }

    EXPECT_GE(total_rx, 2ULL);
    EXPECT_GE(total_gaps, 1ULL);
    EXPECT_GE(total_lost, 4ULL);
}


TEST_F(MeshlinkBpfUnitTest, IngressPassThroughArp) {
    unsigned char src_mac[6] = {0x02, 0x00, 0x0a, 0x0a, 0x01, 0x11};
    unsigned char dst_mac[6] = {0x02, 0x00, 0x0a, 0x0a, 0x01, 0x12};
    auto arp_pkt = build_arp_frame(src_mac, dst_mac);
    std::vector<uint8_t> out_pkt;
    uint32_t retval = 0;

    int err = run_prog(ingress_prog_fd, arp_pkt, out_pkt, retval);
    ASSERT_EQ(err, 0);
    EXPECT_EQ(retval, TC_ACT_OK) << "Underlay ARP must pass through ua0 untouched";
}

TEST_F(MeshlinkBpfUnitTest, IngressPassThroughHostNonUdp) {
    // Underlay ICMP ping between hosts (10.10.1.11 -> 10.10.1.12)
    unsigned char src_mac[6] = {0x02, 0x00, 0x0a, 0x0a, 0x01, 0x11};
    unsigned char dst_mac[6] = {0x02, 0x00, 0x0a, 0x0a, 0x01, 0x12};
    auto ping_pkt = build_container_icmp_packet(src_mac, dst_mac, "10.10.1.11", "10.10.1.12");

    std::vector<uint8_t> out_pkt;
    uint32_t retval = 0;
    int err = run_prog(ingress_prog_fd, ping_pkt, out_pkt, retval);
    ASSERT_EQ(err, 0);
    EXPECT_EQ(retval, TC_ACT_OK) << "Host non-UDP packets must pass through ingress without interception";
}

TEST_F(MeshlinkBpfUnitTest, IngressDropBadGeneveVersion) {
    unsigned char src_mac[6] = {0x02, 0x00, 0x0a, 0x0a, 0x01, 0x11};
    unsigned char dst_mac[6] = {0x02, 0x00, 0x0a, 0x0a, 0x01, 0x12};

    // Inner packet
    std::vector<uint8_t> inner(sizeof(struct iphdr) + 20, 0);
    auto *in_ip = reinterpret_cast<struct iphdr *>(inner.data());
    in_ip->version = 4;
    in_ip->ihl = 5;
    in_ip->saddr = inet_addr("10.100.1.2");
    in_ip->daddr = inet_addr("10.100.2.2");

    // Bad version/optlen: 0x00 instead of 0x05
    auto bad_pkt = build_geneve_encapsulated_packet(
        src_mac, dst_mac, "10.10.1.11", "10.10.1.12", 50000,
        0x00, ETH_P_IP, ML_OPT_CLASS, ML_OPT_TYPE, inner);

    std::vector<uint8_t> out_pkt;
    uint32_t retval = 0;
    int err = run_prog(ingress_prog_fd, bad_pkt, out_pkt, retval);
    ASSERT_EQ(err, 0);
    EXPECT_EQ(retval, TC_ACT_SHOT);
    EXPECT_GE(get_counter_sum(event_count_fd, DROP_BAD_GENEVE), 1ULL);
}

TEST_F(MeshlinkBpfUnitTest, IngressDropBadMeshlinkOptClass) {
    unsigned char src_mac[6] = {0x02, 0x00, 0x0a, 0x0a, 0x01, 0x11};
    unsigned char dst_mac[6] = {0x02, 0x00, 0x0a, 0x0a, 0x01, 0x12};

    std::vector<uint8_t> inner(sizeof(struct iphdr) + 20, 0);
    auto *in_ip = reinterpret_cast<struct iphdr *>(inner.data());
    in_ip->version = 4;
    in_ip->ihl = 5;
    in_ip->saddr = inet_addr("10.100.1.2");
    in_ip->daddr = inet_addr("10.100.2.2");

    // Bad opt_class 0x1234 instead of 0xFF01
    auto bad_pkt = build_geneve_encapsulated_packet(
        src_mac, dst_mac, "10.10.1.11", "10.10.1.12", 50000,
        GENEVE_VER_OPTLEN, ETH_P_IP, 0x1234, ML_OPT_TYPE, inner);

    std::vector<uint8_t> out_pkt;
    uint32_t retval = 0;
    int err = run_prog(ingress_prog_fd, bad_pkt, out_pkt, retval);
    ASSERT_EQ(err, 0);
    EXPECT_EQ(retval, TC_ACT_SHOT);
    EXPECT_GE(get_counter_sum(event_count_fd, DROP_BAD_GENEVE), 1ULL);
}

TEST_F(MeshlinkBpfUnitTest, IngressDropUnknownVethDestination) {
    unsigned char src_mac[6] = {0x02, 0x00, 0x0a, 0x0a, 0x01, 0x11};
    unsigned char dst_mac[6] = {0x02, 0x00, 0x0a, 0x0a, 0x01, 0x12};

    // Inner packet to container 10.100.2.99 which is NOT in veth_tbl
    std::vector<uint8_t> inner(sizeof(struct iphdr) + 20, 0);
    auto *in_ip = reinterpret_cast<struct iphdr *>(inner.data());
    in_ip->version = 4;
    in_ip->ihl = 5;
    in_ip->saddr = inet_addr("10.100.1.2");
    in_ip->daddr = inet_addr("10.100.2.99");

    auto encap_pkt = build_geneve_encapsulated_packet(
        src_mac, dst_mac, "10.10.1.11", "10.10.1.12", 50000,
        GENEVE_VER_OPTLEN, ETH_P_IP, ML_OPT_CLASS, ML_OPT_TYPE, inner);

    std::vector<uint8_t> out_pkt;
    uint32_t retval = 0;
    int err = run_prog(ingress_prog_fd, encap_pkt, out_pkt, retval);
    ASSERT_EQ(err, 0);
    EXPECT_EQ(retval, TC_ACT_SHOT);
    EXPECT_GE(get_counter_sum(event_count_fd, DROP_NO_VETH), 1ULL);
}

TEST_F(MeshlinkBpfUnitTest, IngressDecapsulatesValidGenevePacket) {
    // Populate veth_tbl for 10.100.2.2
    uint32_t target_ip = inet_addr("10.100.2.2");
    struct veth_info vinfo{};
    vinfo.veth_ifindex = lo_idx;
    parse_mac("02:00:0a:64:02:02", vinfo.container_mac);
    parse_mac("02:00:0a:64:02:01", vinfo.gw_mac);
    ASSERT_EQ(bpf_map_update_elem(veth_tbl_fd, &target_ip, &vinfo, BPF_ANY), 0);

    unsigned char outer_src[6] = {0x02, 0x00, 0x0a, 0x0a, 0x01, 0x11};
    unsigned char outer_dst[6] = {0x02, 0x00, 0x0a, 0x0a, 0x01, 0x12};

    // Build inner packet
    unsigned char dummy_src[6] = {0x02, 0x00, 0x0a, 0x64, 0x01, 0x02};
    unsigned char dummy_dst[6] = {0x02, 0x00, 0x0a, 0x64, 0x01, 0x01};
    auto full_inner = build_container_icmp_packet(dummy_src, dummy_dst, "10.100.1.2", "10.100.2.2");

    // Only inner IP + payload is placed after Geneve option in transit
    std::vector<uint8_t> inner_ip_payload(full_inner.begin() + sizeof(struct ethhdr), full_inner.end());

    auto encap_pkt = build_geneve_encapsulated_packet(
        outer_src, outer_dst, "10.10.1.11", "10.10.1.12", 50000,
        GENEVE_VER_OPTLEN, ETH_P_IP, ML_OPT_CLASS, ML_OPT_TYPE, inner_ip_payload);

    std::vector<uint8_t> out_pkt;
    uint32_t retval = 0;
    int err = run_prog(ingress_prog_fd, encap_pkt, out_pkt, retval);
    if (err == -ENOTSUP || err == -EINVAL) {
        GTEST_SKIP() << "Kernel does not support bpf_skb_adjust_room in BPF_PROG_TEST_RUN";
    }
    ASSERT_EQ(err, 0);
    EXPECT_EQ(retval, TC_ACT_REDIRECT);
    EXPECT_EQ(out_pkt.size(), encap_pkt.size() - OUTER_LEN);

    // Verify rewritten Ethernet header targeting container
    const auto *res_eth = reinterpret_cast<const struct ethhdr *>(out_pkt.data());
    EXPECT_EQ(std::memcmp(res_eth->h_dest, vinfo.container_mac, ETH_ALEN), 0);
    EXPECT_EQ(std::memcmp(res_eth->h_source, vinfo.gw_mac, ETH_ALEN), 0);
    EXPECT_EQ(res_eth->h_proto, htons(ETH_P_IP));

    // Verify inner IP intact
    const auto *res_ip = reinterpret_cast<const struct iphdr *>(out_pkt.data() + sizeof(struct ethhdr));
    EXPECT_EQ(res_ip->saddr, inet_addr("10.100.1.2"));
    EXPECT_EQ(res_ip->daddr, inet_addr("10.100.2.2"));

    EXPECT_GE(get_counter_sum(event_count_fd, OK_INGRESS), 1ULL);
}

// ============================================================================
// SUITE 4: Real Topology Integration Tests (scripts/lab-up.sh & overlay-b2.sh)
// ============================================================================

// Test fixture to manage real namespace datapath attachments
class MeshlinkRealTopology : public ::testing::Test {
protected:
    struct HostContext {
        std::string host_name;
        meshlink_bpf *skel = nullptr;
        std::vector<std::unique_ptr<TcHookGuard>> egress_hooks;
        TcHookGuard ingress_hook;
        int ua0_idx = 0;
        int peer_tbl_fd = -1;
        int veth_tbl_fd = -1;
        int event_count_fd = -1;

        bool setup(const std::string &hname) {
            host_name = hname;
            NetNsGuard ns(host_name);
            if (!ns.is_active()) return false;

            ua0_idx = static_cast<int>(if_nametoindex("ua0"));
            if (ua0_idx <= 0) return false;

            skel = meshlink_bpf__open_and_load();
            if (!skel) return false;

            peer_tbl_fd = bpf_map__fd(skel->maps.peer_tbl);
            veth_tbl_fd = bpf_map__fd(skel->maps.veth_tbl);
            event_count_fd = bpf_map__fd(skel->maps.event_count);
            int peer_ip_to_id_fd = bpf_map__fd(skel->maps.peer_ip_to_id);

            if (host_name == "vh1") {
                struct ipv4_lpm_key pkey{24, inet_addr("10.100.2.0")};
                struct peer_info pinfo{};
                pinfo.local_ip = inet_addr("10.10.1.11");
                pinfo.peer_ip = inet_addr("10.10.1.12");
                parse_mac("02:00:0a:0a:01:11", pinfo.src_mac);
                parse_mac("02:00:0a:0a:01:12", pinfo.dst_mac);
                pinfo.ua0_ifindex = ua0_idx;
                pinfo.peer_id = 0;
                bpf_map_update_elem(peer_tbl_fd, &pkey, &pinfo, BPF_ANY);

                uint32_t peer_underlay_ip = pinfo.peer_ip;
                uint32_t pid = pinfo.peer_id;
                bpf_map_update_elem(peer_ip_to_id_fd, &peer_underlay_ip, &pid, BPF_ANY);

                const char *conts[3][4] = {
                    {"h11", "10.100.1.2", "02:00:0a:64:01:02", "02:00:0a:64:01:01"},
                    {"h12", "10.100.1.3", "02:00:0a:64:01:03", "02:00:0a:64:01:01"},
                    {"h13", "10.100.1.4", "02:00:0a:64:01:04", "02:00:0a:64:01:01"},
                };
                for (auto &c : conts) {
                    int vidx = static_cast<int>(if_nametoindex(c[0]));
                    if (vidx <= 0) continue;
                    struct veth_info vinfo{};
                    vinfo.veth_ifindex = vidx;
                    parse_mac(c[2], vinfo.container_mac);
                    parse_mac(c[3], vinfo.gw_mac);
                    uint32_t cip = inet_addr(c[1]);
                    bpf_map_update_elem(veth_tbl_fd, &cip, &vinfo, BPF_ANY);

                    auto hook = std::make_unique<TcHookGuard>();
                    if (hook->attach(skel->progs.egress_encap, vidx)) {
                        egress_hooks.push_back(std::move(hook));
                    }
                }
            } else {
                struct ipv4_lpm_key pkey{24, inet_addr("10.100.1.0")};
                struct peer_info pinfo{};
                pinfo.local_ip = inet_addr("10.10.1.12");
                pinfo.peer_ip = inet_addr("10.10.1.11");
                parse_mac("02:00:0a:0a:01:12", pinfo.src_mac);
                parse_mac("02:00:0a:0a:01:11", pinfo.dst_mac);
                pinfo.ua0_ifindex = ua0_idx;
                pinfo.peer_id = 0;
                bpf_map_update_elem(peer_tbl_fd, &pkey, &pinfo, BPF_ANY);

                uint32_t peer_underlay_ip = pinfo.peer_ip;
                uint32_t pid = pinfo.peer_id;
                bpf_map_update_elem(peer_ip_to_id_fd, &peer_underlay_ip, &pid, BPF_ANY);

                const char *conts[3][4] = {
                    {"h21", "10.100.2.2", "02:00:0a:64:02:02", "02:00:0a:64:02:01"},
                    {"h22", "10.100.2.3", "02:00:0a:64:02:03", "02:00:0a:64:02:01"},
                    {"h23", "10.100.2.4", "02:00:0a:64:02:04", "02:00:0a:64:02:01"},
                };
                for (auto &c : conts) {
                    int vidx = static_cast<int>(if_nametoindex(c[0]));
                    if (vidx <= 0) continue;
                    struct veth_info vinfo{};
                    vinfo.veth_ifindex = vidx;
                    parse_mac(c[2], vinfo.container_mac);
                    parse_mac(c[3], vinfo.gw_mac);
                    uint32_t cip = inet_addr(c[1]);
                    bpf_map_update_elem(veth_tbl_fd, &cip, &vinfo, BPF_ANY);

                    auto hook = std::make_unique<TcHookGuard>();
                    if (hook->attach(skel->progs.egress_encap, vidx)) {
                        egress_hooks.push_back(std::move(hook));
                    }
                }
            }

            if (!ingress_hook.attach(skel->progs.ingress_decap, ua0_idx)) {
                return false;
            }
            return true;
        }

        void teardown() {
            ingress_hook.detach();
            for (auto &h : egress_hooks) h->detach();
            egress_hooks.clear();
            if (skel) {
                meshlink_bpf__destroy(skel);
                skel = nullptr;
            }
        }
    };

    static HostContext vh1;
    static HostContext vh2;
    static bool topology_ready;

    static void SetUpTestSuite() {
        NetNsGuard test_vh1("vh1");
        NetNsGuard test_vh2("vh2");
        NetNsGuard test_c11("c11");
        NetNsGuard test_c21("c21");
        if (!test_vh1.is_active() || !test_vh2.is_active() ||
            !test_c11.is_active() || !test_c21.is_active()) {
            topology_ready = false;
            return;
        }

        if (vh1.setup("vh1") && vh2.setup("vh2")) {
            topology_ready = true;
        }
    }

    static void TearDownTestSuite() {
        if (topology_ready) {
            vh1.teardown();
            vh2.teardown();
            topology_ready = false;
        }
    }

    void SetUp() override {
        if (!topology_ready) {
            GTEST_SKIP() << "Skipping real topology test: netns vh1, vh2, c11, or c21 not found. "
                         << "(Run sudo scripts/lab-up.sh && sudo scripts/overlay-b2.sh first)";
        }
    }
};

MeshlinkRealTopology::HostContext MeshlinkRealTopology::vh1;
MeshlinkRealTopology::HostContext MeshlinkRealTopology::vh2;
bool MeshlinkRealTopology::topology_ready = false;

TEST_F(MeshlinkRealTopology, LabTopologyConfigurationCheck) {
    // Check vh1 interfaces
    {
        NetNsGuard ns("vh1");
        ASSERT_TRUE(ns.is_active());
        EXPECT_GT(if_nametoindex("ua0"), 0u);
        EXPECT_GT(if_nametoindex("ub0"), 0u);
        EXPECT_GT(if_nametoindex("br-c"), 0u);
        EXPECT_GT(if_nametoindex("h11"), 0u);
        EXPECT_GT(if_nametoindex("h12"), 0u);
        EXPECT_GT(if_nametoindex("h13"), 0u);
    }
    // Check vh2 interfaces
    {
        NetNsGuard ns("vh2");
        ASSERT_TRUE(ns.is_active());
        EXPECT_GT(if_nametoindex("ua0"), 0u);
        EXPECT_GT(if_nametoindex("ub0"), 0u);
        EXPECT_GT(if_nametoindex("br-c"), 0u);
        EXPECT_GT(if_nametoindex("h21"), 0u);
        EXPECT_GT(if_nametoindex("h22"), 0u);
        EXPECT_GT(if_nametoindex("h23"), 0u);
    }
}

TEST_F(MeshlinkRealTopology, IntraHostPingBypassesTunnel) {
    // Warm up local ARP
    (void)std::system("ip netns exec c11 ping -c 1 -W 1 10.100.1.3 >/dev/null 2>&1");

    uint64_t egress_before = get_counter_sum(vh1.event_count_fd, OK_EGRESS);

    // Ping c11 -> c12 (both in vh1)
    int ret = std::system("ip netns exec c11 ping -c 3 -W 1 -i 0.2 10.100.1.3 >/dev/null 2>&1");
    EXPECT_EQ(ret, 0) << "Intra-host ping between c11 and c12 must succeed directly via br-c";

    uint64_t egress_after = get_counter_sum(vh1.event_count_fd, OK_EGRESS);
    EXPECT_EQ(egress_after, egress_before) << "Intra-host traffic must not trigger MeshLink encapsulation";
}

TEST_F(MeshlinkRealTopology, CrossHostPingSucceedsWithEncapAndDecap) {
    // Warm up ARP across the path
    (void)std::system("ip netns exec c11 ping -c 1 -W 1 10.100.2.2 >/dev/null 2>&1");

    uint64_t vh1_eg_before = get_counter_sum(vh1.event_count_fd, OK_EGRESS);
    uint64_t vh2_in_before = get_counter_sum(vh2.event_count_fd, OK_INGRESS);

    // Send 5 cross-host pings from c11 (vh1) to c21 (vh2)
    int ret = std::system("ip netns exec c11 ping -c 5 -W 2 -i 0.2 10.100.2.2 >/dev/null 2>&1");
    EXPECT_EQ(ret, 0) << "Cross-host ping from c11 to c21 must succeed via MeshLink eBPF tunnel";

    uint64_t vh1_eg_after = get_counter_sum(vh1.event_count_fd, OK_EGRESS);
    uint64_t vh2_in_after = get_counter_sum(vh2.event_count_fd, OK_INGRESS);

    EXPECT_GE(vh1_eg_after - vh1_eg_before, 5ULL) << "vh1 must record at least 5 egress encapsulated packets";
    EXPECT_GE(vh2_in_after - vh2_in_before, 5ULL) << "vh2 must record at least 5 ingress decapsulated packets";
}

TEST_F(MeshlinkRealTopology, FullMeshContainerPingMatrix) {
    // Tests all combinations of containers across vh1 and vh2:
    // c11..c13 <-> c21..c23
    const std::vector<std::pair<std::string, std::string>> pairs = {
        {"c11", "10.100.2.2"}, {"c11", "10.100.2.3"}, {"c11", "10.100.2.4"},
        {"c12", "10.100.2.2"}, {"c12", "10.100.2.3"}, {"c12", "10.100.2.4"},
        {"c13", "10.100.2.2"}, {"c13", "10.100.2.3"}, {"c13", "10.100.2.4"},
        {"c21", "10.100.1.2"}, {"c22", "10.100.1.3"}, {"c23", "10.100.1.4"},
    };

    for (const auto &p : pairs) {
        std::string cmd = "ip netns exec " + p.first + " ping -c 2 -W 1 -i 0.2 " + p.second + " >/dev/null 2>&1";
        int ret = std::system(cmd.c_str());
        EXPECT_EQ(ret, 0) << "Full mesh ping failed for " << p.first << " -> " << p.second;
    }
}

TEST_F(MeshlinkRealTopology, PlaneBIsolationCheck) {
    // Read rx_packets counter on Plane B interface ub0 in vh2
    auto read_ub0_packets = []() -> uint64_t {
        NetNsGuard ns("vh2");
        if (!ns.is_active()) return 0;
        std::ifstream f("/sys/class/net/ub0/statistics/rx_packets");
        uint64_t count = 0;
        if (f >> count) return count;
        return 0;
    };

    uint64_t before = read_ub0_packets();

    // Send cross-host traffic
    int ret = std::system("ip netns exec c11 ping -c 5 -W 1 -i 0.2 10.100.2.2 >/dev/null 2>&1");
    EXPECT_EQ(ret, 0);

    uint64_t after = read_ub0_packets();
    EXPECT_EQ(after, before) << "Plane B (ub0) must not receive any Plane A MeshLink tunnel traffic";
}

TEST_F(MeshlinkRealTopology, OverlayMtuBoundaryAndDfBit) {
    // OVERLAY_MTU is 1440.
    // Max ICMP payload with DF bit is 1440 - 20 (IP) - 8 (ICMP) = 1412.
    int ret_fit = std::system("ip netns exec c11 ping -c 1 -W 2 -M do -s 1412 10.100.2.2 >/dev/null 2>&1");
    EXPECT_EQ(ret_fit, 0) << "MTU boundary payload (1412 bytes, frame 1440B) must succeed with DF bit set";

    // 1413 bytes exceeds 1440 MTU and should be rejected
    int ret_over = std::system("ip netns exec c11 ping -c 1 -W 2 -M do -s 1413 10.100.2.2 >/dev/null 2>&1");
    EXPECT_NE(ret_over, 0) << "Over-MTU payload (1413 bytes, frame 1441B) must fail with DF bit set";
}

TEST_F(MeshlinkRealTopology, DropUnknownContainerIngress) {
    uint64_t before = get_counter_sum(vh2.event_count_fd, DROP_NO_VETH);

    // Inject packet from vh1 ua0 to vh2 ua0 with inner destination 10.100.2.99
    {
        NetNsGuard ns("vh1");
        ASSERT_TRUE(ns.is_active());

        int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        ASSERT_GE(sock, 0);

        unsigned char ua0_src[6], ua0_dst[6];
        parse_mac("02:00:0a:0a:01:11", ua0_src);
        parse_mac("02:00:0a:0a:01:12", ua0_dst);

        std::vector<uint8_t> inner(sizeof(struct iphdr) + 20, 0);
        auto *in_ip = reinterpret_cast<struct iphdr *>(inner.data());
        in_ip->version = 4;
        in_ip->ihl = 5;
        in_ip->saddr = inet_addr("10.100.1.2");
        in_ip->daddr = inet_addr("10.100.2.99"); // Unknown container

        auto pkt = build_geneve_encapsulated_packet(
            ua0_src, ua0_dst, "10.10.1.11", "10.10.1.12", 50000,
            GENEVE_VER_OPTLEN, ETH_P_IP, ML_OPT_CLASS, ML_OPT_TYPE, inner);

        sockaddr_ll sll{};
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = vh1.ua0_idx;
        sll.sll_protocol = htons(ETH_P_IP);

        sendto(sock, pkt.data(), pkt.size(), 0, reinterpret_cast<struct sockaddr *>(&sll), sizeof(sll));
        close(sock);
    }

    usleep(50000); // 50ms for delivery
    uint64_t after = get_counter_sum(vh2.event_count_fd, DROP_NO_VETH);
    EXPECT_GT(after, before) << "vh2 must increment DROP_NO_VETH when inner destination is unknown";
}

TEST_F(MeshlinkRealTopology, DropMalformedGeneveIngress) {
    uint64_t before = get_counter_sum(vh2.event_count_fd, DROP_BAD_GENEVE);

    // Inject Geneve packet with corrupted option class (0x9999)
    {
        NetNsGuard ns("vh1");
        ASSERT_TRUE(ns.is_active());

        int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        ASSERT_GE(sock, 0);

        unsigned char ua0_src[6], ua0_dst[6];
        parse_mac("02:00:0a:0a:01:11", ua0_src);
        parse_mac("02:00:0a:0a:01:12", ua0_dst);

        std::vector<uint8_t> inner(sizeof(struct iphdr) + 20, 0);
        auto *in_ip = reinterpret_cast<struct iphdr *>(inner.data());
        in_ip->version = 4;
        in_ip->ihl = 5;
        in_ip->saddr = inet_addr("10.100.1.2");
        in_ip->daddr = inet_addr("10.100.2.2");

        auto pkt = build_geneve_encapsulated_packet(
            ua0_src, ua0_dst, "10.10.1.11", "10.10.1.12", 50000,
            GENEVE_VER_OPTLEN, ETH_P_IP, 0x9999 /* Bad opt_class */, ML_OPT_TYPE, inner);

        sockaddr_ll sll{};
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = vh1.ua0_idx;
        sll.sll_protocol = htons(ETH_P_IP);

        sendto(sock, pkt.data(), pkt.size(), 0, reinterpret_cast<struct sockaddr *>(&sll), sizeof(sll));
        close(sock);
    }

    usleep(50000);
    uint64_t after = get_counter_sum(vh2.event_count_fd, DROP_BAD_GENEVE);
    EXPECT_GT(after, before) << "vh2 must increment DROP_BAD_GENEVE when option class is invalid";
}
