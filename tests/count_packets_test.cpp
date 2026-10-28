#include <gtest/gtest.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <net/if.h>
#include <fcntl.h>
#include <sched.h>
#include <unistd.h>
#include <cstdlib>
#include <array>
#include <cstdint>
#include <cerrno>
#include <cstring>
#include <string>
#include <vector>

extern "C" {
#include "count_packets.skel.h"
}

// RAII helper to switch into a network namespace and automatically return on scope exit.
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

// RAII helper to attach a TC ingress hook and guarantee cleanup on test completion or failure.
class TcHookGuard {
    bpf_tc_hook hook{};
    bpf_tc_opts opts{};
    bool attached = false;
    bool created_hook = false;

public:
    bool attach(int ifindex, int prog_fd, uint32_t handle = 1, uint32_t priority = 1) {
        hook.sz = sizeof(hook);
        hook.ifindex = ifindex;
        hook.attach_point = BPF_TC_INGRESS;

        int err = bpf_tc_hook_create(&hook);
        if (err == 0) {
            created_hook = true;
        } else if (err != -EEXIST) {
            return false;
        }

        opts.sz = sizeof(opts);
        opts.prog_fd = prog_fd;
        opts.handle = handle;
        opts.priority = priority;

        err = bpf_tc_attach(&hook, &opts);
        if (err == 0) {
            attached = true;
            return true;
        }
        return false;
    }

    ~TcHookGuard() {
        if (attached) {
            opts.prog_fd = 0; // prog_fd must be 0 for detach
            bpf_tc_detach(&hook, &opts);
        }
        if (created_hook) {
            bpf_tc_hook_destroy(&hook);
        }
    }
};

// Helper to sum per-CPU packet counter values from the BPF map.
static uint64_t get_packet_count(int map_fd, uint32_t ifindex) {
    int ncpus = libbpf_num_possible_cpus();
    if (ncpus <= 0) return 0;
    std::vector<uint64_t> values(static_cast<size_t>(ncpus), 0);
    if (bpf_map_lookup_elem(map_fd, &ifindex, values.data()) != 0) {
        return 0;
    }
    uint64_t total = 0;
    for (uint64_t v : values) total += v;
    return total;
}

// -------------------------------------------------------------
// REAL TOPOLOGY INTEGRATION TESTS
// -------------------------------------------------------------

TEST(CountPacketsRealTopology, ContainerIngressCountsPing)
{
    NetNsGuard ns("c21");
    if (!ns.is_active()) {
        GTEST_SKIP() << "Skipping: netns c21 not found (run sudo scripts/lab-up.sh && sudo scripts/overlay-b1.sh first)";
    }

    unsigned int eth0_idx = if_nametoindex("eth0");
    ASSERT_GT(eth0_idx, 0u) << "eth0 not found in c21";

    // Warm up ARP before attaching counter so count reflects pure ICMP
    (void)std::system("ip netns exec c11 ping -c 1 -W 1 10.100.2.2 >/dev/null 2>&1");

    count_packets_bpf *skel = count_packets_bpf__open_and_load();
    ASSERT_NE(skel, nullptr);

    TcHookGuard tc;
    ASSERT_TRUE(tc.attach(static_cast<int>(eth0_idx), bpf_program__fd(skel->progs.count_packets)));

    // Send 5 pings from c11 to c21
    int ping_ret = std::system("ip netns exec c11 ping -c 5 -W 2 -i 0.2 10.100.2.2 >/dev/null 2>&1");
    EXPECT_EQ(ping_ret, 0);

    int map_fd = bpf_map__fd(skel->maps.packets);
    uint64_t count = get_packet_count(map_fd, eth0_idx);
    EXPECT_EQ(count, 5ULL) << "c21 eth0 should count exactly 5 incoming ICMP requests";

    count_packets_bpf__destroy(skel);
}

TEST(CountPacketsRealTopology, OverlayVxlanIngressCountsPackets)
{
    NetNsGuard ns("vh2");
    if (!ns.is_active()) {
        GTEST_SKIP() << "Skipping: netns vh2 not found";
    }

    unsigned int vxlan_idx = if_nametoindex("vxlan100");
    ASSERT_GT(vxlan_idx, 0u) << "vxlan100 not found in vh2";

    // Warm up ARP
    (void)std::system("ip netns exec c11 ping -c 1 -W 1 10.100.2.2 >/dev/null 2>&1");

    count_packets_bpf *skel = count_packets_bpf__open_and_load();
    ASSERT_NE(skel, nullptr);

    TcHookGuard tc;
    ASSERT_TRUE(tc.attach(static_cast<int>(vxlan_idx), bpf_program__fd(skel->progs.count_packets)));

    int ping_ret = std::system("ip netns exec c11 ping -c 5 -W 2 -i 0.2 10.100.2.2 >/dev/null 2>&1");
    EXPECT_EQ(ping_ret, 0);

    int map_fd = bpf_map__fd(skel->maps.packets);
    uint64_t count = get_packet_count(map_fd, vxlan_idx);
    EXPECT_GE(count, 5ULL) << "vh2 vxlan100 should count decapsulated overlay packets";

    count_packets_bpf__destroy(skel);
}

TEST(CountPacketsRealTopology, UnderlayPlaneAIngressCountsEncapsulatedPackets)
{
    NetNsGuard ns("vh2");
    if (!ns.is_active()) {
        GTEST_SKIP() << "Skipping: netns vh2 not found";
    }

    unsigned int ua0_idx = if_nametoindex("ua0");
    ASSERT_GT(ua0_idx, 0u) << "ua0 not found in vh2";

    count_packets_bpf *skel = count_packets_bpf__open_and_load();
    ASSERT_NE(skel, nullptr);

    TcHookGuard tc;
    ASSERT_TRUE(tc.attach(static_cast<int>(ua0_idx), bpf_program__fd(skel->progs.count_packets)));

    int ping_ret = std::system("ip netns exec c11 ping -c 5 -W 2 -i 0.2 10.100.2.2 >/dev/null 2>&1");
    EXPECT_EQ(ping_ret, 0);

    int map_fd = bpf_map__fd(skel->maps.packets);
    uint64_t count = get_packet_count(map_fd, ua0_idx);
    EXPECT_GE(count, 5ULL) << "vh2 ua0 should count incoming encapsulated underlay UDP packets";

    count_packets_bpf__destroy(skel);
}

TEST(CountPacketsRealTopology, UnderlayPlaneBIsolationCountsZero)
{
    NetNsGuard ns("vh2");
    if (!ns.is_active()) {
        GTEST_SKIP() << "Skipping: netns vh2 not found";
    }

    unsigned int ub0_idx = if_nametoindex("ub0");
    ASSERT_GT(ub0_idx, 0u) << "ub0 not found in vh2";

    count_packets_bpf *skel = count_packets_bpf__open_and_load();
    ASSERT_NE(skel, nullptr);

    TcHookGuard tc;
    ASSERT_TRUE(tc.attach(static_cast<int>(ub0_idx), bpf_program__fd(skel->progs.count_packets)));

    // Send traffic over Plane A
    int ping_ret = std::system("ip netns exec c11 ping -c 5 -W 2 -i 0.2 10.100.2.2 >/dev/null 2>&1");
    EXPECT_EQ(ping_ret, 0);

    int map_fd = bpf_map__fd(skel->maps.packets);
    uint64_t count = get_packet_count(map_fd, ub0_idx);
    EXPECT_EQ(count, 0ULL) << "ub0 must not receive Plane A VXLAN traffic (isolation check)";

    count_packets_bpf__destroy(skel);
}

// -------------------------------------------------------------
// PURE UNIT TEST (FAST SYNTHETIC TEST)
// -------------------------------------------------------------

TEST(CountPacketsUnit, SyntheticLoopbackTestRun)
{
    count_packets_bpf *skel = count_packets_bpf__open_and_load();
    ASSERT_NE(skel, nullptr);

    unsigned int lo_ifindex = if_nametoindex("lo");
    ASSERT_GT(lo_ifindex, 0u);

    std::array<uint8_t, 64> packet{};
    auto output = packet;
    __sk_buff ctx{};
    ctx.ifindex = lo_ifindex;

    bpf_test_run_opts opts{};
    opts.sz = sizeof(opts);
    opts.data_in = packet.data();
    opts.data_size_in = packet.size();
    opts.data_out = output.data();
    opts.data_size_out = output.size();
    opts.ctx_in = &ctx;
    opts.ctx_size_in = sizeof(ctx);

    for (int i = 0; i < 5; ++i) {
        opts.data_size_out = output.size();
        int err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.count_packets), &opts);
        ASSERT_EQ(err, 0);
        EXPECT_EQ(opts.retval, TC_ACT_OK);
    }

    int map_fd = bpf_map__fd(skel->maps.packets);
    uint64_t total = get_packet_count(map_fd, lo_ifindex);
    EXPECT_EQ(total, 5ULL);

    count_packets_bpf__destroy(skel);
}
