#include <bpf/bpf.h>
#include <net/if.h>
#include <signal.h>
#include <unistd.h>
#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

extern "C" {
#include "count_packets.skel.h"
}

static volatile sig_atomic_t stop = 0;
static void on_signal(int) { stop = 1; }

int main(int argc, char **argv)
{
    if (argc != 2) {
        std::fprintf(stderr, "usage: %s IFACE\n", argv[0]);
        return 2;
    }
    unsigned int ifindex = if_nametoindex(argv[1]);
    if (!ifindex) { std::perror("if_nametoindex"); return 2; }

    count_packets_bpf *skel = count_packets_bpf__open();
    if (!skel) { std::fprintf(stderr, "failed to open BPF skeleton\n"); return 1; }
    int err = count_packets_bpf__load(skel);
    if (err) {
        std::fprintf(stderr, "BPF load failed: %s (check privileges/kernel support)\n", std::strerror(-err));
        count_packets_bpf__destroy(skel);
        return 1;
    }

    bpf_tc_hook hook{};
    hook.sz = sizeof(hook);
    hook.ifindex = static_cast<int>(ifindex);
    hook.attach_point = BPF_TC_INGRESS;
    bool created_hook = false;
    err = bpf_tc_hook_create(&hook);
    if (err == 0) created_hook = true;
    else if (err != -EEXIST) {
        std::fprintf(stderr, "bpf_tc_hook_create: %s\n", std::strerror(-err));
        count_packets_bpf__destroy(skel);
        return 1;
    }

    bpf_tc_opts opts{};
    opts.sz = sizeof(opts);
    opts.prog_fd = bpf_program__fd(skel->progs.count_packets);
    opts.handle = 1;
    opts.priority = 1;
    err = bpf_tc_attach(&hook, &opts);
    if (err) {
        std::fprintf(stderr, "bpf_tc_attach: %s\n", std::strerror(-err));
        if (created_hook) bpf_tc_hook_destroy(&hook);
        count_packets_bpf__destroy(skel);
        return 1;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    std::printf("Counting ingress packets on %s (ifindex %u); Ctrl-C to stop\n", argv[1], ifindex);
    int ncpus = libbpf_num_possible_cpus();
    if (ncpus <= 0) {
        std::fprintf(stderr, "libbpf_num_possible_cpus failed\n");
        bpf_tc_detach(&hook, &opts);
        if (created_hook) bpf_tc_hook_destroy(&hook);
        count_packets_bpf__destroy(skel);
        return 1;
    }
    std::vector<uint64_t> values(static_cast<size_t>(ncpus));
    uint32_t key = ifindex;
    int map_fd = bpf_map__fd(skel->maps.packets);
    while (!stop) {
        sleep(1);
        std::fill(values.begin(), values.end(), 0);
        if (bpf_map_lookup_elem(map_fd, &key, values.data()) == 0) {
            uint64_t total = 0;
            for (uint64_t v : values) total += v;
            std::printf("%s ifindex=%u packets=%llu\n", argv[1], ifindex,
                        static_cast<unsigned long long>(total));
        } else if (errno == ENOENT) {
            std::printf("%s ifindex=%u packets=0 (no packet seen yet)\n", argv[1], ifindex);
        } else std::perror("bpf_map_lookup_elem");
        std::fflush(stdout);
    }
    err = bpf_tc_detach(&hook, &opts);
    if (err) std::fprintf(stderr, "warning: detach: %s\n", std::strerror(-err));
    if (created_hook) bpf_tc_hook_destroy(&hook);
    count_packets_bpf__destroy(skel);
    return 0;
}
