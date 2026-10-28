#pragma once
#include <linux/bpf.h>

// For Geneve headers and options 
#define GENEVE_UDP_PORT	6081
#define ETH_P_IP	0x0800
#define ML_OPT_CLASS	0xFF01
#define ML_OPT_TYPE	0
#define GENEVE_VER_OPTLEN 0x05		// ver=0, opt_len=5 4-byte words (20B option)
#define OUTER_LEN (20 + 8 + 8 + 20)	// 56

// Event codes
#define OK_INGRESS	1
#define OK_EGRESS	2
#define DROP_NOT_IPV4	3
#define DROP_BAD_GENEVE 4
#define DROP_NO_PEER	5
#define DROP_NO_VETH	6
#define DROP_PARSE_FAIL 7
#define DROP_BAD_CSUM	8
#define DROP_ADJUST_ROOM 9

// For path_tbl
#define MAX_PEERS 8
#define MAX_PATHS 64 


struct geneve_hdr {		// 8 bytes
	__u8   ver_optlen;	// ver=0 in top 2 bits, opt_len in low 6 bits = 5 words
	__u8   flags;
	__be16 proto;		// 0x0800 = inner is IPv4
	__u8   vni[3];
	__u8   rsvd;
};

struct ml_opt {			// 20 bytes
	__be16 opt_class;	// experimental range, e.g. 0xFF01
	__u8   type;
	__u8   len_words;	// data length in 4-byte words = 4
	__u8   cls, flags, path_id, rsvd;	// traffic class, ctrl bits, underlay id (0=A,1=B), reserved
	__be32 tunnel_seq, path_seq, tx_ts_us;
};

struct peer_info {
	__u32 local_ip; 	// Outer src IP: 10.10.1.11 (this host's ua0)
	__u32 peer_ip;		// Outer dst IP: 10.10.1.12 (remote host's ua0)
	unsigned char src_mac[6];     // Local ua0 MAC
	unsigned char dst_mac[6];     // Remote ua0 MAC (or gateway MAC)
	__u32 ua0_ifindex;	// Interface index of ua0 to redirect packet to
	__u32 peer_id;		// Dense index assigned by agent (0..MAX_PEERS-1)
};

struct veth_info {
	__u32 veth_ifindex;		// Host-side veth ifindex (e.g., h21)
	unsigned char container_mac[6]; // MAC of c21's eth0
	unsigned char gw_mac[6];	// MAC of gateway
};

struct ipv4_lpm_key {
	__u32 prefixlen;	// u32 is an ABI requirement
	__be32 addr;
};

#define PATH_UP       1
#define PATH_DEGRADED 2
#define PATH_DOWN     3

#define PATH_KEY(peer_id, path_id) \
	((((__u32)(peer_id)) << 1) | (((__u32)(path_id)) & 1))

#define PATH_TBL_KEY(ver, peer_id, path_id) \
	(((((__u32)(ver)) & 1) << 4) | (((__u32)(peer_id)) << 1) | (((__u32)(path_id)) & 1))

struct path_entry {
	__u32 ifindex;		// ua0 or ub0 ifindex
	__u32 src_ip;		// underlay outer src IP
	__u32 dst_ip;		// underlay outer dst IP
	unsigned char src_mac[6]; // local outer MAC
	unsigned char dst_mac[6]; // remote router/peer MAC
	__u32 state;		// PATH_UP (1), PATH_DEGRADED (2), PATH_DOWN (3)
	__u32 path_id;		// 0 (Plane A) or 1 (Plane B)
	__u32 is_primary;	// 1 if chosen primary for this peer	
};

struct path_stats {
	__u64 rx_packets;	// Total valid packets received on this path
	__u64 rx_bytes;		// Total bytes received on this path
	__u64 seq_gaps;		// Number of forward jumps / packet loss events
	__u64 seq_lost_pkts;	// Total count of lost packets estimated from gaps
	__u64 seq_ooo;		// Out-of-order packets received (seq < expected)
};

struct rx_tracker {
	__u32 expected_seq;
	__u32 initialized;
};

#ifdef __bpf__
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 256);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct ipv4_lpm_key);
	__type(value, struct peer_info);
} peer_tbl SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, struct veth_info);
} veth_tbl SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 32);
	__type(key, __u32);
	__type(value, __u64);
} event_count SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} ctl_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2 * MAX_PEERS * 2);
	__type(key, __u32);	// version << 4 | peer_id << 1 | path_id 
	__type(value, struct path_entry);
} path_tbl SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, MAX_PEERS * 2);	// (peer_id << 1) | path_id
	__type(key, __u32);
	__type(value, struct path_stats);
} stats_path SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_PEERS * 2);
	__type(key, __u32);	// peer_id << 1 | path_id
	__type(value, struct rx_tracker);
} rx_seq_tracker SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_PEERS);
	__type(key, __u32);	// peer_id
	__type(value, __u32);
} peer_tunnel_seq SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_PEERS * 2);
	__type(key, __u32);	// peer_id << 1 | path_id
	__type(value, __u32);
} path_seq SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_PEERS);
	__type(key, __u32);		// peer underlay IP (network byte order)
	__type(value, __u32);		// local peer_id (0..MAX_PEERS-1)
} peer_ip_to_id SEC(".maps");

#endif
