#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"

char LICENSE[] SEC("license") = "GPL";

static __always_inline void increment_counter(__u32 reason) {
	__u64 *count = bpf_map_lookup_elem(&event_count, &reason);
	if (count) {
		*count += 1;
	}
}

static __always_inline void compute_ipv4_checksum(struct iphdr *ip)
{
    ip->check = 0;
    __u32 sum = 0;
    const __u16 *p = (const __u16 *)ip;

    #pragma unroll
    for (int i = 0; i < 10; i++) {
        sum += p[i];
    }

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);

    ip->check = (__sum16)~sum;
}

SEC("tc")
int ingress_decap(struct __sk_buff *skb) {
	void *data, *data_end;
	
	data = (void *)(__u64) skb->data;
	data_end = (void *)(__u64) skb->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		increment_counter(DROP_PARSE_FAIL);
		return TC_ACT_SHOT;
	}

	// Might be ARP
        if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        	return TC_ACT_OK;
        }

        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end) {
        	increment_counter(DROP_PARSE_FAIL);
        	return TC_ACT_SHOT;
        }

  	// Only process UDP packets (Geneve is UDP). Let TCP/ICMP on the host pass through.
        if (ip->protocol != IPPROTO_UDP) {
        	return TC_ACT_OK;
        }

	// If not a 20 byte header, drop
        if (ip->ihl < 5) {
            increment_counter(DROP_PARSE_FAIL);
            return TC_ACT_SHOT;
        }

        struct udphdr *udp = (void *)((__u8 *)ip + (ip->ihl * 4));
        if ((void *)(udp + 1) > data_end) {
            increment_counter(DROP_PARSE_FAIL);
            return TC_ACT_SHOT;
        }

	// Only intercept Geneve port 6081. Let other UDP traffic pass through untouched!
        if (udp->dest != bpf_htons(GENEVE_UDP_PORT)) {
            return TC_ACT_OK;
        }
	
	struct geneve_hdr * gnv = (void *) (udp + 1);
	struct ml_opt *opts = (void *) (gnv + 1);

	if ((void *)(opts + 1) > data_end) {
		increment_counter(DROP_PARSE_FAIL);
		return TC_ACT_SHOT;
	}

	if (gnv->ver_optlen != GENEVE_VER_OPTLEN || gnv->proto != bpf_htons(ETH_P_IP)) {
		increment_counter(DROP_BAD_GENEVE);
		return TC_ACT_SHOT;
	}

	if (opts->opt_class != bpf_htons(ML_OPT_CLASS) || opts->type != ML_OPT_TYPE) {
		increment_counter(DROP_BAD_GENEVE);
		return TC_ACT_SHOT;
	}

	__u8 rx_path_id = opts->path_id;
	__u32 rx_seq = bpf_ntohl(opts->path_seq);
	// Identify sender by outer source IP — peer_id is a local index,
	// never transmitted on the wire.
	__u32 outer_src = ip->saddr;
	__u32 *p_peer_id = bpf_map_lookup_elem(&peer_ip_to_id, &outer_src);
	__u32 rx_peer_id = p_peer_id ? *p_peer_id : 0;
	__u32 stats_key = PATH_KEY(rx_peer_id, rx_path_id);

	struct path_stats *stats = bpf_map_lookup_elem(&stats_path, &stats_key);
	if (stats) {
		stats->rx_packets++;
		stats->rx_bytes += skb->len;
	}

	struct rx_tracker *trk = bpf_map_lookup_elem(&rx_seq_tracker, &stats_key);
	if (trk) {
		if (!trk->initialized) {
			trk->initialized = 1;
			trk->expected_seq = rx_seq + 1;
		} else {
			if (rx_seq == trk->expected_seq) {
				trk->expected_seq = rx_seq + 1;
			} else if ((__s32)(rx_seq - trk->expected_seq) > 0) {
				if (stats) {
					stats->seq_gaps++;
					stats->seq_lost_pkts += (rx_seq - trk->expected_seq);
				}
				trk->expected_seq = rx_seq + 1;
			} else {
				if (stats) {
					stats->seq_ooo++;
				}
			}
		}
	}

	struct iphdr *inner_ip = (void *)(opts + 1);

	if ((void *)(inner_ip + 1) > data_end) {
		increment_counter(DROP_PARSE_FAIL);
		return TC_ACT_SHOT;
	}

	__u32 inner_dst_addr = inner_ip->daddr;
	struct veth_info *vethinf;

	vethinf = bpf_map_lookup_elem(&veth_tbl, &inner_dst_addr);
	if (vethinf == NULL) {
		increment_counter(DROP_NO_VETH);
		return TC_ACT_SHOT;
	}

	__u32 veth_ifindex = vethinf->veth_ifindex;
	unsigned char container_mac[6];
	unsigned char gw_mac[6];

	__builtin_memcpy(container_mac, vethinf->container_mac, ETH_ALEN);
	__builtin_memcpy(gw_mac, vethinf->gw_mac, ETH_ALEN);

	// Strip the Outer IP header and Genever header and opts
	int err = bpf_skb_adjust_room(skb, -OUTER_LEN, BPF_ADJ_ROOM_MAC, 0);

	if (err != 0) {
		return TC_ACT_SHOT;
	}

	// All the pointers are invalidated by the verifier after adjust_room
	data = (void *)(__u64)(skb->data);
	data_end = (void *)(__u64)(skb->data_end);

	if (data + sizeof (struct ethhdr) > data_end) {
		increment_counter(DROP_PARSE_FAIL);
		return TC_ACT_SHOT;
	}

	eth = (void *)(__u64)data;
	__builtin_memcpy(eth->h_dest, container_mac, ETH_ALEN);
	__builtin_memcpy(eth->h_source, gw_mac, ETH_ALEN);
	eth->h_proto = bpf_htons(ETH_P_IP);

	increment_counter(OK_INGRESS);
	
	return bpf_redirect_peer(veth_ifindex, 0);
}

SEC("tc")
int egress_encap(struct __sk_buff *skb) {
	void *data = (void *)(__u64)skb->data;
	void *data_end = (void *)(__u64)skb->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		increment_counter(DROP_PARSE_FAIL);
		return TC_ACT_SHOT;
	}

	// Non-IPv4 (e.g. ARP) from container passes to local bridge
	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		return TC_ACT_OK;
	}

	struct iphdr *inner_ip = (void *)(eth + 1);
	if ((void *)(inner_ip + 1) > data_end) {
		increment_counter(DROP_PARSE_FAIL);
		return TC_ACT_SHOT;
	}

	// Lookup destination in peer_tbl (LPM trie)
	struct ipv4_lpm_key key = {
		.prefixlen = 32,
		.addr = inner_ip->daddr
	};
	struct peer_info *pinfo = bpf_map_lookup_elem(&peer_tbl, &key);
	if (!pinfo) {
		// Miss: local container on same host or local gateway, let bridge handle it
		return TC_ACT_OK;
	}

	// peer_id comes from the LPM lookup result — agent assigns a dense
	// index per remote subnet at startup, so this works for any topology.
	__u32 peer_id = pinfo->peer_id;

	// Read active version from ctl_map (default 0)
	__u32 ctl_k = 0;
	__u32 *p_ver = bpf_map_lookup_elem(&ctl_map, &ctl_k);
	__u32 active_ver = p_ver ? (*p_ver & 1) : 0;

	// Look up primary path in active path_tbl
	__u32 key_a = PATH_TBL_KEY(active_ver, peer_id, 0);
	__u32 key_b = PATH_TBL_KEY(active_ver, peer_id, 1);
	struct path_entry *entry_a = bpf_map_lookup_elem(&path_tbl, &key_a);
	struct path_entry *entry_b = bpf_map_lookup_elem(&path_tbl, &key_b);

	struct path_entry *chosen = 0;
	if (entry_a && entry_a->is_primary && entry_a->state == PATH_UP) {
		chosen = entry_a;
	} else if (entry_b && entry_b->is_primary && entry_b->state == PATH_UP) {
		chosen = entry_b;
	} else if (entry_a && entry_a->state == PATH_UP) {
		chosen = entry_a;
	} else if (entry_b && entry_b->state == PATH_UP) {
		chosen = entry_b;
	} else if (entry_a && entry_a->state == PATH_DEGRADED) {
		chosen = entry_a;
	} else if (entry_b && entry_b->state == PATH_DEGRADED) {
		chosen = entry_b;
	}

	__u32 local_ip, peer_ip, redirect_ifindex;
	__u8 chosen_path_id;
	unsigned char src_mac[ETH_ALEN];
	unsigned char dst_mac[ETH_ALEN];

	if (chosen) {
		local_ip = chosen->src_ip;
		peer_ip = chosen->dst_ip;
		redirect_ifindex = chosen->ifindex;
		chosen_path_id = (__u8)chosen->path_id;
		__builtin_memcpy(src_mac, chosen->src_mac, ETH_ALEN);
		__builtin_memcpy(dst_mac, chosen->dst_mac, ETH_ALEN);
	} else {
		// Fallback to legacy peer_info (for backward compatibility with M2 tests)
		local_ip = pinfo->local_ip;
		peer_ip = pinfo->peer_ip;
		redirect_ifindex = pinfo->ua0_ifindex;
		chosen_path_id = 0;
		__builtin_memcpy(src_mac, pinfo->src_mac, ETH_ALEN);
		__builtin_memcpy(dst_mac, pinfo->dst_mac, ETH_ALEN);
	}

	// Compute UDP source port from inner 5-tuple for underlay ECMP entropy
	__u32 hash = inner_ip->saddr ^ inner_ip->daddr ^ inner_ip->protocol;
	if ((inner_ip->protocol == IPPROTO_TCP || inner_ip->protocol == IPPROTO_UDP) &&
	    (void *)((__u8 *)inner_ip + (inner_ip->ihl * 4) + 4) <= data_end) {
		__be16 *ports = (void *)((__u8 *)inner_ip + (inner_ip->ihl * 4));
		hash ^= ((__u32)ports[0] << 16) | ports[1];
	}
	__u16 src_port = 49152 + (hash % 16384);

	// Expand packet headroom by 56 bytes for outer headers
	int err = bpf_skb_adjust_room(skb, OUTER_LEN, BPF_ADJ_ROOM_MAC, 0);
	if (err != 0) {
		increment_counter(DROP_ADJUST_ROOM);
		return TC_ACT_SHOT;
	}

	// Pointers are invalidated after adjust_room, re-fetch
	data = (void *)(__u64)skb->data;
	data_end = (void *)(__u64)skb->data_end;

	if (data + sizeof(struct ethhdr) + OUTER_LEN > data_end) {
		increment_counter(DROP_PARSE_FAIL);
		return TC_ACT_SHOT;
	}

	eth = data;
	struct iphdr *outer_ip = (void *)(eth + 1);
	struct udphdr *outer_udp = (void *)(outer_ip + 1);
	struct geneve_hdr *gnv = (void *)(outer_udp + 1);
	struct ml_opt *opt = (void *)(gnv + 1);

	// Format Outer IPv4 header
	outer_ip->version = 4;
	outer_ip->ihl = 5;
	outer_ip->tos = 0;
	outer_ip->tot_len = bpf_htons(skb->len - sizeof(struct ethhdr));
	outer_ip->id = 0;
	outer_ip->frag_off = bpf_htons(0x4000); // DF bit
	outer_ip->ttl = 64;
	outer_ip->protocol = IPPROTO_UDP;
	outer_ip->saddr = local_ip;
	outer_ip->daddr = peer_ip;
	compute_ipv4_checksum(outer_ip);

	// Format Outer UDP header
	outer_udp->source = bpf_htons(src_port);
	outer_udp->dest = bpf_htons(GENEVE_UDP_PORT);
	outer_udp->len = bpf_htons(skb->len - sizeof(struct ethhdr) - sizeof(struct iphdr));
	outer_udp->check = 0; // Checksum 0 is legal in IPv4 UDP

	// Format Geneve header
	gnv->ver_optlen = GENEVE_VER_OPTLEN; // 0x05 (ver 0, opt_len 5 words)
	gnv->flags = 0;
	gnv->proto = bpf_htons(ETH_P_IP);
	gnv->vni[0] = 0;
	gnv->vni[1] = 0;
	gnv->vni[2] = 100;
	gnv->rsvd = 0;

	// Format MeshLink Option
	opt->opt_class = bpf_htons(ML_OPT_CLASS);
	opt->type = ML_OPT_TYPE;
	opt->len_words = 4;
	opt->cls = 0;
	opt->flags = 0;
	opt->path_id = chosen_path_id;
	opt->rsvd = 0;

	// Per-peer tunnel_seq atomic increment
	__u32 *p_tseq = bpf_map_lookup_elem(&peer_tunnel_seq, &peer_id);
	if (p_tseq) {
		opt->tunnel_seq = bpf_htonl(__sync_fetch_and_add(p_tseq, 1));
	} else {
		opt->tunnel_seq = 0;
	}

	// Per-path path_seq atomic increment
	__u32 path_key = PATH_KEY(peer_id, chosen_path_id);
	__u32 *p_pseq = bpf_map_lookup_elem(&path_seq, &path_key);
	if (p_pseq) {
		opt->path_seq = bpf_htonl(__sync_fetch_and_add(p_pseq, 1));
	} else {
		opt->path_seq = 0;
	}

	opt->tx_ts_us = bpf_htonl((__u32)(bpf_ktime_get_ns() / 1000));

	// Rewrite outer Ethernet header
	__builtin_memcpy(eth->h_dest, dst_mac, ETH_ALEN);
	__builtin_memcpy(eth->h_source, src_mac, ETH_ALEN);
	eth->h_proto = bpf_htons(ETH_P_IP);

	increment_counter(OK_EGRESS);
	return bpf_redirect(redirect_ifindex, 0);
}
