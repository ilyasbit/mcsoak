//go:build ignore

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TARGET_PORT 7777

struct pulse_event {
    __u64 timestamp_ns;
    __u8  src_ip[16];
    __u16 src_port;
    __u8  proto;
    __u8  ip_version;
    __u8  flags;
    __u8  pad[3];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} pulse_events SEC(".maps");

static __always_inline void emit_pulse_event_v4(__u32 src_ip, __u16 src_port_be, __u8 proto, __u8 flags) {
    struct pulse_event *ev = bpf_ringbuf_reserve(&pulse_events, sizeof(*ev), 0);
    if (!ev) {
        return;
    }
    __builtin_memset(ev, 0, sizeof(*ev));
    ev->timestamp_ns = bpf_ktime_get_ns();
    __builtin_memcpy(ev->src_ip, &src_ip, 4);
    ev->src_port = bpf_ntohs(src_port_be);
    ev->proto = proto;
    ev->ip_version = 4;
    ev->flags = flags;
    bpf_ringbuf_submit(ev, 0);
}

static __always_inline void emit_pulse_event_v6(const struct in6_addr *src_ip, __u16 src_port_be, __u8 proto, __u8 flags) {
    struct pulse_event *ev = bpf_ringbuf_reserve(&pulse_events, sizeof(*ev), 0);
    if (!ev) {
        return;
    }
    __builtin_memset(ev, 0, sizeof(*ev));
    ev->timestamp_ns = bpf_ktime_get_ns();
    __builtin_memcpy(ev->src_ip, src_ip, 16);
    ev->src_port = bpf_ntohs(src_port_be);
    ev->proto = proto;
    ev->ip_version = 6;
    ev->flags = flags;
    bpf_ringbuf_submit(ev, 0);
}

static __always_inline __u16 csum_fold_helper(__u32 csum) {
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    return (__u16)~csum;
}

static __always_inline __u16 csum_tcp_udp_helper(struct iphdr *iph, void *l4_hdr, void *data_end, __u8 proto) {
    __u32 csum = 0;
    
    // Add Pseudo Header
    csum += iph->saddr & 0xFFFF;
    csum += (iph->saddr >> 16) & 0xFFFF;
    csum += iph->daddr & 0xFFFF;
    csum += (iph->daddr >> 16) & 0xFFFF;
    csum += bpf_htons(proto);
    
    __u16 l4_len = (void *)data_end - l4_hdr;
    csum += bpf_htons(l4_len);

    // Add TCP/UDP header and payload
    __u16 *ptr = l4_hdr;
    
    // Bounded loop for eBPF verifier (max 256 bytes)
    #pragma clang loop unroll(full)
    for (int i = 0; i < 128; i++) {
        if ((void *)(ptr + 1) > data_end) {
            break;
        }
        csum += *ptr++;
    }

    if ((void *)ptr < data_end) {
        __u8 *odd_byte = (__u8 *)ptr;
        csum += bpf_htons((*odd_byte) << 8);
    }

    return csum_fold_helper(csum);
}

static __always_inline __u16 csum_ipv6_helper(struct ipv6hdr *ip6h, void *l4_hdr, void *data_end, __u8 proto) {
    __u32 csum = 0;
    
    // Add IPv6 source address (8 16-bit words)
    __u16 *src = (__u16 *)&ip6h->saddr;
    #pragma clang loop unroll(full)
    for (int i = 0; i < 8; i++) {
        csum += src[i];
    }
    // Add IPv6 destination address
    __u16 *dst = (__u16 *)&ip6h->daddr;
    #pragma clang loop unroll(full)
    for (int i = 0; i < 8; i++) {
        csum += dst[i];
    }
    
    // Add length and protocol
    __u32 l4_len = (void *)data_end - l4_hdr;
    csum += bpf_htons(l4_len);
    csum += bpf_htons(proto);
    
    // Add L4 header and payload (max 256 bytes)
    __u16 *ptr = l4_hdr;
    #pragma clang loop unroll(full)
    for (int i = 0; i < 128; i++) {
        if ((void *)(ptr + 1) > data_end) {
            break;
        }
        csum += *ptr++;
    }
    if ((void *)ptr < data_end) {
        __u8 *odd_byte = (__u8 *)ptr;
        csum += bpf_htons((*odd_byte) << 8);
    }
    return csum_fold_helper(csum);
}

SEC("xdp")
int xdp_pulse_reflector(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end) return XDP_PASS;
        if (iph->ihl < 5) return XDP_PASS;

        if (iph->protocol == IPPROTO_UDP) {
            struct udphdr *udph = (void *)iph + (iph->ihl * 4);
            if ((void *)(udph + 1) > data_end) return XDP_PASS;

            if (udph->dest == bpf_htons(TARGET_PORT)) {
                __u32 client_ip = iph->saddr;
                __u16 client_port_be = udph->source;
                __u8 *payload = (void *)(udph + 1);
                int has_magic = 0;

                if ((void *)(payload + 4) <= data_end) {
                    if (payload[0] == 'M' && payload[1] == 'C' && payload[2] == 'P' &&
                        (payload[3] == 0 || payload[3] == 1)) {
                        has_magic = 1;
                    }
                }

                if (has_magic) {
                    if ((void *)(payload + 6) <= data_end) {
                        __builtin_memcpy(payload, &client_ip, 4);
                        __builtin_memcpy(payload + 4, &client_port_be, 2);
                    } else if ((void *)(payload + 4) <= data_end) {
                        __builtin_memcpy(payload, &client_ip, 4);
                    }
                } else {
                    // Legacy packet: expand packet tail by 4 bytes for IP payload
                    if (bpf_xdp_adjust_tail(ctx, 4) != 0) {
                        return XDP_PASS;
                    }

                    // Re-evaluate boundaries after tail adjustment
                    data = (void *)(long)ctx->data;
                    data_end = (void *)(long)ctx->data_end;
                    eth = data;
                    if ((void *)(eth + 1) > data_end) return XDP_DROP;
                    iph = (void *)(eth + 1);
                    if ((void *)(iph + 1) > data_end) return XDP_DROP;
                    if (iph->ihl < 5) return XDP_DROP;
                    udph = (void *)iph + (iph->ihl * 4);
                    if ((void *)(udph + 1) > data_end) return XDP_DROP;

                    __u32 *legacy_payload = (void *)(udph + 1);
                    if ((void *)(legacy_payload + 1) > data_end) return XDP_DROP;

                    // Write client's public IPv4 address
                    *legacy_payload = client_ip;
                }

                emit_pulse_event_v4(client_ip, client_port_be, IPPROTO_UDP, 0);

                // Swap MACs
                __u8 tmp_mac[ETH_ALEN];
                __builtin_memcpy(tmp_mac, eth->h_source, ETH_ALEN);
                __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
                __builtin_memcpy(eth->h_dest, tmp_mac, ETH_ALEN);

                // Swap IPs
                __u32 tmp_ip = iph->saddr;
                iph->saddr = iph->daddr;
                iph->daddr = tmp_ip;

                // Swap Ports
                __u16 tmp_port = udph->source;
                udph->source = udph->dest;
                udph->dest = tmp_port;

                // Update Header Lengths
                __u16 total_ip_len = (void *)data_end - (void *)iph;
                iph->tot_len = bpf_htons(total_ip_len);
                
                __u16 total_udp_len = (void *)data_end - (void *)udph;
                udph->len = bpf_htons(total_udp_len);

                // Recalculate Checksums
                iph->check = 0;
                __u32 csum = 0;
                __u16 *next_iph_u16 = (__u16 *)iph;
                #pragma clang loop unroll(full)
                for (int i = 0; i < sizeof(*iph) >> 1; i++) {
                    csum += *next_iph_u16++;
                }
                iph->check = csum_fold_helper(csum);

                // IPv4 UDP checksum is optional (0 = disabled)
                udph->check = 0;

                return XDP_TX;
            }
        } else if (iph->protocol == IPPROTO_TCP) {
            struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
            if ((void *)(tcph + 1) > data_end) return XDP_PASS;

            if (tcph->dest == bpf_htons(TARGET_PORT)) {
                __u32 client_ip = iph->saddr;

                if (tcph->syn) {
                    if ((bpf_ntohl(tcph->seq) & 0xFF) != 0x4D) {
                        return XDP_DROP;
                    }
                    if ((void *)tcph + 256 < data_end) {
                        return XDP_PASS;
                    }
                    // TCP Handshake Spoofing (SYN -> SYN-ACK)
                    emit_pulse_event_v4(client_ip, tcph->source, IPPROTO_TCP, 0x02);
                    // Swap MACs
                    __u8 tmp_mac[ETH_ALEN];
                    __builtin_memcpy(tmp_mac, eth->h_source, ETH_ALEN);
                    __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
                    __builtin_memcpy(eth->h_dest, tmp_mac, ETH_ALEN);

                    // Swap IPs
                    __u32 tmp_ip = iph->saddr;
                    iph->saddr = iph->daddr;
                    iph->daddr = tmp_ip;

                    // Swap Ports
                    __u16 tmp_port = tcph->source;
                    tcph->source = tcph->dest;
                    tcph->dest = tmp_port;

                    // Sequence Math
                    __u32 client_seq = bpf_ntohl(tcph->seq);
                    tcph->ack_seq = bpf_htonl(client_seq + 1);
                    tcph->seq = bpf_htonl(1000); // Server ISN

                    // Flags
                    tcph->syn = 1;
                    tcph->ack = 1;

                    // Recalculate Checksums
                    iph->check = 0;
                    __u32 csum = 0;
                    __u16 *next_iph_u16 = (__u16 *)iph;
                    #pragma clang loop unroll(full)
                    for (int i = 0; i < sizeof(*iph) >> 1; i++) {
                        csum += *next_iph_u16++;
                    }
                    iph->check = csum_fold_helper(csum);

                    tcph->check = 0;
                    tcph->check = csum_tcp_udp_helper(iph, tcph, data_end, IPPROTO_TCP);

                    return XDP_TX;
                } else if (tcph->ack) {
                    if (tcph->doff < 5) {
                        return XDP_PASS;
                    }
                    void *tcp_end = (void *)tcph + (tcph->doff * 4);
                    if (tcp_end != data_end) {
                        return XDP_PASS;
                    }
                    if ((void *)tcph + 252 < data_end) {
                        return XDP_PASS;
                    }
                    // TCP Keepalive Reflector (ACK -> ACK + IP Payload)
                    if (bpf_xdp_adjust_tail(ctx, 4) != 0) {
                        return XDP_PASS;
                    }

                    // Re-evaluate boundaries after tail adjustment
                    data = (void *)(long)ctx->data;
                    data_end = (void *)(long)ctx->data_end;
                    eth = data;
                    if ((void *)(eth + 1) > data_end) return XDP_DROP;
                    iph = (void *)(eth + 1);
                    if ((void *)(iph + 1) > data_end) return XDP_DROP;
                    if (iph->ihl < 5) return XDP_DROP;
                    tcph = (void *)iph + (iph->ihl * 4);
                    if ((void *)(tcph + 1) > data_end) return XDP_DROP;
                    if (tcph->doff < 5) return XDP_DROP;

                    __u32 *payload = (void *)tcph + (tcph->doff * 4);
                    if ((void *)(payload + 1) > data_end) return XDP_DROP;

                    // Write client's public IP
                    *payload = client_ip;

                    // Save sequences
                    __u32 client_seq = bpf_ntohl(tcph->seq);
                    __u32 client_ack = bpf_ntohl(tcph->ack_seq);

                    // Swap MACs
                    __u8 tmp_mac[ETH_ALEN];
                    __builtin_memcpy(tmp_mac, eth->h_source, ETH_ALEN);
                    __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
                    __builtin_memcpy(eth->h_dest, tmp_mac, ETH_ALEN);

                    // Swap IPs
                    __u32 tmp_ip = iph->saddr;
                    iph->saddr = iph->daddr;
                    iph->daddr = tmp_ip;

                    // Swap Ports
                    __u16 tmp_port = tcph->source;
                    tcph->source = tcph->dest;
                    tcph->dest = tmp_port;

                    // Sequence Inversion
                    tcph->seq = bpf_htonl(client_ack);
                    tcph->ack_seq = bpf_htonl(client_seq);

                    // Flags (Set PSH to push the 4-byte payload to client)
                    tcph->ack = 1;
                    tcph->psh = 1;

                    // Update Lengths
                    __u16 total_ip_len = (void *)data_end - (void *)iph;
                    iph->tot_len = bpf_htons(total_ip_len);

                    // Recalculate Checksums
                    iph->check = 0;
                    __u32 csum = 0;
                    __u16 *next_iph_u16 = (__u16 *)iph;
                    #pragma clang loop unroll(full)
                    for (int i = 0; i < sizeof(*iph) >> 1; i++) {
                        csum += *next_iph_u16++;
                    }
                    iph->check = csum_fold_helper(csum);

                    tcph->check = 0;
                    tcph->check = csum_tcp_udp_helper(iph, tcph, data_end, IPPROTO_TCP);

                    return XDP_TX;
                }
            }
        }
    } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6h = (void *)(eth + 1);
        if ((void *)(ip6h + 1) > data_end) return XDP_PASS;

        if (ip6h->nexthdr == IPPROTO_UDP) {
            struct udphdr *udph = (void *)(ip6h + 1);
            if ((void *)(udph + 1) > data_end) return XDP_PASS;

            if (udph->dest == bpf_htons(TARGET_PORT)) {
                struct in6_addr client_ip = ip6h->saddr;
                __u16 client_port_be = udph->source;
                __u8 *payload = (void *)(udph + 1);
                int has_magic = 0;

                if ((void *)udph + 256 < data_end) {
                    return XDP_PASS;
                }

                if ((void *)(payload + 4) <= data_end) {
                    if (payload[0] == 'M' && payload[1] == 'C' && payload[2] == 'P' &&
                        (payload[3] == 0 || payload[3] == 1)) {
                        has_magic = 1;
                    }
                }

                if (has_magic) {
                    if ((void *)(payload + 18) <= data_end) {
                        __builtin_memcpy(payload, &client_ip, 16);
                        __builtin_memcpy(payload + 16, &client_port_be, 2);
                    } else if ((void *)(payload + 16) <= data_end) {
                        __builtin_memcpy(payload, &client_ip, 16);
                    } else if ((void *)(payload + 4) == data_end) {
                        if (bpf_xdp_adjust_tail(ctx, 12) != 0) {
                            return XDP_PASS;
                        }

                        data = (void *)(long)ctx->data;
                        data_end = (void *)(long)ctx->data_end;
                        eth = data;
                        if ((void *)(eth + 1) > data_end) return XDP_DROP;
                        ip6h = (void *)(eth + 1);
                        if ((void *)(ip6h + 1) > data_end) return XDP_DROP;
                        udph = (void *)(ip6h + 1);
                        if ((void *)(udph + 1) > data_end) return XDP_DROP;

                        payload = (void *)(udph + 1);
                        if ((void *)(payload + 16) > data_end) return XDP_DROP;
                        __builtin_memcpy(payload, &client_ip, 16);
                    } else {
                        return XDP_PASS;
                    }
                } else {
                    // UDP Keepalive Reflector over IPv6 (Expand tail by 16 bytes)
                    if (bpf_xdp_adjust_tail(ctx, 16) != 0) {
                        return XDP_PASS;
                    }

                    // Re-evaluate boundaries after tail adjustment
                    data = (void *)(long)ctx->data;
                    data_end = (void *)(long)ctx->data_end;
                    eth = data;
                    if ((void *)(eth + 1) > data_end) return XDP_DROP;
                    ip6h = (void *)(eth + 1);
                    if ((void *)(ip6h + 1) > data_end) return XDP_DROP;
                    udph = (void *)(ip6h + 1);
                    if ((void *)(udph + 1) > data_end) return XDP_DROP;

                    struct in6_addr *legacy_payload = (void *)(udph + 1);
                    if ((void *)(legacy_payload + 1) > data_end) return XDP_DROP;

                    // Write client's public IPv6 address
                    *legacy_payload = client_ip;
                }

                emit_pulse_event_v6(&client_ip, client_port_be, IPPROTO_UDP, 0);

                // Swap MACs
                __u8 tmp_mac[ETH_ALEN];
                __builtin_memcpy(tmp_mac, eth->h_source, ETH_ALEN);
                __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
                __builtin_memcpy(eth->h_dest, tmp_mac, ETH_ALEN);

                // Swap IPv6 source/destination addresses
                struct in6_addr tmp_ip = ip6h->saddr;
                ip6h->saddr = ip6h->daddr;
                ip6h->daddr = tmp_ip;

                // Swap Ports
                __u16 tmp_port = udph->source;
                udph->source = udph->dest;
                udph->dest = tmp_port;

                // Update Header Lengths
                __u16 total_ip_len = (void *)data_end - (void *)ip6h;
                ip6h->payload_len = bpf_htons(total_ip_len - sizeof(struct ipv6hdr));

                __u16 total_udp_len = (void *)data_end - (void *)udph;
                udph->len = bpf_htons(total_udp_len);

                // Recalculate UDP Checksum
                udph->check = 0;
                udph->check = csum_ipv6_helper(ip6h, udph, data_end, IPPROTO_UDP);

                return XDP_TX;
            }
        } else if (ip6h->nexthdr == IPPROTO_TCP) {
            struct tcphdr *tcph = (void *)(ip6h + 1);
            if ((void *)(tcph + 1) > data_end) return XDP_PASS;

            if (tcph->dest == bpf_htons(TARGET_PORT)) {
                if (tcph->syn) {
                    if ((bpf_ntohl(tcph->seq) & 0xFF) != 0x4D) {
                        return XDP_DROP;
                    }
                    if ((void *)tcph + 256 < data_end) {
                        return XDP_PASS;
                    }
                    // TCP Handshake Spoofing over IPv6 (SYN -> SYN-ACK)
                    emit_pulse_event_v6(&ip6h->saddr, tcph->source, IPPROTO_TCP, 0x02);

                    // Swap MACs
                    __u8 tmp_mac[ETH_ALEN];
                    __builtin_memcpy(tmp_mac, eth->h_source, ETH_ALEN);
                    __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
                    __builtin_memcpy(eth->h_dest, tmp_mac, ETH_ALEN);

                    // Swap IPs
                    struct in6_addr tmp_ip = ip6h->saddr;
                    ip6h->saddr = ip6h->daddr;
                    ip6h->daddr = tmp_ip;

                    // Swap Ports
                    __u16 tmp_port = tcph->source;
                    tcph->source = tcph->dest;
                    tcph->dest = tmp_port;

                    // Sequence Math
                    __u32 client_seq = bpf_ntohl(tcph->seq);
                    tcph->ack_seq = bpf_htonl(client_seq + 1);
                    tcph->seq = bpf_htonl(1000); // Server ISN

                    // Flags
                    tcph->syn = 1;
                    tcph->ack = 1;

                    // Update Lengths
                    __u16 total_ip_len = (void *)data_end - (void *)ip6h;
                    ip6h->payload_len = bpf_htons(total_ip_len - sizeof(struct ipv6hdr));

                    // Recalculate TCP Checksum
                    tcph->check = 0;
                    tcph->check = csum_ipv6_helper(ip6h, tcph, data_end, IPPROTO_TCP);

                    return XDP_TX;
                } else if (tcph->ack) {
                    if (tcph->doff < 5) {
                        return XDP_PASS;
                    }
                    void *tcp_end = (void *)tcph + (tcph->doff * 4);
                    if (tcp_end != data_end) {
                        return XDP_PASS;
                    }
                    if ((void *)tcph + 240 < data_end) {
                        return XDP_PASS;
                    }
                    // TCP Keepalive Reflector over IPv6 (ACK -> ACK + IP Payload)
                    if (bpf_xdp_adjust_tail(ctx, 16) != 0) {
                        return XDP_PASS;
                    }

                    // Re-evaluate boundaries after tail adjustment
                    data = (void *)(long)ctx->data;
                    data_end = (void *)(long)ctx->data_end;
                    eth = data;
                    if ((void *)(eth + 1) > data_end) return XDP_DROP;
                    ip6h = (void *)(eth + 1);
                    if ((void *)(ip6h + 1) > data_end) return XDP_DROP;
                    tcph = (void *)(ip6h + 1);
                    if ((void *)(tcph + 1) > data_end) return XDP_DROP;
                    if (tcph->doff < 5) return XDP_DROP;

                    struct in6_addr *payload = (void *)tcph + (tcph->doff * 4);
                    if ((void *)(payload + 1) > data_end) return XDP_DROP;

                    // Write client's public IPv6 address
                    *payload = ip6h->saddr;

                    // Save sequences
                    __u32 client_seq = bpf_ntohl(tcph->seq);
                    __u32 client_ack = bpf_ntohl(tcph->ack_seq);

                    // Swap MACs
                    __u8 tmp_mac[ETH_ALEN];
                    __builtin_memcpy(tmp_mac, eth->h_source, ETH_ALEN);
                    __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
                    __builtin_memcpy(eth->h_dest, tmp_mac, ETH_ALEN);

                    // Swap IPs
                    struct in6_addr tmp_ip = ip6h->saddr;
                    ip6h->saddr = ip6h->daddr;
                    ip6h->daddr = tmp_ip;

                    // Swap Ports
                    __u16 tmp_port = tcph->source;
                    tcph->source = tcph->dest;
                    tcph->dest = tmp_port;

                    // Sequence Inversion
                    tcph->seq = bpf_htonl(client_ack);
                    tcph->ack_seq = bpf_htonl(client_seq);

                    // Flags
                    tcph->ack = 1;
                    tcph->psh = 1;

                    // Update Lengths
                    __u16 total_ip_len = (void *)data_end - (void *)ip6h;
                    ip6h->payload_len = bpf_htons(total_ip_len - sizeof(struct ipv6hdr));

                    // Recalculate Checksums
                    tcph->check = 0;
                    tcph->check = csum_ipv6_helper(ip6h, tcph, data_end, IPPROTO_TCP);

                    return XDP_TX;
                }
            }
        }
    }

    return XDP_PASS;
}

SEC("tc")
int tc_egress_drop_rst(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
    
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end) return TC_ACT_OK;
        if (iph->ihl < 5) return TC_ACT_OK;
        if (iph->protocol != IPPROTO_TCP) return TC_ACT_OK;

        struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
        if ((void *)(tcph + 1) > data_end) return TC_ACT_OK;

        if (tcph->source != bpf_htons(TARGET_PORT)) return TC_ACT_OK;

        __u8 *flags = (__u8 *)tcph + 13;
        if ((void *)(flags + 1) > data_end) return TC_ACT_OK;

        if (*flags & 0x04) {
#ifdef MCSOAK_BPF_DEBUG
            bpf_printk("TC Egress: Vaporized IPv4 RST packet for port %d\n", TARGET_PORT);
#endif
            return TC_ACT_SHOT; // Drop RST
        }
    } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6h = (void *)(eth + 1);
        if ((void *)(ip6h + 1) > data_end) return TC_ACT_OK;
        if (ip6h->nexthdr != IPPROTO_TCP) return TC_ACT_OK;

        struct tcphdr *tcph = (void *)(ip6h + 1);
        if ((void *)(tcph + 1) > data_end) return TC_ACT_OK;

        if (tcph->source != bpf_htons(TARGET_PORT)) return TC_ACT_OK;

        __u8 *flags = (__u8 *)tcph + 13;
        if ((void *)(flags + 1) > data_end) return TC_ACT_OK;

        if (*flags & 0x04) {
#ifdef MCSOAK_BPF_DEBUG
            bpf_printk("TC Egress: Vaporized IPv6 RST packet for port %d\n", TARGET_PORT);
#endif
            return TC_ACT_SHOT; // Drop RST
        }
    }

    return TC_ACT_OK;
}

char __license[] SEC("license") = "Dual MIT/GPL";
