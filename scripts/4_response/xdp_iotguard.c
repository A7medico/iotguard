// SPDX-License-Identifier: GPL-2.0
/*
 * scripts/4_response/xdp_iotguard.c
 * =============================================================================
 * IoTGuard Phase 4 — High-Speed In-Kernel eBPF / XDP Packet Filter
 * =============================================================================
 *
 * Position in pipeline:
 *     NIC Driver RX Ring
 *         → [THIS eBPF/XDP PROGRAM] (Fast-Path In-Kernel Filter)
 *             ├── Malicious Source IP? → Atomically bump stats & XDP_DROP (<1 µs)
 *             └── Benign / Unmatched  → XDP_PASS (Enter normal Linux kernel stack)
 *
 * Features & Design Contracts:
 *   1. Driver Hook: Executes at the earliest possible point in the network driver
 *      RX queue (XDP native driver hook or generic SKB hook), bypassing socket
 *      buffers (sk_buff), conntrack, netfilter, and route lookups.
 *   2. Pinned Hash Map: `iotguard_blocked_ips` (max 65,536 entries)
 *      Key:   __u32 (IPv4 source address in network byte order)
 *      Value: struct blocked_ip_entry { __u64 blocked_at_ns; __u64 drop_count; }
 *   3. Zero Memory Allocation: Map lookup is O(1) in-kernel RCU-protected hash.
 *   4. Drop Statistics: Per-IP drop counter incremented atomically via
 *      `__sync_fetch_and_add` without locks or userspace context switches.
 *   5. Seamless Userspace Management: Controlled via `ebpf_driver.py` using
 *      pinned map at `/sys/fs/bpf/iotguard_blocked_ips` or bpftool/libbpf.
 *
 * Compilation:
 *   clang -O2 -g -target bpf -Wall -D__TARGET_ARCH_x86 \
 *         -c xdp_iotguard.c -o xdp_iotguard.o
 *
 * Loading & Attachment (Manual CLI example):
 *   ip link set dev eth0 xdp obj xdp_iotguard.o sec xdp
 *   bpftool map dump pinned /sys/fs/bpf/iotguard_blocked_ips -j
 * =============================================================================
 */

#ifndef __KERNEL__
#define __KERNEL__
#endif

// Support compilation with standard Linux headers or standalone environments
#if defined(__has_include)
  #if __has_include(<linux/bpf.h>) && __has_include(<bpf/bpf_helpers.h>) && __has_include(<bpf/bpf_endian.h>)
    #include <linux/bpf.h>
    #include <linux/if_ether.h>
    #include <linux/ip.h>
    #include <linux/in.h>
    #include <bpf/bpf_helpers.h>
    #include <bpf/bpf_endian.h>
    #define HAVE_NATIVE_BPF_HEADERS 1
  #endif
#endif

#ifndef HAVE_NATIVE_BPF_HEADERS
// Self-contained fallback definitions for standalone cross-compilation & IDE tooling
typedef unsigned char       __u8;
typedef unsigned short      __u16;
typedef unsigned int        __u32;
typedef unsigned long long  __u64;

#define SEC(NAME) __attribute__((section(NAME), used))

#ifndef bpf_htons
#define bpf_htons(x) __builtin_bswap16(x)
#endif
#ifndef bpf_ntohs
#define bpf_ntohs(x) __builtin_bswap16(x)
#endif

#define ETH_P_IP    0x0800  /* Internet Protocol packet */
#define ETH_HLEN    14      /* Total octets in header */

enum xdp_action {
    XDP_ABORTED = 0,
    XDP_DROP,
    XDP_PASS,
    XDP_TX,
    XDP_REDIRECT,
};

struct xdp_md {
    __u32 data;
    __u32 data_end;
    __u32 data_meta;
    __u32 ingress_ifindex;
    __u32 rx_queue_index;
    __u32 egress_ifindex;
};

struct ethhdr {
    unsigned char   h_dest[6];
    unsigned char   h_source[6];
    __u16           h_proto;
};

struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u8    ihl:4,
            version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
    __u8    version:4,
            ihl:4;
#else
    __u8    ihl:4,
            version:4;
#endif
    __u8    tos;
    __u16   tot_len;
    __u16   id;
    __u16   frag_off;
    __u8    ttl;
    __u8    protocol;
    __u16   check;
    __u32   saddr;
    __u32   daddr;
};

enum bpf_map_type {
    BPF_MAP_TYPE_UNSPEC = 0,
    BPF_MAP_TYPE_HASH = 1,
};

#define LIBBPF_PIN_BY_NAME 1

/* BPF Helper Prototypes */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;

#endif /* !HAVE_NATIVE_BPF_HEADERS */

#define MAX_BLOCKED_IPS 65536

/*
 * Structure stored in BPF hash map for each quarantined IP.
 */
struct blocked_ip_entry {
    __u64 blocked_at_ns;    /* Nanosecond timestamp when rule was activated */
    __u64 drop_count;       /* Monotonic atomic counter of dropped packets */
};

/*
 * BTF-defined pinned BPF Map for blocked IP addresses.
 * Maps pinned at /sys/fs/bpf/iotguard_blocked_ips can be inspected and modified
 * by userspace without detaching or interrupting the running XDP program.
 */
struct {
    __u32 type;
    __u32 max_entries;
    __u32 key_size;
    __u32 value_size;
    __u32 pinning;
} iotguard_blocked_ips SEC(".maps") = {
    .type = BPF_MAP_TYPE_HASH,
    .max_entries = MAX_BLOCKED_IPS,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct blocked_ip_entry),
    .pinning = LIBBPF_PIN_BY_NAME,
};

/*
 * Main XDP packet filtering hook.
 * Invoked by the NIC driver for every incoming Ethernet packet.
 */
SEC("xdp")
int xdp_iotguard_filter(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* 1. Ethernet Header Boundary Check (Required by Kernel Verifier) */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* 2. Filter for IPv4 Traffic Only (Pass ARP, IPv6, LLDP untouched) */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* 3. IPv4 Header Boundary Check */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* 4. Extract Source IPv4 Address in Network Byte Order */
    __u32 src_ip = ip->saddr;

    /* 5. Fast O(1) Hash Map Lookup in Pinned Blocklist */
    struct blocked_ip_entry *entry = (struct blocked_ip_entry *)bpf_map_lookup_elem(&iotguard_blocked_ips, &src_ip);
    if (entry) {
        /*
         * Atomically increment drop statistics counter.
         * Using GCC atomic intrinsic to guarantee lock-free SMP safety across CPU cores.
         */
        __sync_fetch_and_add(&entry->drop_count, 1);

        /* Drop packet immediately at the NIC driver stage */
        return XDP_DROP;
    }

    /* Allowed packet continues up the Linux networking stack */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

