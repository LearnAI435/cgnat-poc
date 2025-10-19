/*
 * cgnat.c
 *
 * Simple userspace CGNAT/PAT prototype using libnetfilter_queue.
 *
 * Build:
 *   gcc -O2 -o cgnat cgnat.c -lnetfilter_queue -lpthread
 *
 * Requires:
 *   - libnetfilter_queue (libnfnetlink, libnetfilter_queue)
 *   - root privileges to run and to add iptables rules
 *   - uthash.h available in include path (or in same dir)
 *
 * WARNING: Prototype only. Not production ready. See notes below.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>    /* for NF_ACCEPT */
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "uthash.h"

#define PUBLIC_IP_COUNT 10
#define MIN_PORT 1024
#define MAX_PORT 65535
#define PORTS_PER_IP (MAX_PORT - MIN_PORT + 1)
#define TOTAL_PORTS (PUBLIC_IP_COUNT * PORTS_PER_IP)

#define TCP_TIMEOUT 300   /* seconds */
#define UDP_TIMEOUT 60
#define CLEANUP_INTERVAL 5 /* seconds */

typedef uint32_t ipv4_t;

struct port_slot {
    uint8_t used; /* 0 free, 1 used */
};

struct pubip {
    ipv4_t addr; /* network order */
    struct port_slot *slots; /* size: PORTS_PER_IP */
};

/* mapping key: private src ip, private src port, proto, remote ip, remote port */
struct mapping_key {
    ipv4_t priv_ip;
    uint16_t priv_port;
    ipv4_t remote_ip;
    uint16_t remote_port;
    uint8_t proto; /* IPPROTO_TCP or IPPROTO_UDP */
};

/* mapping entry */
struct mapping {
    struct mapping_key key;
    uint32_t pub_ip_idx; /* index into pubips[] */
    uint16_t pub_port;
    time_t last_seen;
    UT_hash_handle hh; /* uthash */
};

static struct pubip pubips[PUBLIC_IP_COUNT];
static pthread_mutex_t map_lock = PTHREAD_MUTEX_INITIALIZER;
static struct mapping *map_table = NULL;

/* utility: htons/ntohs etc are used directly */

/* simple IP header parsing helpers */
struct ip_hdr {
    uint8_t ihl:4, version:4;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
} __attribute__((packed));

struct tcp_hdr {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
    uint16_t doff_res_flags;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
} __attribute__((packed));

struct udp_hdr {
    uint16_t source;
    uint16_t dest;
    uint16_t len;
    uint16_t check;
} __attribute__((packed));

/* checksum helpers */
static uint16_t ip_checksum(void *vdata, size_t length) {
    // from RFC
    char *data = vdata;
    uint64_t acc = 0xffff;
    unsigned int i;

    // Handle complete 16-bit blocks.
    for (i = 0; i + 1 < length; i += 2) {
        uint16_t word;
        memcpy(&word, data + i, 2);
        acc += ntohs(word);
        if (acc > 0xffff) acc -= 0xffff;
    }

    // Handle any partial block at the end of the data.
    if (length & 1) {
        uint16_t word = 0;
        memcpy(&word, data + length - 1, 1);
        acc += ntohs(word);
        if (acc > 0xffff) acc -= 0xffff;
    }

    // Return the checksum in network byte order.
    uint16_t res = ~acc & 0xffff;
    return htons(res);
}

static uint16_t tcp_udp_checksum(uint32_t saddr, uint32_t daddr, uint8_t proto,
                                 const uint8_t *segment, size_t seglen) {
    // pseudo header + segment
    uint32_t sum = 0;
    uint16_t tmp;
    // pseudo header
    sum += (saddr >> 16) & 0xFFFF;
    sum += (saddr) & 0xFFFF;
    sum += (daddr >> 16) & 0xFFFF;
    sum += (daddr) & 0xFFFF;
    sum += htons(proto);
    sum += htons((uint16_t)seglen);

    // segment
    for (size_t i = 0; i + 1 < seglen; i += 2) {
        tmp = (segment[i] << 8) + segment[i+1];
        sum += tmp;
    }
    if (seglen & 1) {
        tmp = (segment[seglen - 1] << 8);
        sum += tmp;
    }
    // fold
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    sum = ~sum;
    return (uint16_t)sum;
}

/* port allocation: pick first free port (simple). Could use hashed/deterministic allocation. */
static int alloc_public_port(uint32_t *out_ip_idx, uint16_t *out_port) {
    for (uint32_t ipi = 0; ipi < PUBLIC_IP_COUNT; ++ipi) {
        struct pubip *p = &pubips[ipi];
        for (uint32_t i = 0; i < PORTS_PER_IP; ++i) {
            if (!p->slots[i].used) {
                p->slots[i].used = 1;
                *out_ip_idx = ipi;
                *out_port = (uint16_t)(MIN_PORT + i);
                return 0;
            }
        }
    }
    return -1; /* no free port */
}

static void free_public_port(uint32_t ip_idx, uint16_t port) {
    if (ip_idx >= PUBLIC_IP_COUNT) return;
    if (port < MIN_PORT || port > MAX_PORT) return;
    uint32_t i = port - MIN_PORT;
    pubips[ip_idx].slots[i].used = 0;
}

/* mapping management */
static struct mapping* find_mapping_by_private(const struct mapping_key *k) {
    struct mapping *m;
    pthread_mutex_lock(&map_lock);
    HASH_FIND(hh, map_table, k, sizeof(*k), m);
    pthread_mutex_unlock(&map_lock);
    return m;
}

static struct mapping* find_mapping_by_public(uint32_t pub_ip_idx, uint16_t pub_port, uint8_t proto) {
    struct mapping *m, *found = NULL;
    pthread_mutex_lock(&map_lock);
    for (m = map_table; m != NULL; m = m->hh.next) {
        if (m->pub_ip_idx == pub_ip_idx && m->pub_port == pub_port && m->key.proto == proto) {
            found = m;
            break;
        }
    }
    pthread_mutex_unlock(&map_lock);
    return found;
}

static struct mapping* create_mapping(const struct mapping_key *k, uint32_t pub_ip_idx, uint16_t pub_port) {
    struct mapping *m = malloc(sizeof(*m));
    if (!m) return NULL;
    memset(m, 0, sizeof(*m));
    memcpy(&m->key, k, sizeof(*k));
    m->pub_ip_idx = pub_ip_idx;
    m->pub_port = pub_port;
    m->last_seen = time(NULL);

    pthread_mutex_lock(&map_lock);
    HASH_ADD_KEYPTR(hh, map_table, &m->key, sizeof(m->key), m);
    pthread_mutex_unlock(&map_lock);
    return m;
}

static void touch_mapping(struct mapping *m) {
    if (!m) return;
    m->last_seen = time(NULL);
}

static void delete_mapping(struct mapping *m) {
    if (!m) return;
    pthread_mutex_lock(&map_lock);
    HASH_DEL(map_table, m);
    pthread_mutex_unlock(&map_lock);
    free_public_port(m->pub_ip_idx, m->pub_port);
    free(m);
}

/* cleanup thread */
static void *cleanup_thread(void *arg) {
    while (1) {
        sleep(CLEANUP_INTERVAL);
        time_t now = time(NULL);
        pthread_mutex_lock(&map_lock);
        struct mapping *m, *tmp;
        for (m = map_table; m != NULL; m = tmp) {
            tmp = m->hh.next;
            int to_expire = 0;
            if (m->key.proto == IPPROTO_TCP) {
                if (now - m->last_seen > TCP_TIMEOUT) to_expire = 1;
            } else {
                if (now - m->last_seen > UDP_TIMEOUT) to_expire = 1;
            }
            if (to_expire) {
                HASH_DEL(map_table, m);
                free_public_port(m->pub_ip_idx, m->pub_port);
                free(m);
            }
        }
        pthread_mutex_unlock(&map_lock);
    }
    return NULL;
}

/* IP parsing + modification helpers */
static int parse_ipv4(const unsigned char *data, int len, struct ip_hdr **iph, int *iph_len) {
    if (len < sizeof(struct ip_hdr)) return -1;
    *iph = (struct ip_hdr*)data;
    int ihl = ((*iph)->ihl) * 4;
    if (ihl < 20 || len < ihl) return -1;
    *iph_len = ihl;
    return 0;
}

/* recompute IP checksum */
static void recompute_ip_checksum(struct ip_hdr *iph) {
    iph->check = 0;
    iph->check = ip_checksum(iph, (iph->ihl)*4);
}

/* recompute TCP/UDP checksums */
static void recompute_l4_checksum(struct ip_hdr *iph, unsigned char *l4ptr, int l4len) {
    if (iph->protocol == IPPROTO_TCP) {
        struct tcp_hdr *th = (struct tcp_hdr*)l4ptr;
        th->check = 0;
        th->check = tcp_udp_checksum(iph->saddr, iph->daddr, IPPROTO_TCP, l4ptr, l4len);
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udp_hdr *uh = (struct udp_hdr*)l4ptr;
        uh->check = 0;
        uh->check = tcp_udp_checksum(iph->saddr, iph->daddr, IPPROTO_UDP, l4ptr, l4len);
    }
}

/* main packet handler */
static int handle_packet(struct nfq_q_handle *qh, struct nfq_data *tb, struct pubip *pubip_pool, uint32_t pub_count) {
    unsigned char *data;
    int ret = nfq_get_payload(tb, &data);
    if (ret <= 0) return nfq_set_verdict(qh, nfq_get_msg_packet_hdr(tb)->packet_id, NF_ACCEPT, 0, NULL);

    struct ip_hdr *iph;
    int ihl;
    if (parse_ipv4(data, ret, &iph, &ihl) < 0) {
        return nfq_set_verdict(qh, nfq_get_msg_packet_hdr(tb)->packet_id, NF_ACCEPT, 0, NULL);
    }

    /* ignore fragmented packets (simple) */
    uint16_t frag = ntohs(iph->frag_off);
    if (frag & 0x1fff) {
        // fragmentation handling omitted
        return nfq_set_verdict(qh, nfq_get_msg_packet_hdr(tb)->packet_id, NF_ACCEPT, 0, NULL);
    }

    /* Only handle TCP/UDP */
    if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP) {
        return nfq_set_verdict(qh, nfq_get_msg_packet_hdr(tb)->packet_id, NF_ACCEPT, 0, NULL);
    }

    unsigned char *l4 = data + ihl;
    int l4len = ntohs(iph->tot_len) - ihl;
    if (l4len < 4) {
        return nfq_set_verdict(qh, nfq_get_msg_packet_hdr(tb)->packet_id, NF_ACCEPT, 0, NULL);
    }

    uint16_t sport = 0, dport = 0;
    memcpy(&sport, l4, 2);
    memcpy(&dport, l4+2, 2);
    sport = ntohs(sport);
    dport = ntohs(dport);

    /* Heuristic: determine outbound vs inbound by source address */
    uint32_t saddr = iph->saddr;
    uint32_t daddr = iph->daddr;

    /* Check if source is private RFC1918 (we handle SNAT outbound from private to public) */
    uint32_t saddr_h = ntohl(saddr);
    int source_is_private = 0;
    if ((saddr_h >> 24) == 10) source_is_private = 1;
    if ((saddr_h >> 20) == ((172<<4)|16)) {} /* ignore this incorrect check - we'll use mask below */
    /* correct checks for private ranges */
    if ((saddr_h & 0xFF000000) == 0x0A000000) source_is_private = 1; /* 10.0.0.0/8 */
    if ((saddr_h & 0xFFF00000) == 0xAC100000) source_is_private = 1; /* 172.16.0.0/12 */
    if ((saddr_h & 0xFFFF0000) == 0xC0A80000) source_is_private = 1; /* 192.168.0.0/16 */

    uint32_t pkt_id = nfq_get_msg_packet_hdr(tb)->packet_id;

    if (source_is_private) {
        /* OUTBOUND SNAT */
        struct mapping_key key;
        memset(&key, 0, sizeof(key));
        key.priv_ip = saddr;
        key.priv_port = htons((uint16_t)sport);
        key.remote_ip = daddr;
        key.remote_port = htons((uint16_t)dport);
        key.proto = iph->protocol;

        /* find existing mapping */
        pthread_mutex_lock(&map_lock);
        struct mapping *m = NULL;
        HASH_FIND(hh, map_table, &key, sizeof(key), m);
        pthread_mutex_unlock(&map_lock);

        if (!m) {
            uint32_t alloc_ip_idx;
            uint16_t alloc_port;
            if (alloc_public_port(&alloc_ip_idx, &alloc_port) < 0) {
                // no ports, drop
                return nfq_set_verdict(qh, pkt_id, NF_DROP, 0, NULL);
            }
            m = create_mapping(&key, alloc_ip_idx, alloc_port);
            if (!m) {
                free_public_port(alloc_ip_idx, alloc_port);
                return nfq_set_verdict(qh, pkt_id, NF_DROP, 0, NULL);
            }
        } else {
            touch_mapping(m);
        }

        /* rewrite source IP and port */
        uint32_t new_saddr = pubip_pool[m->pub_ip_idx].addr;
        uint16_t new_sport = htons(m->pub_port);

        iph->saddr = new_saddr;
        if (iph->protocol == IPPROTO_TCP) {
            struct tcp_hdr *th = (struct tcp_hdr*)l4;
            th->source = new_sport;
        } else {
            struct udp_hdr *uh = (struct udp_hdr*)l4;
            uh->source = new_sport;
        }

        /* recompute checksums */
        recompute_l4_checksum(iph, l4, l4len);
        recompute_ip_checksum(iph);

        /* deliver modified packet */
        return nfq_set_verdict(qh, pkt_id, NF_ACCEPT, ret, data);
    } else {
        /* INBOUND: check if destination matches one of our public IPs */
        int dst_is_our_public = -1;
        uint32_t pub_idx = 0;
        for (uint32_t i = 0; i < pub_count; ++i) {
            if (pubip_pool[i].addr == daddr) {
                dst_is_our_public = 1;
                pub_idx = i;
                break;
            }
        }
        if (!dst_is_our_public) {
            return nfq_set_verdict(qh, pkt_id, NF_ACCEPT, 0, NULL);
        }

        /* lookup mapping by public ip_idx and dest port */
        struct mapping *m = NULL;
        pthread_mutex_lock(&map_lock);
        for (m = map_table; m != NULL; m = m->hh.next) {
            if (m->pub_ip_idx == pub_idx && m->pub_port == dport && m->key.proto == iph->protocol) {
                break;
            }
        }
        pthread_mutex_unlock(&map_lock);

        if (!m) {
            /* no mapping — drop or accept depending on policy */
            return nfq_set_verdict(qh, pkt_id, NF_DROP, 0, NULL);
        }

        touch_mapping(m);

        /* rewrite destination to private tuple */
        iph->daddr = m->key.priv_ip;
        uint16_t new_dport = m->key.priv_port;
        if (iph->protocol == IPPROTO_TCP) {
            struct tcp_hdr *th = (struct tcp_hdr*)l4;
            th->dest = new_dport;
        } else {
            struct udp_hdr *uh = (struct udp_hdr*)l4;
            uh->dest = new_dport;
        }

        recompute_l4_checksum(iph, l4, l4len);
        recompute_ip_checksum(iph);
        return nfq_set_verdict(qh, pkt_id, NF_ACCEPT, ret, data);
    }
}

/* nfqueue callback wrapper */
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfd, void *data) {
    struct pubip *pool = (struct pubip*)data;
    return handle_packet(qh, nfd, pool, PUBLIC_IP_COUNT);
}

int main(int argc, char **argv) {
    if (geteuid() != 0) {
        fprintf(stderr, "This program must be run as root\n");
        return 1;
    }

    if (argc < 2 + PUBLIC_IP_COUNT - PUBLIC_IP_COUNT) {
        fprintf(stdout, "Usage: %s <pubip1> [pubip2 ...] \n", argv[0]);
        fprintf(stdout, "Will use first %d addresses (supply %d). Default requires %d.\n", PUBLIC_IP_COUNT, PUBLIC_IP_COUNT, PUBLIC_IP_COUNT);
        fprintf(stdout, "Example: %s 203.0.113.10 203.0.113.11 ...\n", argv[0]);
        /* continue to allow flexibility: if user gave less, use what given and fill rest? For clarity require exact */
        return 1;
    }

    if (argc - 1 < PUBLIC_IP_COUNT) {
        fprintf(stderr, "Please supply exactly %d public IP addresses.\n", PUBLIC_IP_COUNT);
        return 1;
    }

    /* initialize pubip pool */
    for (int i = 0; i < PUBLIC_IP_COUNT; ++i) {
        struct pubip *p = &pubips[i];
        if (inet_pton(AF_INET, argv[1 + i], &p->addr) != 1) {
            fprintf(stderr, "Invalid IP: %s\n", argv[1 + i]);
            return 1;
        }
        p->slots = calloc(PORTS_PER_IP, sizeof(struct port_slot));
        if (!p->slots) {
            fprintf(stderr, "OOM\n");
            return 1;
        }
    }

    /* start cleanup thread */
    pthread_t tid;
    pthread_create(&tid, NULL, cleanup_thread, NULL);

    /* setup nfqueue */
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    h = nfq_open();
    if (!h) {
        fprintf(stderr, "nfq_open failed\n");
        return 1;
    }

    if (nfq_unbind_pf(h, AF_INET) < 0) {
        // ignore
    }
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "nfq_bind_pf failed\n");
        return 1;
    }

    qh = nfq_create_queue(h,  0, &cb, &pubips);
    if (!qh) {
        fprintf(stderr, "nfq_create_queue failed\n");
        return 1;
    }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "could not set copy packet mode\n");
        return 1;
    }

    fd = nfq_fd(h);
    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
        nfq_handle_packet(h, buf, rv);
    }

    nfq_destroy_queue(qh);
    nfq_close(h);
    return 0;
}
