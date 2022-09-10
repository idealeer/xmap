/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * XMap Copyright 2021 Xiang Li from Network and Information Security Lab
 * Tsinghua University
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef XMAP_PACKET_H
#define XMAP_PACKET_H

#include "../../lib/includes.h"
#include "../state.h"

#define MAX_PACKET_SIZE 4096

typedef unsigned short __attribute__((__may_alias__)) alias_unsigned_short;

void make_eth_header(struct ether_header *ethh, macaddr_t *src, macaddr_t *dst);

void make_eth6_header(struct ether_header *ethh, macaddr_t *src,
                      macaddr_t *dst);

void make_eth_header_ethertype(struct ether_header *ethh, macaddr_t *src,
                               macaddr_t *dst, uint16_t ether_type);

void make_ip_header(struct ip *iph, uint8_t protocol, uint16_t ip_len);

void make_ip6_header(struct ip6_hdr *iph, uint8_t protocol, uint16_t pl_len);

void make_tcp_header(struct tcphdr *tcp_header, uint16_t len);

void make_icmp_header(struct icmp *);

void make_icmp6_header(struct icmp6_hdr *);

void make_udp_header(struct udphdr *udp_header, uint16_t len);

void fprintf_ip_header(FILE *fp, struct ip *iph);

void fprintf_ip6_header(FILE *fp, struct ip6_hdr *ip6h);

void fprintf_eth_header(FILE *fp, struct ether_header *ethh);

static inline unsigned short in_checksum(unsigned short *ip_pkt, int len) {
    unsigned long sum = 0;
    for (int nwords = len / 2; nwords > 0; nwords--) {
        sum += *ip_pkt++;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    return (unsigned short) (~sum);
}

__attribute__((unused)) static inline unsigned short
    ip_checksum_(unsigned short *buf) {
    return in_checksum(buf, (int) sizeof(struct ip));
}

__attribute__((unused)) static inline unsigned short
    icmp_checksum_(unsigned short *buf) {
    return in_checksum(buf, (int) sizeof(struct icmp));
}

__attribute__((unused)) static inline uint16_t
    icmp_checksum(struct icmp *icmp_pkt, size_t data_len) {
    unsigned short  icmp_len = sizeof(struct icmp) + data_len;
    unsigned long   sum      = 0;
    int             nleft    = icmp_len;
    unsigned short *w        = (unsigned short *) icmp_pkt;

    // calculate the checksum for the icmp header and icmp data
    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    // if nleft is 1 there ist still on byte left.
    // We add a padding byte (0xFF) to build a 16bit word
    if (nleft > 0) {
        sum += *w & 0x00FF;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    // Take the one's complement of sum
    return (unsigned short) (~sum);
}

__attribute__((unused)) static inline uint16_t
    icmp6_checksum(struct in6_addr *saddr, struct in6_addr *daddr,
                   struct icmp6_hdr *icmp6_pkt, size_t data_len) {
    alias_unsigned_short *src_addr  = (alias_unsigned_short *) saddr;
    alias_unsigned_short *dest_addr = (alias_unsigned_short *) daddr;
    unsigned short        icmp6_len = sizeof(struct icmp6_hdr) + data_len;
    unsigned long         sum       = 0;
    int                   nleft     = icmp6_len;
    unsigned short       *w         = (unsigned short *) icmp6_pkt;

    // calculate the checksum for the icmpv6 header and icmpv6 data
    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    // if nleft is 1 there ist still on byte left.
    // We add a padding byte (0xFF) to build a 16bit word
    if (nleft > 0) {
        sum += *w & 0x00FF;
    }

    // add the pseudo header
    sum += src_addr[0];
    sum += src_addr[1];
    sum += src_addr[2];
    sum += src_addr[3];
    sum += src_addr[4];
    sum += src_addr[5];
    sum += src_addr[6];
    sum += src_addr[7];
    sum += dest_addr[0];
    sum += dest_addr[1];
    sum += dest_addr[2];
    sum += dest_addr[3];
    sum += dest_addr[4];
    sum += dest_addr[5];
    sum += dest_addr[6];
    sum += dest_addr[7];
    sum += htons(icmp6_len);
    sum += htons(IPPROTO_ICMPV6);
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    // Take the one's complement of sum
    return (unsigned short) (~sum);
}

__attribute__((unused)) static inline uint16_t
    udp6_checksum(struct in6_addr *saddr, struct in6_addr *daddr,
                  struct udphdr *udp_pkt) {
    alias_unsigned_short *src_addr  = (alias_unsigned_short *) saddr;
    alias_unsigned_short *dest_addr = (alias_unsigned_short *) daddr;
    unsigned long         sum       = 0;
    int                   nleft     = ntohs(udp_pkt->uh_ulen);
    unsigned short       *w         = (unsigned short *) udp_pkt;

    // calculate the checksum for the udp6 header and udp6 data
    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    // if nleft is 1 there ist still on byte left.
    // We add a padding byte (0xFF) to build a 16bit word
    if (nleft > 0) {
        sum += *w & 0x00FF;
    }

    // add the pseudo header
    sum += src_addr[0];
    sum += src_addr[1];
    sum += src_addr[2];
    sum += src_addr[3];
    sum += src_addr[4];
    sum += src_addr[5];
    sum += src_addr[6];
    sum += src_addr[7];
    sum += dest_addr[0];
    sum += dest_addr[1];
    sum += dest_addr[2];
    sum += dest_addr[3];
    sum += dest_addr[4];
    sum += dest_addr[5];
    sum += dest_addr[6];
    sum += dest_addr[7];
    sum += udp_pkt->uh_ulen; // net order
    sum += htons(IPPROTO_UDP);

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    // Take the one's complement of sum
    return (unsigned short) (~sum);
}

__attribute__((unused)) static inline uint16_t
    udp_checksum(uint32_t saddr, uint32_t daddr, struct udphdr *udp_pkt) {
    alias_unsigned_short *src_addr  = (alias_unsigned_short *) &saddr;
    alias_unsigned_short *dest_addr = (alias_unsigned_short *) &daddr;
    unsigned long         sum       = 0;
    int                   nleft     = ntohs(udp_pkt->uh_ulen);
    unsigned short       *w         = (unsigned short *) udp_pkt;

    // calculate the checksum for the udp header and udp data
    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    // if nleft is 1 there ist still on byte left.
    // We add a padding byte (0xFF) to build a 16bit word
    if (nleft > 0) {
        sum += *w & 0x00FF;
    }

    // add the pseudo header
    sum += src_addr[0];
    sum += src_addr[1];
    sum += dest_addr[0];
    sum += dest_addr[1];
    sum += udp_pkt->uh_ulen; // net order
    sum += htons(IPPROTO_UDP);

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    // Take the one's complement of sum
    return (unsigned short) (~sum);
}

__attribute__((unused)) static inline uint16_t
    tcp6_checksum(struct in6_addr *saddr, struct in6_addr *daddr,
                  struct tcphdr *tcp_pkt, unsigned short len_tcp) {
    uint16_t *src_addr  = (uint16_t *) saddr;
    uint16_t *dest_addr = (uint16_t *) daddr;

    unsigned long   sum   = 0;
    int             nleft = len_tcp;
    unsigned short *w     = (unsigned short *) tcp_pkt;

    // calculate the checksum for the tcp6 header and tcp6 data
    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    // if nleft is 1 there ist still on byte left.
    // We add a padding byte (0xFF) to build a 16bit word
    if (nleft > 0) {
        sum += *w & 0x00FF;
    }

    // add the pseudo header
    sum += src_addr[0];
    sum += src_addr[1];
    sum += src_addr[2];
    sum += src_addr[3];
    sum += src_addr[4];
    sum += src_addr[5];
    sum += src_addr[6];
    sum += src_addr[7];
    sum += dest_addr[0];
    sum += dest_addr[1];
    sum += dest_addr[2];
    sum += dest_addr[3];
    sum += dest_addr[4];
    sum += dest_addr[5];
    sum += dest_addr[6];
    sum += dest_addr[7];
    sum += htons(len_tcp);
    sum += htons(IPPROTO_TCP);
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    // Take the one's complement of sum
    return (unsigned short) (~sum);
}

__attribute__((unused)) static inline uint16_t
    tcp_checksum(unsigned short len_tcp, uint32_t saddr, uint32_t daddr,
                 struct tcphdr *tcp_pkt) {
    alias_unsigned_short *src_addr  = (alias_unsigned_short *) &saddr;
    alias_unsigned_short *dest_addr = (alias_unsigned_short *) &daddr;

    unsigned long   sum   = 0;
    int             nleft = len_tcp;
    unsigned short *w     = (unsigned short *) tcp_pkt;
    // calculate the checksum for the tcp header and tcp data
    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    // if nleft is 1 there ist still on byte left.
    // We add a padding byte (0xFF) to build a 16bit word
    if (nleft > 0) {
        sum += *w & 0x00FF;
    }

    // add the pseudo header
    sum += src_addr[0];
    sum += src_addr[1];
    sum += dest_addr[0];
    sum += dest_addr[1];
    sum += htons(len_tcp);
    sum += htons(IPPROTO_TCP);
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    // Take the one's complement of sum
    return (unsigned short) (~sum);
}

// Returns 0 if dst_port is outside the expected valid range, non-zero otherwise
__attribute__((unused)) static inline int
    check_src_port(uint16_t sport, int num_ports, uint8_t *validation) {
    if (sport > xconf.source_port_last || sport < xconf.source_port_first) {
        return 0;
    }

    int32_t to_validate = sport - xconf.source_port_first;
    int32_t min =
        ((((uint16_t) validation[0]) << 8u) + validation[1]) % num_ports;
    int32_t max = ((((uint16_t) validation[0]) << 8u) + validation[1] +
                   xconf.packet_streams - 1) %
                  num_ports;

    return (((max - min) % num_ports) >= ((to_validate - min) % num_ports));
}

__attribute__((unused)) static inline int
    check_dns_src_port(uint16_t sport, int num_ports, uint8_t *validation) {
    if (sport > xconf.source_port_last || sport < xconf.source_port_first) {
        return 0;
    }

    int32_t to_validate = sport - xconf.source_port_first;
    int32_t min =
        ((((uint16_t) validation[0]) << 8u) + validation[1]) % num_ports;
    int32_t max = ((((uint16_t) validation[0]) << 8u) + validation[1] +
                   xconf.target_index_num - 1) %
                  num_ports;

    return (((max - min) % num_ports) >= ((to_validate - min) % num_ports));
}

__attribute__((unused)) static inline uint16_t
    get_src_port(int num_ports, int probe_num, uint8_t *validation) {
    return xconf.source_port_first +
           (((((uint16_t) validation[0]) << 8u) + validation[1] + probe_num) %
            num_ports);
}

__attribute__((unused)) static inline uint16_t
    get_icmp_idnum(uint8_t *validation) {
    return (((uint16_t) validation[0]) << 8u) + validation[1];
}

__attribute__((unused)) static inline uint16_t
    get_icmp_seqnum(uint8_t *validation) {
    return (((uint16_t) validation[2]) << 8u) + validation[3];
}

__attribute__((unused)) static inline uint32_t
    get_tcp_seqnum(uint8_t *validation) {
    return (((uint32_t) validation[0]) << 24u) +
           (((uint32_t) validation[1]) << 16u) +
           (((uint32_t) validation[2]) << 8u) + (((uint32_t) validation[3]));
}

__attribute__((unused)) static inline uint16_t
    get_dns_txid(uint8_t *validation) {
    return (((uint16_t) validation[0]) << 8u) + validation[1];
}

// Returns 1 if match
__attribute__((unused)) static inline int check_dns_txid(uint16_t txid,
                                                         uint8_t *validation) {
    return txid == get_dns_txid(validation);
}

// Note: caller must free return value
char *make_ip_str(uint32_t ip);

char *make_ipv6_str(struct in6_addr *ipv6);

#endif // XMAP_PACKET_H
