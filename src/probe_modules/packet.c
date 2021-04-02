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

#include "stdio.h"
#include "string.h"

#include "../../lib/includes.h" // should above packet.h
#include "../../lib/xalloc.h"

#include "packet.h"

#ifndef NDEBUG

void print_macaddr(struct ifreq *i) {
    printf("Device %s -> Ethernet %02x:%02x:%02x:%02x:%02x:%02x\n", i->ifr_name,
           (int) ((unsigned char *) &i->ifr_addr.sa_data)[0],
           (int) ((unsigned char *) &i->ifr_addr.sa_data)[1],
           (int) ((unsigned char *) &i->ifr_addr.sa_data)[2],
           (int) ((unsigned char *) &i->ifr_addr.sa_data)[3],
           (int) ((unsigned char *) &i->ifr_addr.sa_data)[4],
           (int) ((unsigned char *) &i->ifr_addr.sa_data)[5]);
}

#endif /* NDEBUG */

#define IP_ADDR_LEN_STR 20

void fprintf_ip_header(FILE *fp, struct ip *iph) {
    struct in_addr *s = (struct in_addr *) &(iph->ip_src);
    struct in_addr *d = (struct in_addr *) &(iph->ip_dst);

    char srcip[IP_ADDR_LEN_STR + 1];
    char dstip[IP_ADDR_LEN_STR + 1];
    // inet_ntoa is a const char * so we if just call it in
    // fprintf, you'll get back wrong results since we're
    // calling it twice.
    strncpy(srcip, inet_ntoa(*s), IP_ADDR_LEN_STR - 1);
    strncpy(dstip, inet_ntoa(*d), IP_ADDR_LEN_STR - 1);

    srcip[IP_ADDR_LEN_STR] = '\0';
    dstip[IP_ADDR_LEN_STR] = '\0';

    fprintf(fp,
            "IPv4\n"
            "\tVersion(4b)\t\t: 4\n"
            "\tHeader Length(4b)\t: %d\n"
            "\tService Field(1B)\t: 0x%02x\n"
            "\tTotal Length(2B)\t: %d\n"
            "\tIdentification(2B)\t: %d\n"
            "\tFlag(2B)\t\t: 0x%04x\n"
            "\tTime to live(1B)\t: %d\n"
            "\tProtocol(1B)\t\t: %d\n"
            "\tChecksum(2B)\t\t: 0x%04x\n"
            "\tSource(4B)\t\t: %s\n"
            "\tDestination(4B)\t\t: %s\n",
            iph->ip_hl * 4, iph->ip_tos, ntohs(iph->ip_len), ntohs(iph->ip_id),
            ((uint16_t *) iph)[3], iph->ip_ttl, iph->ip_p, iph->ip_sum, srcip,
            dstip);
}

void fprintf_ip6_header(FILE *fp, struct ip6_hdr *ip6h) {
    struct in6_addr *s = (struct in6_addr *) &(ip6h->ip6_src);
    struct in6_addr *d = (struct in6_addr *) &(ip6h->ip6_dst);

    char srcip[INET6_ADDRSTRLEN + 1];
    char dstip[INET6_ADDRSTRLEN + 1];

    // TODO: Is restrict correct here?
    inet_ntop(AF_INET6, s, (char *restrict) &srcip, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, d, (char *restrict) &dstip, INET6_ADDRSTRLEN);

    srcip[INET6_ADDRSTRLEN] = '\0';
    dstip[INET6_ADDRSTRLEN] = '\0';

    fprintf(fp,
            "IPv6\n"
            "\tVersion(4b)\t\t: 6\n"
            "\tTraffic Class(8b)\t: 0x%x%x\n"
            "\tFlow Label(20b)\t\t: 0x%x%02x%02x\n"
            "\tPayload Length(2B)\t: %d\n"
            "\tNext Header(1B)\t\t: %d\n"
            "\tHop Limit(1B)\t\t: %u\n"
            "\tSource(16B)\t\t: %s\n"
            "\tDestination(16B)\t: %s\n",
            ((uint8_t *) ip6h)[0] & 0x0fu, ((uint8_t *) ip6h)[1] & 0xf0u,
            ((uint8_t *) ip6h)[1] & 0x0fu, ((uint8_t *) ip6h)[2],
            ((uint8_t *) ip6h)[3], ntohs(ip6h->ip6_plen), ip6h->ip6_nxt,
            ip6h->ip6_hlim, srcip, dstip);
}

void fprintf_eth_header(FILE *fp, struct ether_header *ethh) {
    if (!xconf.send_ip_pkts) {
        fprintf(fp,
                "Ethernet\n"
                "\tDestination(6B)\t\t: %02x:%02x:%02x:%02x:%02x:%02x\n"
                "\tSource(6B)\t\t: %02x:%02x:%02x:%02x:%02x:%02x\n"
                "\tType(2B)\t\t: 0x%04x\n",
                (int) ((unsigned char *) ethh->ether_dhost)[0],
                (int) ((unsigned char *) ethh->ether_dhost)[1],
                (int) ((unsigned char *) ethh->ether_dhost)[2],
                (int) ((unsigned char *) ethh->ether_dhost)[3],
                (int) ((unsigned char *) ethh->ether_dhost)[4],
                (int) ((unsigned char *) ethh->ether_dhost)[5],
                (int) ((unsigned char *) ethh->ether_shost)[0],
                (int) ((unsigned char *) ethh->ether_shost)[1],
                (int) ((unsigned char *) ethh->ether_shost)[2],
                (int) ((unsigned char *) ethh->ether_shost)[3],
                (int) ((unsigned char *) ethh->ether_shost)[4],
                (int) ((unsigned char *) ethh->ether_shost)[5],
                ntohs(ethh->ether_type));
    }
}

void make_eth_header(struct ether_header *ethh, macaddr_t *src,
                     macaddr_t *dst) {
    // Create a frame with IPv4 ethertype by default
    make_eth_header_ethertype(ethh, src, dst, ETHERTYPE_IP);
}

void make_eth6_header(struct ether_header *ethh, macaddr_t *src,
                      macaddr_t *dst) {
    // Create a frame with IPv6 ethertype by default
    make_eth_header_ethertype(ethh, src, dst, ETHERTYPE_IPV6);
}

void make_eth_header_ethertype(struct ether_header *ethh, macaddr_t *src,
                               macaddr_t *dst, uint16_t ethertype) {
    memcpy(ethh->ether_shost, src, ETHER_ADDR_LEN);
    memcpy(ethh->ether_dhost, dst, ETHER_ADDR_LEN);
    ethh->ether_type = htons(ethertype);
}

void make_ip_header(struct ip *iph, uint8_t protocol, uint16_t ip_len) {
    iph->ip_hl  = 5; // Internet Header Length
    iph->ip_v   = 4; // IPv4
    iph->ip_tos = 0; // Type of Service
    iph->ip_len = htons(ip_len);
    iph->ip_id  = htons(54321); // identification number
    iph->ip_off = 0;            // fragmentation flag
    iph->ip_ttl = MAXTTL;       // time to live (TTL)
    iph->ip_p   = protocol;     // upper layer protocol => TCP
    // we set the checksum = 0 for now because that's
    // what it needs to be when we run the IP checksum
    iph->ip_sum = 0;
}

void make_ip6_header(struct ip6_hdr *iph, uint8_t protocol, uint16_t pl_len) {
    iph->ip6_ctlun.ip6_un2_vfc = 0x60; // 4 bits version, top 4 bits class
    iph->ip6_plen              = htons(pl_len); // payload length
    iph->ip6_nxt               = protocol;      // next header
    iph->ip6_hlim              = MAXTTL;        // hop limit
}

void make_icmp6_header(struct icmp6_hdr *buf) {
    buf->icmp6_type  = ICMP6_ECHO_REQUEST;
    buf->icmp6_code  = 0;
    buf->icmp6_cksum = 0;
}

void make_icmp_header(struct icmp *buf) {
    buf->icmp_type  = ICMP_ECHO;
    buf->icmp_code  = 0;
    buf->icmp_cksum = 0;
}

void make_tcp_header(struct tcphdr *tcp_header, uint16_t th_flags) {
    tcp_header->th_seq   = random();
    tcp_header->th_ack   = 0;
    tcp_header->th_x2    = 0;
    tcp_header->th_off   = 5; // data offset
    tcp_header->th_flags = 0;
    tcp_header->th_flags |= th_flags;
    tcp_header->th_win = htons(65535); // largest possible window
    tcp_header->th_sum = 0;
    tcp_header->th_urp = 0;
    //    tcp_header->th_dport
}

void make_udp_header(struct udphdr *udp_header, uint16_t len) {
    //    udp_header->uh_sport
    //    udp_header->uh_dport
    udp_header->uh_ulen = htons(len);
    udp_header->uh_sum  = 0; // checksum ignored in IPv4 if 0
}

// Note: caller must free return value
char *make_ip_str(uint32_t ip) {
    struct in_addr t;
    t.s_addr         = ip;
    const char *temp = inet_ntoa(t);
    char *      retv = xmalloc(strlen(temp) + 1);
    strcpy(retv, temp);
    return retv;
}

// Note: caller must free return value
char *make_ipv6_str(struct in6_addr *ipv6) {
    char *retv = xmalloc(INET6_ADDRSTRLEN + 1);
    inet_ntop(AF_INET6, ipv6, retv, INET6_ADDRSTRLEN);
    return retv;
}
