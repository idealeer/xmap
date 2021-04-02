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

// probe module for performing TCP SYN scans

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../lib/includes.h"
#include "../fieldset.h"
#include "packet.h"
#include "probe_modules.h"
#include "validate.h"

probe_module_t  module_tcp_syn;
static uint32_t tcp_num_sports;

static int tcp_syn_global_init(struct state_conf *state) {
    tcp_num_sports = state->source_port_last - state->source_port_first + 1;
    return EXIT_SUCCESS;
}

static int tcp_syn_thread_init(void *buf, macaddr_t *src, macaddr_t *gw,
                               UNUSED void **arg_ptr) {
    memset(buf, 0, MAX_PACKET_SIZE);

    struct ether_header *eth_header = (struct ether_header *) buf;
    make_eth_header(eth_header, src, gw);

    struct ip *ip_header = (struct ip *) (&eth_header[1]);
    uint16_t   ip_len    = sizeof(struct ip) + sizeof(struct tcphdr);
    make_ip_header(ip_header, IPPROTO_TCP, ip_len);

    struct tcphdr *tcp_header = (struct tcphdr *) (&ip_header[1]);
    make_tcp_header(tcp_header, TH_SYN);

    return EXIT_SUCCESS;
}

static int tcp_syn_make_packet(void *buf, UNUSED size_t *buf_len,
                               ipaddr_n_t *src_ip, ipaddr_n_t *dst_ip,
                               port_h_t dst_port, uint8_t ttl, int probe_num,
                               UNUSED void *arg) {
    struct ether_header *eth_header = (struct ether_header *) buf;
    struct ip *          ip_header  = (struct ip *) (&eth_header[1]);
    struct tcphdr *      tcp_header = (struct tcphdr *) (&ip_header[1]);

    uint8_t validation[VALIDATE_BYTES];
    validate_gen(src_ip, dst_ip, dst_port, validation);
    uint32_t tcp_seq = tcp_get_seqnum(validation);

    ip_header->ip_src.s_addr = *(uint32_t *) src_ip;
    ip_header->ip_dst.s_addr = *(uint32_t *) dst_ip;
    ip_header->ip_ttl        = ttl;
    tcp_header->th_sport =
        htons(get_src_port(tcp_num_sports, probe_num, validation));
    tcp_header->th_dport = htons(dst_port);
    tcp_header->th_seq   = tcp_seq;
    tcp_header->th_sum   = 0;
    tcp_header->th_sum =
        tcp_checksum(sizeof(struct tcphdr), ip_header->ip_src.s_addr,
                     ip_header->ip_dst.s_addr, tcp_header);

    ip_header->ip_sum = 0;
    ip_header->ip_sum = ip_checksum_((unsigned short *) ip_header);

    return EXIT_SUCCESS;
}

// not static because used by synack scan
void tcp_syn_print_packet(FILE *fp, void *packet) {
    struct ether_header *eth_header = (struct ether_header *) packet;
    struct ip *          ip_header  = (struct ip *) &eth_header[1];
    struct tcphdr *      tcp_header = (struct tcphdr *) &ip_header[1];

    fprintf_eth_header(fp, eth_header);
    fprintf_ip_header(fp, ip_header);
    fprintf(fp,
            "TCP\n"
            "\tSource Port(2B)\t\t: %u\n"
            "\tDestination Port(2B)\t: %u\n"
            "\tSequence number(4B)\t: %u\n"
            "\tAcknowledge number(4B)\t: %d\n"
            "\tHeader Length(4b)\t: %d\n"
            "\tFlag(12b)\t\t: 0x%03x\n"
            "\tWindow size value(2B)\t: %d\n"
            "\tChecksum(2B)\t\t: 0x%04x\n"
            "\tUrgent pointer(2B)\t: %d\n",
            ntohs(tcp_header->th_sport), ntohs(tcp_header->th_dport),
            ntohl(tcp_header->th_seq), ntohl(tcp_header->th_ack),
            tcp_header->th_off * 4, tcp_header->th_flags,
            ntohs(tcp_header->th_win), tcp_header->th_sum, tcp_header->th_urp);
    fprintf(fp, "------------------------------------------------------\n");
}

static int tcp_syn_validate_packet(const struct ip *ip_hdr, uint32_t len,
                                   UNUSED int *is_repeat) {
    if (ip_hdr->ip_p != IPPROTO_TCP) {
        return PACKET_INVALID;
    }
    if ((4 * ip_hdr->ip_hl + sizeof(struct tcphdr)) > len) {
        // buffer not large enough to contain expected tcp_header header
        return PACKET_INVALID;
    }

    struct tcphdr *tcp_header =
        (struct tcphdr *) ((char *) ip_hdr + 4 * ip_hdr->ip_hl);
    uint16_t dport = ntohs(tcp_header->th_sport);
    uint16_t sport = ntohs(tcp_header->th_dport);

    // validate destination port
    if (!xconf.target_port_flag[dport]) {
        return PACKET_INVALID;
    }

    // validate source port
    uint8_t validation[VALIDATE_BYTES];
    validate_gen((uint8_t *) &(ip_hdr->ip_dst.s_addr),
                 (uint8_t *) &(ip_hdr->ip_src.s_addr), dport, validation);
    if (!check_src_port(sport, tcp_num_sports, validation)) {
        return PACKET_INVALID;
    }

    // We treat RST packets different from non RST packets
    uint32_t tcp_seq = tcp_get_seqnum(validation);
    if (tcp_header->th_flags & TH_RST) {
        // For RST packets, recv(ack) == sent(seq) + 0 or + 1
        if (htonl(tcp_header->th_ack) != htonl(tcp_seq) &&
            htonl(tcp_header->th_ack) != htonl(tcp_seq) + 1) {
            return PACKET_INVALID;
        }
    } else {
        // For non RST packets, recv(ack) == sent(seq) + 1
        if (htonl(tcp_header->th_ack) != htonl(tcp_seq) + 1) {
            return PACKET_INVALID;
        }
    }

    // whether repeat: reply ip + dport
    char ip_port_str[xconf.ipv46_bytes + 2];
    memcpy(ip_port_str, (char *) &(ip_hdr->ip_src.s_addr), xconf.ipv46_bytes);
    ip_port_str[xconf.ipv46_bytes]     = (char) (dport >> 8u);
    ip_port_str[xconf.ipv46_bytes + 1] = (char) (dport & 0xffu);
    if (bloom_filter_check_string(&xrecv.bf, (const char *) ip_port_str,
                                  xconf.ipv46_bytes + 2) == BLOOM_FAILURE) {
        bloom_filter_add_string(&xrecv.bf, (const char *) ip_port_str,
                                xconf.ipv46_bytes + 2);
        *is_repeat = 0;
    }

    return PACKET_VALID;
}

static void tcp_syn_process_packet(const u_char *packet, UNUSED uint32_t len,
                                   fieldset_t *fs, UNUSED struct timespec ts) {
    struct ip *ip_heaher = (struct ip *) &packet[sizeof(struct ether_header)];
    struct tcphdr *tcp_header =
        (struct tcphdr *) ((char *) ip_heaher + 4 * ip_heaher->ip_hl);

    fs_add_uint64(fs, "sport", (uint64_t) ntohs(tcp_header->th_sport));
    fs_add_uint64(fs, "dport", (uint64_t) ntohs(tcp_header->th_dport));
    fs_add_uint64(fs, "seqnum", (uint64_t) ntohl(tcp_header->th_seq));
    fs_add_uint64(fs, "acknum", (uint64_t) ntohl(tcp_header->th_ack));
    fs_add_uint64(fs, "window", (uint64_t) ntohs(tcp_header->th_win));

    if (tcp_header->th_flags & TH_RST) { // RST packet
        fs_add_string(fs, "clas", (char *) "rst", 0);
        fs_add_bool(fs, "success", 0);
    } else { // SYNACK packet
        fs_add_string(fs, "clas", (char *) "synack", 0);
        fs_add_bool(fs, "success", 1);
    }
}

static fielddef_t fields[] = {
    {.name = "sport", .type = "int", .desc = "TCP source port"},
    {.name = "dport", .type = "int", .desc = "TCP destination port"},
    {.name = "seqnum", .type = "int", .desc = "TCP sequence number"},
    {.name = "acknum", .type = "int", .desc = "TCP acknowledgement number"},
    {.name = "window", .type = "int", .desc = "TCP window size"},
    {.name = "clas",
     .type = "string",
     .desc = "packet classification"
             "\t\t\te.g., `synack', `rst'\n"},
    {.name = "success",
     .type = "bool",
     .desc = "is response considered success"}};

probe_module_t module_tcp_syn = {
    .ipv46_flag      = 4,
    .name            = "tcp_syn",
    .packet_length   = 14 + 20 + 20,
    .pcap_filter     = "ip && tcp && (tcp[13] & 4 != 0 || tcp[13] == 18)",
    .pcap_snaplen    = 14 + 20 + 20 + 40,
    .port_args       = 1,
    .global_init     = &tcp_syn_global_init,
    .thread_init     = &tcp_syn_thread_init,
    .make_packet     = &tcp_syn_make_packet,
    .print_packet    = &tcp_syn_print_packet,
    .process_packet  = &tcp_syn_process_packet,
    .validate_packet = &tcp_syn_validate_packet,
    .close           = NULL,
    .output_type     = OUTPUT_TYPE_STATIC,
    .fields          = fields,
    .numfields       = sizeof(fields) / sizeof(fields[0]),
    .helptext        = "Probe module that sends a TCP SYN packet to a specific "
                "port. Possible classifications are: synack and rst. A "
                "SYN-ACK packet is considered a success and a reset packet "
                "is considered a failed response."};
