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

/* send module for performing arbitrary IPv4 UDP scans */

#include <assert.h>
#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../lib/blocklist.h"
#include "../../lib/lockfd.h"
#include "../../lib/logger.h"
#include "../../lib/xalloc.h"
#include "../aesrand.h"
#include "../state.h"
#include "packet.h"
#include "packet_icmp.h"
#include "probe_modules.h"
#include "validate.h"

#include "module_udp.h"

#define MAX_UDP_PAYLOAD_LEN 1500 - 20 - 8 // 1500 - IP_h - UDP_h
#define ICMP_UNREACH_HEADER_SIZE 8
#define UDP_SEND_MSG_EXT_NUM 3

static char *                  udp_send_msg           = NULL;
static int                     udp_send_msg_len       = 0;
static int                     udp_send_substitutions = 0;
static udp_payload_template_t *udp_template           = NULL;

static char *      udp_send_msg_list[MAX_PORT_NUM];
static int         udp_send_msg_len_list[MAX_PORT_NUM];
static const char *udp_send_msg_ext_list[UDP_SEND_MSG_EXT_NUM] = {"pkt", "txt",
                                                                  "hex"};
enum UDP_SEND_MSG_EXT { PKT, TXT, HEX };
static int udp_send_dir_payload = 0;

static const char *udp_send_msg_default =
    "GET / HTTP/1.1\r\nHost: ida.\r\n\r\n";
static const int udp_send_msg_default_len = 30;

const char *udp_usage_error = "unknown UDP probe specification "
                              "(expected file:/path or text:STRING or "
                              "hex:01020304 or dir:/dir_to_files or "
                              "template:/path or template-fields or "
                              "icmp-type-code-str)";

const unsigned char *charset_alphanum =
    (unsigned char
         *) "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const unsigned char *charset_alpha =
    (unsigned char *) "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const unsigned char *charset_digit    = (unsigned char *) "0123456789";
const unsigned char  charset_all[257] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24,
    0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c,
    0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
    0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54,
    0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60,
    0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c,
    0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
    0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84,
    0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90,
    0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c,
    0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
    0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4,
    0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0,
    0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc,
    0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8,
    0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4,
    0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0,
    0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc,
    0xfd, 0xfe, 0xff, 0x00};

static int udp_num_sports;

probe_module_t module_udp;

// Field definitions for template parsing and displaying usage
static udp_payload_field_type_def_t udp_payload_template_fields[] = {
    {.name  = "SADDR_N",
     .ftype = UDP_SADDR_N,
     .desc  = "Source IPv4 address in network byte order"},
    {.name  = "SADDR",
     .ftype = UDP_SADDR_A,
     .desc  = "Source IPv4 address in dotted-quad format"},
    {.name  = "DADDR_N",
     .ftype = UDP_DADDR_N,
     .desc  = "Destination IPv4 address in network byte order"},
    {.name  = "DADDR",
     .ftype = UDP_DADDR_A,
     .desc  = "Destination IPv4 address in dotted-quad format"},
    {.name  = "SPORT_N",
     .ftype = UDP_SPORT_N,
     .desc  = "UDP source port in netowrk byte order"},
    {.name  = "SPORT",
     .ftype = UDP_SPORT_A,
     .desc  = "UDP source port in ascii format"},
    {.name  = "DPORT_N",
     .ftype = UDP_DPORT_N,
     .desc  = "UDP destination port in network byte order"},
    {.name  = "DPORT",
     .ftype = UDP_DPORT_A,
     .desc  = "UDP destination port in ascii format"},
    {.name  = "RAND_BYTE",
     .ftype = UDP_RAND_BYTE,
     .desc  = "Random bytes from 0-255"},
    {.name  = "RAND_DIGIT",
     .ftype = UDP_RAND_DIGIT,
     .desc  = "Random digits from 0-9"},
    {.name  = "RAND_ALPHA",
     .ftype = UDP_RAND_ALPHA,
     .desc  = "Random mixed-case letters (a-z)"},
    {.name  = "RAND_ALPHANUM",
     .ftype = UDP_RAND_ALPHANUM,
     .desc  = "Random mixed-case letters (a-z) and numbers"}};
static uint32_t udp_num_template_field_types =
    sizeof(udp_payload_template_fields) /
    sizeof(udp_payload_template_fields[0]);

void udp_set_num_sports(int x) { udp_num_sports = x; }

static int udp_load_payload(const char *dir) {
    log_debug("udp", "load udp payload from dir");
    if (!opendir(dir)) {
        log_error("udp", "could not read UDP data dir '%s'", dir);
        return EXIT_FAILURE;
    }

    udp_send_msg_len = 0;

    char dir_new[strlen(dir) + 1];
    strncpy(dir_new, dir, strlen(dir));
    if (dir[strlen(dir) - 1] != '/') strcat(dir_new, "/");

    FILE *       inp;
    unsigned int n, f;
    int          port;

    for (int i = 0; i < xconf.target_port_num; i++) {
        port                        = xconf.target_port_list[i];
        f                           = 0;
        udp_send_msg_list[port]     = strdup(udp_send_msg_default);
        udp_send_msg_len_list[port] = udp_send_msg_default_len;
        char *new_file              = xmalloc(strlen(dir_new) + 10);
        for (int j = 0; j < UDP_SEND_MSG_EXT_NUM; j++) {
            memset(new_file, 0, strlen(dir_new) + 10);
            sprintf(new_file, "%s%d.%s", dir_new, port,
                    udp_send_msg_ext_list[j]);

            switch (j) {
            case PKT:
                inp = fopen(new_file, "rb");
                break;
            case TXT:
            case HEX:
                inp = fopen(new_file, "r");
                break;
            default:
                continue;
            }
            if (!inp) continue;

            char *udp_send_msg_t;
            int   udp_send_msg_len_t;
            free(udp_send_msg_list[port]);
            switch (j) {
            case PKT:
            case TXT:
                udp_send_msg_list[port]     = xmalloc(MAX_UDP_PAYLOAD_LEN);
                udp_send_msg_len_list[port] = (int) fread(
                    udp_send_msg_list[port], 1, MAX_UDP_PAYLOAD_LEN, inp);
                fclose(inp);
                break;
            case HEX:
                udp_send_msg_t     = xmalloc(MAX_UDP_PAYLOAD_LEN * 2);
                udp_send_msg_len_t = (int) fread(udp_send_msg_t, 1,
                                                 MAX_UDP_PAYLOAD_LEN * 2, inp);
                fclose(inp);
                udp_send_msg_len_t          = (int) udp_send_msg_len_t / 2;
                udp_send_msg_list[port]     = xmalloc(udp_send_msg_len_t);
                udp_send_msg_len_list[port] = udp_send_msg_len_t;
                for (int k = 0; k < udp_send_msg_len_t; k++) {
                    if (sscanf(udp_send_msg_t + (k * 2), "%2x", &n) != 1) {
                        log_error("udp", "non-hex character: '%02x'",
                                  udp_send_msg_t[k * 2]);
                        free(udp_send_msg_t);
                        return EXIT_FAILURE;
                    }
                    udp_send_msg_list[port][k] = (n & 0xff);
                }
                free(udp_send_msg_t);
                break;
            default:
                break;
            }

            j = UDP_SEND_MSG_EXT_NUM;
            f = 1;
            log_debug("udp", "read UDP data file '%s' for port %d", new_file,
                      port);
        }

        if (sizeof(struct ether_header) + sizeof(struct ip) +
                sizeof(struct udphdr) + udp_send_msg_len_list[port] >
            MAX_PACKET_SIZE) {
            log_error("udp", "payload too long, should be no more than %d",
                      MAX_PACKET_SIZE -
                          (sizeof(struct ether_header) + sizeof(struct ip) +
                           sizeof(struct udphdr)));
            return EXIT_FAILURE;
        }

        udp_send_msg_len += udp_send_msg_len_list[port];

        free(new_file);
        if (!f) {
            log_debug("udp", "no UDP data file for port %d, using default",
                      port);
        }
    }

    udp_send_msg_len /= xconf.target_port_num;
    log_debug("udp", "load udp payload from dir completed");

    return EXIT_SUCCESS;
}

int udp_global_init(struct state_conf *conf) {
    udp_num_sports = conf->source_port_last - conf->source_port_first + 1;

    udp_send_msg     = strdup(udp_send_msg_default);
    udp_send_msg_len = udp_send_msg_default_len;
    if (!(conf->probe_args && strlen(conf->probe_args) > 0))
        return EXIT_SUCCESS;

    char *       args, *c;
    int          i;
    unsigned int n;

    FILE *inp;

    args = strdup(conf->probe_args);
    assert(args);

    if (strcmp(args, "icmp-type-code-str") == 0) {
        print_icmp_type_code_str();
        exit(EXIT_SUCCESS);
    }

    if (strcmp(args, "template-fields") == 0) {
        lock_file(stderr);
        fprintf(stderr, "%s", "List of allowed UDP template fields\n");
        fprintf(stderr,
                "------------------------------------------------------\n");
        fprintf(stderr, "%-15s: %s\n", "Name", "Description");
        fprintf(stderr,
                "------------------------------------------------------\n");
        for (uint32_t i = 0; i < udp_num_template_field_types; i++) {
            fprintf(stderr, "%-15s: %s\n", udp_payload_template_fields[i].name,
                    udp_payload_template_fields[i].desc);
        }
        fprintf(stderr,
                "------------------------------------------------------\n");
        fprintf(stderr, "%s\n",
                "Example:\n    Specify the field at ${}, e.g., ${SADDR}, "
                "${RAND_DIGIT=9}");
        unlock_file(stderr);
        exit(EXIT_SUCCESS);
    }

    c = strchr(args, ':');
    if (!c) {
        free(args);
        free(udp_send_msg);
        log_error("udp", udp_usage_error);
        return EXIT_FAILURE;
    }

    *c++ = 0;

    if (strcmp(args, "text") == 0) {
        free(udp_send_msg);
        udp_send_msg     = strdup(c);
        udp_send_msg_len = (int) strlen(udp_send_msg);
    } else if (strcmp(args, "file") == 0 || strcmp(args, "template") == 0) {
        inp = fopen(c, "rb");
        if (!inp) {
            log_error("udp", "could not open UDP data file '%s'", c);
            free(args);
            free(udp_send_msg);
            return EXIT_FAILURE;
        }
        free(udp_send_msg);
        udp_send_msg = xmalloc(MAX_UDP_PAYLOAD_LEN);
        udp_send_msg_len =
            (int) fread(udp_send_msg, 1, MAX_UDP_PAYLOAD_LEN, inp);
        fclose(inp);

        if (strcmp(args, "template") == 0) {
            udp_send_substitutions = 1;
            udp_template = udp_template_load(udp_send_msg, udp_send_msg_len);
        }

    } else if (strcmp(args, "hex") == 0) {
        udp_send_msg_len = (int) strlen(c) / 2;
        free(udp_send_msg);
        udp_send_msg = xmalloc(udp_send_msg_len);

        for (i = 0; i < udp_send_msg_len; i++) {
            if (sscanf(c + (i * 2), "%2x", &n) != 1) {
                log_error("udp", "non-hex character: '%c'", c[i * 2]);
                free(args);
                free(udp_send_msg);
                return EXIT_FAILURE;
            }
            udp_send_msg[i] = (n & 0xff);
        }
    } else if (strcmp(args, "dir") == 0) {
        udp_send_dir_payload = 1;
        if (udp_load_payload(c))
            return EXIT_FAILURE; // udp_send_msg_len = avg len
    } else {
        log_error("udp", udp_usage_error);
        free(args);
        free(udp_send_msg);
        return EXIT_FAILURE;
    }

    if (udp_send_msg_len > MAX_UDP_PAYLOAD_LEN) {
        log_warn("udp",
                 "warning: reducing UDP payload to %d bytes (from %d) to fit "
                 "on the wire",
                 MAX_UDP_PAYLOAD_LEN, udp_send_msg_len);
        udp_send_msg_len = MAX_UDP_PAYLOAD_LEN;
    }

    module_udp.packet_length = sizeof(struct ether_header) + sizeof(struct ip) +
                               sizeof(struct udphdr) + udp_send_msg_len;
    assert(module_udp.packet_length <= MAX_PACKET_SIZE);

    free(args);

    return EXIT_SUCCESS;
}

int udp_global_cleanup(UNUSED struct state_conf *xconf,
                       UNUSED struct state_send *xsend,
                       UNUSED struct state_recv *xrecv) {
    if (udp_send_msg) {
        free(udp_send_msg);
        udp_send_msg = NULL;
    }

    if (udp_template) {
        udp_template_free(udp_template);
        udp_template = NULL;
    }

    if (udp_send_dir_payload) {
        for (int i = 0; i < MAX_PORT_NUM; i++)
            if (udp_send_msg_list[i]) {
                free(udp_send_msg_list[i]);
                udp_send_msg_list[i] = NULL;
            }
    }

    return EXIT_SUCCESS;
}

int udp_thread_init(void *buf, macaddr_t *src, macaddr_t *gw, void **arg_ptr) {
    memset(buf, 0, MAX_PACKET_SIZE);

    struct ether_header *eth_header = (struct ether_header *) buf;
    make_eth_header(eth_header, src, gw);

    struct ip *ip_header = (struct ip *) (&eth_header[1]);
    uint16_t   ip_len =
        sizeof(struct ip) + sizeof(struct udphdr) + udp_send_msg_len;
    make_ip_header(ip_header, IPPROTO_UDP, ip_len);

    struct udphdr *udp_header = (struct udphdr *) (&ip_header[1]);
    uint16_t       udp_len    = sizeof(struct udphdr) + udp_send_msg_len;
    make_udp_header(udp_header, udp_len);

    char *payload = (char *) (&udp_header[1]);
    memcpy(payload, udp_send_msg, udp_send_msg_len);

    // Seed our random number generator with the global generator
    uint32_t   seed = aesrand_getword(xconf.aes);
    aesrand_t *aes  = aesrand_init_from_seed(seed);
    *arg_ptr        = aes;

    return EXIT_SUCCESS;
}

int udp_make_packet(void *buf, UNUSED size_t *buf_len, ipaddr_n_t *src_ip,
                    ipaddr_n_t *dst_ip, port_h_t dst_port, uint8_t ttl,
                    int probe_num, UNUSED void *arg) {
    struct ether_header *eth_header = (struct ether_header *) buf;
    struct ip *          ip_header  = (struct ip *) (&eth_header[1]);
    struct udphdr *      udp_header = (struct udphdr *) &ip_header[1];

    ip_header->ip_src.s_addr = *(uint32_t *) src_ip;
    ip_header->ip_dst.s_addr = *(uint32_t *) dst_ip;
    ip_header->ip_ttl        = ttl;

    uint8_t validation[VALIDATE_BYTES];
    validate_gen(src_ip, dst_ip, dst_port, validation);

    udp_header->uh_sport =
        htons(get_src_port(udp_num_sports, probe_num, validation));
    udp_header->uh_dport = htons(dst_port);

    if (udp_send_substitutions) { // from templete
        char *payload     = (char *) &udp_header[1];
        int   payload_len = 0;
        memset(payload, 0, MAX_UDP_PAYLOAD_LEN);

        // Grab our random number generator
        aesrand_t *aes = (aesrand_t *) arg;

        // The buf is a stack var of our caller of size MAX_PACKET_SIZE
        // Recalculate the payload using the loaded template
        payload_len =
            udp_template_build(udp_template, payload, MAX_UDP_PAYLOAD_LEN,
                               ip_header, udp_header, aes);
        // Recalculate the total length of the packet
        module_udp.packet_length = sizeof(struct ether_header) +
                                   sizeof(struct ip) + sizeof(struct udphdr) +
                                   payload_len;

        // If success is zero, the template output was truncated
        if (payload_len <= 0) {
            log_fatal("udp", "UDP payload template generated an empty payload");
            exit(EXIT_FAILURE);
        }

        // Update the IP and UDP headers to match the new payload length
        size_t ip_len = sizeof(struct ip) + sizeof(struct udphdr) + payload_len;
        ip_header->ip_len   = htons(ip_len);
        udp_header->uh_ulen = htons(sizeof(struct udphdr) + payload_len);
        *buf_len            = ip_len + sizeof(struct ether_header);
    } else if (udp_send_dir_payload) { // from dir
        char *payload     = (char *) &udp_header[1];
        int   payload_len = udp_send_msg_len_list[dst_port];
        memcpy(payload, udp_send_msg_list[dst_port], payload_len);

        // Update the IP and UDP headers to match the new payload length
        size_t ip_len = sizeof(struct ip) + sizeof(struct udphdr) + payload_len;
        ip_header->ip_len   = htons(ip_len);
        udp_header->uh_ulen = htons(sizeof(struct udphdr) + payload_len);
        *buf_len            = ip_len + sizeof(struct ether_header);
    }

    udp_header->uh_sum = 0;
    udp_header->uh_sum = udp_checksum(ip_header->ip_src.s_addr,
                                      ip_header->ip_dst.s_addr, udp_header);

    ip_header->ip_sum = 0;
    ip_header->ip_sum = ip_checksum_((unsigned short *) ip_header);

    return EXIT_SUCCESS;
}

void udp_print_packet(FILE *fp, void *packet) {
    struct ether_header *eth_header = (struct ether_header *) packet;
    struct ip *          ip_header  = (struct ip *) &eth_header[1];
    struct udphdr *      udp_header = (struct udphdr *) (&ip_header[1]);

    fprintf_eth_header(fp, eth_header);
    fprintf_ip_header(fp, ip_header);
    fprintf(fp,
            "UDP\n"
            "\tSource Port(2B)\t\t: %u\n"
            "\tDestination Port(2B)\t: %u\n"
            "\tLength(2B)\t\t: %u\n"
            "\tChecksum(2B)\t\t: 0x%04x\n",
            ntohs(udp_header->uh_sport), ntohs(udp_header->uh_dport),
            ntohs(udp_header->uh_ulen), ntohs(udp_header->uh_sum));
    fprintf(fp, "------------------------------------------------------\n");
}

int udp_validate_packet(const struct ip *ip_hdr, uint32_t len,
                        UNUSED int *is_repeat) {
    uint16_t dport;
    if (ip_hdr->ip_p == IPPROTO_UDP) {
        if ((4 * ip_hdr->ip_hl + sizeof(struct udphdr)) > len) {
            // buffer not large enough to contain expected udp
            // header
            return PACKET_INVALID;
        }

        struct udphdr *udp_header =
            (struct udphdr *) ((char *) ip_hdr + 4 * ip_hdr->ip_hl);
        uint16_t sport = ntohs(udp_header->uh_dport);
        dport          = ntohs(udp_header->uh_sport);

        if (!xconf.target_port_flag[dport]) {
            return PACKET_INVALID;
        }

        uint8_t validation[VALIDATE_BYTES];
        validate_gen((uint8_t *) &(ip_hdr->ip_dst.s_addr),
                     (uint8_t *) &(ip_hdr->ip_src.s_addr), dport, validation);
        if (!check_src_port(sport, udp_num_sports, validation)) {
            return PACKET_INVALID;
        }

        if (!blocklist_is_allowed_ip((uint8_t *) &(ip_hdr->ip_src.s_addr))) {
            return PACKET_INVALID;
        }

    } else if (ip_hdr->ip_p == IPPROTO_ICMP) {
        // UDP can return ICMP Destination unreach
        // IP( ICMP( IP( UDP ) ) ) for a destination unreach
        const uint32_t min_len = 4 * ip_hdr->ip_hl + ICMP_UNREACH_HEADER_SIZE +
                                 sizeof(struct ip) + sizeof(struct udphdr);
        if (len < min_len) {
            // Not enough information for us to validate
            return PACKET_INVALID;
        }

        struct icmp *icmp_header =
            (struct icmp *) ((char *) ip_hdr + 4 * ip_hdr->ip_hl);
        if (!(icmp_header->icmp_type == ICMP_TIMXCEED ||
              icmp_header->icmp_type == ICMP_UNREACH ||
              icmp_header->icmp_type == ICMP_PARAMPROB)) {
            return PACKET_INVALID;
        }

        struct ip *ip_inner_header =
            (struct ip *) ((char *) icmp_header + ICMP_UNREACH_HEADER_SIZE);
        // Now we know the actual inner ip length, we should recheck the
        // buffer
        if (len < 4 * ip_inner_header->ip_hl - sizeof(struct ip) + min_len) {
            return PACKET_INVALID;
        }

        // This is the UDP packet we sent
        struct udphdr *udp_inner_header =
            (struct udphdr *) ((char *) ip_inner_header +
                               4 * ip_inner_header->ip_hl);
        // we can always check the destination port because this is the
        // original packet and wouldn't have been altered by something
        // responding on a different port
        dport          = ntohs(udp_inner_header->uh_dport);
        uint16_t sport = ntohs(udp_inner_header->uh_sport);
        if (!xconf.target_port_flag[dport]) {
            return PACKET_INVALID;
        }

        uint8_t validation[VALIDATE_BYTES];
        validate_gen((uint8_t *) &(ip_inner_header->ip_src.s_addr),
                     (uint8_t *) &(ip_inner_header->ip_dst.s_addr), dport,
                     validation);
        if (!check_src_port(sport, udp_num_sports, validation)) {
            return PACKET_INVALID;
        }

        // find original destination IP and check that we sent a packet
        // to that IP address
        if (!blocklist_is_allowed_ip(
                (uint8_t *) &(ip_inner_header->ip_dst.s_addr))) {
            return PACKET_INVALID;
        }

    } else {
        return PACKET_INVALID;
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

void udp_process_packet(const u_char *packet, uint32_t len, fieldset_t *fs,
                        UNUSED struct timespec ts) {
    struct ip *ip_header = (struct ip *) &packet[sizeof(struct ether_header)];
    if (ip_header->ip_p == IPPROTO_UDP) {
        struct udphdr *udp_header =
            (struct udphdr *) ((char *) ip_header + ip_header->ip_hl * 4);
        fs_add_bool(fs, "success", 1);
        fs_add_constchar(fs, "clas", "udp");
        fs_add_uint64(fs, "sport", ntohs(udp_header->uh_sport));
        fs_add_uint64(fs, "dport", ntohs(udp_header->uh_dport));
        fs_add_null(fs, "icmp_responder");
        fs_add_null(fs, "icmp_type");
        fs_add_null(fs, "icmp_code");
        fs_add_null(fs, "icmp_str");
        fs_add_uint64(fs, "udp_pkt_size", ntohs(udp_header->uh_ulen));
        // Verify that the UDP length is big enough for the header and
        // at least one byte
        uint16_t payload_len =
            ntohs(udp_header->uh_ulen - sizeof(struct udphdr));
        if (payload_len > 0) {
            uint32_t max_rlen = len - sizeof(struct ether_header) -
                                ip_header->ip_hl * 4 - sizeof(struct udphdr);
            uint32_t max_ilen = ntohs(ip_header->ip_len) -
                                ip_header->ip_hl * 4 - sizeof(struct udphdr);

            // Verify that the UDP length is inside of our received
            // buffer
            if (payload_len > max_rlen) {
                payload_len = max_rlen;
            }
            // Verify that the UDP length is inside of our IP packet
            if (payload_len > max_ilen) {
                payload_len = max_ilen;
            }
            fs_add_binary(fs, "data", payload_len, (void *) &udp_header[1], 0);
            // Some devices reply with a zero UDP length but still
            // return data, ignore the data
        } else {
            fs_add_null(fs, "data");
        }
    } else if (ip_header->ip_p == IPPROTO_ICMP) {
        struct icmp *icmp_header =
            (struct icmp *) ((char *) ip_header + ip_header->ip_hl * 4);
        struct ip *ip_inner_header =
            (struct ip *) ((char *) icmp_header + ICMP_UNREACH_HEADER_SIZE);
        struct udphdr *udp_inner_header =
            (struct udphdr *) (&ip_inner_header[1]);
        // ICMP unreach comes from another server (not the one we sent a
        // probe to); But we will fix up saddr to be who we sent the
        // probe to, in case you care.
        fs_modify_string(fs, "saddr",
                         make_ip_str(ip_inner_header->ip_dst.s_addr), 1);
        fs_add_bool(fs, "success", 0);
        fs_add_string(fs, "clas",
                      (char *) get_icmp_type_str(icmp_header->icmp_type), 0);
        fs_add_uint64(fs, "sport", ntohs(udp_inner_header->uh_dport));
        fs_add_uint64(fs, "dport", ntohs(udp_inner_header->uh_sport));
        fs_add_string(fs, "icmp_responder",
                      make_ip_str(ip_header->ip_src.s_addr), 1);
        fs_add_uint64(fs, "icmp_type", icmp_header->icmp_type);
        fs_add_uint64(fs, "icmp_code", icmp_header->icmp_code);
        fs_add_string(fs, "icmp_str",
                      (char *) get_icmp_type_code_str(icmp_header->icmp_type,
                                                      icmp_header->icmp_code),
                      0);
        fs_add_null(fs, "udp_pkt_size");
        fs_add_null(fs, "data");
    } else {
        fs_add_bool(fs, "success", 0);
        fs_add_string(fs, "clas", (char *) "other", 0);
        fs_add_null(fs, "sport");
        fs_add_null(fs, "dport");
        fs_add_null(fs, "icmp_responder");
        fs_add_null(fs, "icmp_type");
        fs_add_null(fs, "icmp_code");
        fs_add_null(fs, "icmp_str");
        fs_add_null(fs, "udp_pkt_size");
        fs_add_null(fs, "data");
    }
}

//
// payload templete
int udp_random_bytes(char *dst, int len, const unsigned char *charset,
                     int charset_len, aesrand_t *aes) {
    int i;
    for (i = 0; i < len; i++) {
        *dst++ = charset[(aesrand_getword(aes) & 0xFFFFFFFF) % charset_len];
    }

    return i;
}

int udp_template_build(udp_payload_template_t *t, char *out, unsigned int len,
                       struct ip *ip_hdr, struct udphdr *udp_hdr,
                       aesrand_t *aes) {
    udp_payload_field_t *c;
    char *               p;
    char *               max;
    char                 tmp[256];
    int                  full = 0;
    unsigned int         x, y;
    uint32_t *           u32;
    uint16_t *           u16;

    max = out + len;
    p   = out;

    for (x = 0; x < t->fcount; x++) {
        c = t->fields[x];

        // Exit the processing loop if our packet buffer would overflow
        if (p + c->length >= max) {
            full = 1;
            return 0;
        }

        switch (c->ftype) {

            // These fields have a specified output length value

        case UDP_DATA:
            if (!(c->data && c->length)) break;
            memcpy(p, c->data, c->length);
            p += c->length;
            break;

        case UDP_RAND_DIGIT:
            p += udp_random_bytes(p, c->length, charset_digit, 10, aes);
            break;

        case UDP_RAND_ALPHA:
            p += udp_random_bytes(p, c->length, charset_alpha, 52, aes);
            break;

        case UDP_RAND_ALPHANUM:
            p += udp_random_bytes(p, c->length, charset_alphanum, 62, aes);
            break;

        case UDP_RAND_BYTE:
            p += udp_random_bytes(p, c->length, charset_all, 256, aes);
            break;

            // These fields need to calculate size on their own

            // TODO: Condense these case statements to remove redundant code
        case UDP_SADDR_A:
            if (p + 15 >= max) {
                full = 1;
                break;
            }
            // Write to stack and then memcpy in order to properly
            // track length
            inet_ntop(AF_INET, (char *) &ip_hdr->ip_src, tmp, sizeof(tmp) - 1);
            memcpy(p, tmp, strlen(tmp));
            p += strlen(tmp);
            break;

        case UDP_DADDR_A:
            if (p + 15 >= max) {
                full = 1;
                break;
            }
            // Write to stack and then memcpy in order to properly
            // track length
            inet_ntop(AF_INET, (char *) &ip_hdr->ip_dst, tmp, sizeof(tmp) - 1);
            memcpy(p, tmp, strlen(tmp));
            p += strlen(tmp);
            break;

        case UDP_SADDR_N:
            if (p + 4 >= max) {
                full = 1;
                break;
            }

            u32  = (uint32_t *) p;
            *u32 = ip_hdr->ip_src.s_addr;
            p += 4;
            break;

        case UDP_DADDR_N:
            if (p + 4 >= max) {
                full = 1;
                break;
            }
            u32  = (uint32_t *) p;
            *u32 = ip_hdr->ip_dst.s_addr;
            p += 4;
            break;

        case UDP_SPORT_N:
            if (p + 2 >= max) {
                full = 1;
                break;
            }
            u16  = (uint16_t *) p;
            *u16 = udp_hdr->uh_sport;
            p += 2;
            break;

        case UDP_DPORT_N:
            if (p + 2 >= max) {
                full = 1;
                break;
            }
            u16  = (uint16_t *) p;
            *u16 = udp_hdr->uh_sport;
            p += 2;
            break;

        case UDP_SPORT_A:
            if (p + 5 >= max) {
                full = 1;
                break;
            }
            y = snprintf(tmp, 6, "%d", ntohs(udp_hdr->uh_sport));
            memcpy(p, tmp, y);
            p += y;
            break;

        case UDP_DPORT_A:
            if (p + 5 >= max) {
                full = 1;
                break;
            }
            y = snprintf(tmp, 6, "%d", ntohs(udp_hdr->uh_sport));
            memcpy(p, tmp, y);
            p += y;
            break;
        }

        // Bail out if our packet buffer would overflow
        if (full == 1) {
            return 0;
        }
    }

    return p - out;
}

// Free all buffers held by the payload template, including its own
void udp_template_free(udp_payload_template_t *t) {
    for (unsigned int x = 0; x < t->fcount; x++) {
        if (t->fields[x]->data) {
            free(t->fields[x]->data);
            t->fields[x]->data = NULL;
        }
        free(t->fields[x]);
        t->fields[x] = NULL;
    }
    free(t->fields);
    t->fields = NULL;
    t->fcount = 0;
    free(t);
}

// Add a new field to the template
void udp_template_add_field(udp_payload_template_t * t,
                            udp_payload_field_type_t ftype, unsigned int length,
                            char *data) {
    udp_payload_field_t *c;

    t->fcount++;
    t->fields = xrealloc(t->fields, sizeof(udp_payload_field_t) * t->fcount);
    if (!t->fields) {
        exit(1);
    }

    t->fields[t->fcount - 1] = xmalloc(sizeof(udp_payload_field_t));
    c                        = t->fields[t->fcount - 1];

    if (!c) {
        exit(1);
    }

    c->ftype  = ftype;
    c->length = length;
    c->data   = data;
}

// Convert a string field name to a field type, parsing any specified length
// value
int udp_template_lookup_field(char *vname, udp_payload_field_t *c) {
    char *       param;
    unsigned int f;
    unsigned int olen   = 0;
    unsigned int fcount = sizeof(udp_payload_template_fields) /
                          sizeof(udp_payload_template_fields[0]);

    param = strstr((const char *) vname, "=");
    if (param) {
        *param = '\0';
        param++;
    }

    // Most field types treat their parameter as a generator output length
    // unless it is ignored (ADDR, PORT, etc).
    if (param) {
        olen = atoi((const char *) param);
    }

    // Find a field that matches the
    for (f = 0; f < fcount; f++) {

        if (strcmp((char *) vname, udp_payload_template_fields[f].name) == 0) {
            c->ftype  = udp_payload_template_fields[f].ftype;
            c->length = olen;
            c->data   = NULL;
            return 1;
        }
    }

    // No match, skip and treat it as a data field
    return 0;
}

// Allocate a payload template and populate it by parsing a template file as a
// binary buffer
udp_payload_template_t *udp_template_load(char *buf, unsigned int len) {
    udp_payload_template_t *t = xmalloc(sizeof(udp_payload_template_t));

    // The last $ we encountered outside of a field specifier
    char *dollar = NULL;

    // The last { we encountered outside of a field specifier
    char *lbrack = NULL;

    // Track the start pointer of a data field (static)
    char *s = buf;

    // Track the index into the template
    char *p = buf;

    char *       tmp;
    unsigned int tlen;

    udp_payload_field_t c;

    t->fcount = 0;
    t->fields = NULL;

    while (p < (buf + len)) {
        switch (*p) {

        case '$':
            if ((dollar && !lbrack) || !dollar) {
                dollar = p;
            }
            p++;
            continue;

        case '{':
            if (dollar && !lbrack) {
                lbrack = p;
            }

            p++;
            continue;

        case '}':
            if (!(dollar && lbrack)) {
                p++;
                continue;
            }

            // Store the leading bytes before ${ as a data field
            tlen = dollar - s;
            if (tlen > 0) {
                tmp = xmalloc(tlen);
                memcpy(tmp, s, tlen);
                udp_template_add_field(t, UDP_DATA, tlen, tmp);
            }

            tmp = xcalloc(1, p - lbrack);
            memcpy(tmp, lbrack + 1, p - lbrack - 1);

            if (udp_template_lookup_field(tmp, &c)) {
                udp_template_add_field(t, c.ftype, c.length, c.data);

                // Push the pointer past the } if this was a
                // valid variable
                s = p + 1;
            } else {

                // Rewind back to the ${ sequence if this was an
                // invalid variable
                s = dollar;
            }

            free(tmp);
            break;

        default:
            if (dollar && lbrack) {
                p++;
                continue;
            }
        }

        dollar = NULL;
        lbrack = NULL;

        p++;
    }

    // Store the trailing bytes as a final data field
    if (s < p) {
        tlen = p - s;
        tmp  = xmalloc(tlen);
        memcpy(tmp, s, tlen);
        udp_template_add_field(t, UDP_DATA, tlen, tmp);
    }

    return t;
}

static fielddef_t fields[] = {
    {.name = "success",
     .type = "bool",
     .desc = "is response considered success"},
    {.name = "clas",
     .type = "string",
     .desc = "packet classification(type str):\n"
             "\t\t\te.g., `udp', `unreach', `other'\n"
             "\t\t\tuse `--probe-args=icmp-type-code-str' to list"},
    {.name = "sport", .type = "int", .desc = "UDP source port"},
    {.name = "dport", .type = "int", .desc = "UDP destination port"},
    {.name = "icmp_responder",
     .type = "string",
     .desc = "source IP address of ICMP message"},
    {.name = "icmp_type", .type = "int", .desc = "icmp message type"},
    {.name = "icmp_code", .type = "int", .desc = "icmp message code"},
    {.name = "icmp_str",
     .type = "string",
     .desc = "ICMP message detail(code str):\n"
             "\t\t\tuse `--probe-args=icmp-type-code-str' to list"},
    {.name = "udp_pkt_size", .type = "int", .desc = "UDP packet length"},
    {.name = "data", .type = "binary", .desc = "UDP payload"}};

probe_module_t module_udp = {
    .ipv46_flag      = 4,
    .name            = "udp",
    .packet_length   = 14 + 20 + 8 + 30,
    .pcap_filter     = "(ip && udp) || icmp",
    .pcap_snaplen    = 1500,
    .port_args       = 1,
    .global_init     = &udp_global_init,
    .thread_init     = &udp_thread_init,
    .make_packet     = &udp_make_packet,
    .print_packet    = &udp_print_packet,
    .validate_packet = &udp_validate_packet,
    .process_packet  = &udp_process_packet,
    .close           = &udp_global_cleanup,
    .fields          = fields,
    .numfields       = sizeof(fields) / sizeof(fields[0]),
    .helptext =
        "Probe module that sends UDP packets to hosts.\n"
        "Packets can optionally be templated based on destination host.\n"
        "    --probe-args=file:/path_to_packet_file\n"
        "    --probe-args=text:SomeText\n"
        "    --probe-args=hex:5061796c6f6164\n"
        "    --probe-args=dir:/dir_to_files\n"
        "                 (each file named by port num, e.g., 53.pkt>txt>hex)\n"
        "    --probe-args=template:/path_to_template_file\n"
        "    --probe-args=template-fields (list allowed UDP template fields)\n"
        "    --probe-args=icmp-type-code-str (list allowed type/code str)",
};
