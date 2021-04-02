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

// probe module for performing ICMP echo request (ping) scans

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "packet.h"
#include "packet_icmp.h"
#include "probe_modules.h"

#include "../../lib/includes.h"
#include "../../lib/logger.h"
#include "../../lib/types.h"
#include "../../lib/xalloc.h"
#include "../fieldset.h"
#include "../validate.h"

#define ICMP_SMALLEST_SIZE 5
#define ICMP_MAX_PAYLOAD_LEN 1500 - 20 - 8 // 1500 - IP_h - ICMP_h
#define ICMP_TIMXCEED_UNREACH_HEADER_SIZE 8

probe_module_t module_icmp_echo;

const char *icmp_usage_error =
    "unknown ICMP probe specification (expected file:/path or text:STRING or "
    "hex:01020304 or icmp-type-code-str)";

static size_t       icmp_payload_len         = 0;
static const size_t icmp_payload_default_len = 8;
static char *       icmp_payload             = NULL;

static int icmp_echo_global_init(struct state_conf *conf) {
    if (!(conf->probe_args && strlen(conf->probe_args) > 0)) {
        icmp_payload     = xmalloc(icmp_payload_default_len);
        icmp_payload_len = icmp_payload_default_len;
        return EXIT_SUCCESS;
    }

    if (strcmp(conf->probe_args, "icmp-type-code-str") == 0) {
        print_icmp_type_code_str();
        exit(EXIT_SUCCESS);
    }

    char *c = strchr(conf->probe_args, ':');
    if (!c) {
        log_error("icmp", icmp_usage_error);
        return EXIT_FAILURE;
    }
    ++c;

    if (strncmp(conf->probe_args, "text", 4) == 0) {
        icmp_payload     = strdup(c);
        icmp_payload_len = strlen(icmp_payload);
    } else if (strncmp(conf->probe_args, "file", 4) == 0) {
        FILE *inp = fopen(c, "rb");
        if (!inp) {
            log_error("icmp", "could not open ICMP data file '%s'", c);
            return EXIT_FAILURE;
        }
        if (fseek(inp, 0, SEEK_END)) {
            log_error("icmp", "unable to get size of ICMP data file '%s'", c);
            return EXIT_FAILURE;
        }
        size_t input_size = ftell(inp);
        if (input_size > ICMP_MAX_PAYLOAD_LEN) {
            log_error(
                "icmp",
                "input file larger than %d bytes and will not fit on the wire "
                "(%llu bytes provided)",
                ICMP_MAX_PAYLOAD_LEN, input_size);
            return EXIT_FAILURE;
        }
        if (fseek(inp, 0, SEEK_SET)) {
            log_error("icmp", "unable to read ICMP data file '%s'", c);
            return EXIT_FAILURE;
        }
        icmp_payload     = xmalloc(ICMP_MAX_PAYLOAD_LEN);
        icmp_payload_len = fread(icmp_payload, 1, ICMP_MAX_PAYLOAD_LEN, inp);
        fclose(inp);
    } else if (strncmp(conf->probe_args, "hex", 3) == 0) {
        if (strlen(c) % 2 != 0) {
            log_error("icmp",
                      "invalid hex input (length must be a multiple of 2)");
            return EXIT_FAILURE;
        }
        icmp_payload_len = strlen(c) / 2;
        icmp_payload     = xmalloc(icmp_payload_len);

        unsigned int n;
        for (size_t i = 0; i < icmp_payload_len; i++) {
            if (sscanf(c + (i * 2), "%2x", &n) != 1) {
                free(icmp_payload);
                log_error("icmp", "non-hex character: '%c'", c[i * 2]);
                return EXIT_FAILURE;
            }
            icmp_payload[i] = (char) (n & 0xff);
        }
    } else {
        log_error("icmp", icmp_usage_error);
        return EXIT_FAILURE;
    }

    if (icmp_payload_len > ICMP_MAX_PAYLOAD_LEN) {
        log_error("icmp",
                  "reducing ICMP payload must be at most %d bytes to fit on "
                  "the wire (%d were provided)\n",
                  ICMP_MAX_PAYLOAD_LEN, icmp_payload_len);
        return EXIT_FAILURE;
    }

    module_icmp_echo.packet_length = sizeof(struct ether_header) +
                                     sizeof(struct ip) + ICMP_MINLEN +
                                     icmp_payload_len;
    assert(module_icmp_echo.packet_length <=
           1500 + sizeof(struct ether_header));
    module_icmp_echo.pcap_snaplen = sizeof(struct ether_header) +
                                    2 * (sizeof(struct ip) + ICMP_MINLEN) +
                                    icmp_payload_len;

    return EXIT_SUCCESS;
}

static int icmp_echo_global_cleanup(UNUSED struct state_conf *xconf,
                                    UNUSED struct state_send *xsend,
                                    UNUSED struct state_recv *xrecv) {
    if (icmp_payload) {
        free(icmp_payload);
        icmp_payload = NULL;
    }

    return EXIT_SUCCESS;
}

static int icmp_echo_thread_init(void *buf, macaddr_t *src, macaddr_t *gw,
                                 UNUSED void **arg_ptr) {
    memset(buf, 0, MAX_PACKET_SIZE);

    struct ether_header *eth_header = (struct ether_header *) buf;
    make_eth_header(eth_header, src, gw);

    struct ip *ip_header = (struct ip *) (&eth_header[1]);
    uint16_t   ip_len    = sizeof(struct ip) + ICMP_MINLEN + icmp_payload_len;
    make_ip_header(ip_header, IPPROTO_ICMP, ip_len);

    struct icmp *icmp_header = (struct icmp *) (&ip_header[1]);
    make_icmp_header(icmp_header);

    char *payload = (char *) icmp_header + ICMP_MINLEN;
    memcpy(payload, icmp_payload, icmp_payload_len);

    return EXIT_SUCCESS;
}

static int icmp_echo_make_packet(void *buf, UNUSED size_t *buf_len,
                                 ipaddr_n_t *src_ip, ipaddr_n_t *dst_ip,
                                 UNUSED port_h_t dst_port, uint8_t ttl,
                                 UNUSED int probe_num, UNUSED void *arg) {
    struct ether_header *eth_header  = (struct ether_header *) buf;
    struct ip *          ip_header   = (struct ip *) (&eth_header[1]);
    struct icmp *        icmp_header = (struct icmp *) (&ip_header[1]);

    uint8_t validation[VALIDATE_BYTES];
    validate_gen(src_ip, dst_ip, 0, validation);

    uint16_t icmp_idnum  = icmp_get_idnum(validation);
    uint16_t icmp_seqnum = icmp_get_seqnum(validation);

    ip_header->ip_src.s_addr = *(uint32_t *) src_ip;
    ip_header->ip_dst.s_addr = *(uint32_t *) dst_ip;
    ip_header->ip_ttl        = ttl;

    icmp_header->icmp_id  = icmp_idnum;
    icmp_header->icmp_seq = icmp_seqnum;

    icmp_header->icmp_cksum = 0;
    icmp_header->icmp_cksum = icmp_checksum(icmp_header, icmp_payload_len);

    ip_header->ip_sum = 0;
    ip_header->ip_sum = ip_checksum_((unsigned short *) ip_header);

    return EXIT_SUCCESS;
}

static void icmp_echo_print_packet(FILE *fp, void *packet) {
    struct ether_header *eth_header  = (struct ether_header *) packet;
    struct ip *          ip_header   = (struct ip *) &eth_header[1];
    struct icmp *        icmp_header = (struct icmp *) (&ip_header[1]);

    fprintf_eth_header(fp, eth_header);
    fprintf_ip_header(fp, ip_header);
    fprintf(fp,
            "ICMP\n"
            "\tType(1B)\t\t: %u\n"
            "\tCode(1B)\t\t: %u\n"
            "\tChecksum(2B)\t\t: 0x%04x\n"
            "\tIdentifier(2B)\t\t: n:%d (0x%04x) h:%d (0x%04x)\n"
            "\tSequence number(2B)\t: n:%d (0x%04x) h:%d (0x%04x)\n",
            icmp_header->icmp_type, icmp_header->icmp_code,
            icmp_header->icmp_cksum, icmp_header->icmp_id, icmp_header->icmp_id,
            ntohs(icmp_header->icmp_id), ntohs(icmp_header->icmp_id),
            icmp_header->icmp_seq, icmp_header->icmp_seq,
            ntohs(icmp_header->icmp_seq), ntohs(icmp_header->icmp_seq));
    fprintf(fp, "------------------------------------------------------\n");
}

static int icmp_echo_validate_packet(const struct ip *ip_hdr, uint32_t len,
                                     int *is_repeat) {
    if (ip_hdr->ip_p != IPPROTO_ICMP) {
        return 0;
    }
    // check if buffer is large enough to contain expected icmp header
    if (((uint32_t) 4 * ip_hdr->ip_hl + ICMP_SMALLEST_SIZE) > len) {
        return 0;
    }

    struct icmp *icmp_header =
        (struct icmp *) ((char *) ip_hdr + 4 * ip_hdr->ip_hl);
    uint16_t icmp_idnum  = icmp_header->icmp_id;
    uint16_t icmp_seqnum = icmp_header->icmp_seq;

    // ICMP validation is tricky: for some packet types, we must look inside
    // the payload
    uint8_t validation[VALIDATE_BYTES];
    if (icmp_header->icmp_type == ICMP_TIMXCEED ||
        icmp_header->icmp_type == ICMP_UNREACH ||
        icmp_header->icmp_type == ICMP_PARAMPROB) {

        // Should have 16B TimeExceeded/Dest_Unreachable header +
        // original IP header + 1st 8B of original ICMP frame
        if ((4 * ip_hdr->ip_hl + ICMP_TIMXCEED_UNREACH_HEADER_SIZE +
             sizeof(struct ip)) > len) {
            return 0;
        }

        struct ip *ip_inner_header =
            (struct ip *) ((char *) icmp_header +
                           ICMP_TIMXCEED_UNREACH_HEADER_SIZE);
        if (((uint32_t) 4 * ip_hdr->ip_hl + ICMP_TIMXCEED_UNREACH_HEADER_SIZE +
             4 * ip_inner_header->ip_hl + 8 /*1st 8 bytes of original*/) >
            len) {
            return 0;
        }

        struct icmp *icmp_inner_header =
            (struct icmp *) ((char *) ip_inner_header + 4 * ip_hdr->ip_hl);
        // Regenerate validation and icmp id based off inner payload
        icmp_idnum  = icmp_inner_header->icmp_id;
        icmp_seqnum = icmp_inner_header->icmp_seq;

        validate_gen((uint8_t *) &(ip_inner_header->ip_src.s_addr),
                     (uint8_t *) &(ip_inner_header->ip_dst.s_addr), 0,
                     validation);
    } else if (icmp_header->icmp_type == ICMP_ECHOREPLY) {
        validate_gen((uint8_t *) &(ip_hdr->ip_dst.s_addr),
                     (uint8_t *) &(ip_hdr->ip_src.s_addr), 0, validation);
    }

    // validate icmp id and seqnum
    if (icmp_idnum != icmp_get_idnum(validation)) {
        return 0;
    }
    if (icmp_seqnum != icmp_get_seqnum(validation)) {
        return 0;
    }

    // whether repeat: reply ip
    char ip_port_str[xconf.ipv46_bytes];
    memcpy(ip_port_str, (char *) &(ip_hdr->ip_src.s_addr), xconf.ipv46_bytes);
    if (bloom_filter_check_string(&xrecv.bf, (const char *) ip_port_str,
                                  xconf.ipv46_bytes) == BLOOM_FAILURE) {
        bloom_filter_add_string(&xrecv.bf, (const char *) ip_port_str,
                                xconf.ipv46_bytes);
        *is_repeat = 0;
    }

    return 1;
}

static void icmp_echo_process_packet(const u_char *packet, uint32_t len,
                                     fieldset_t *           fs,
                                     UNUSED struct timespec ts) {
    struct ip *  ip_header = (struct ip *) &packet[sizeof(struct ether_header)];
    struct icmp *icmp_header =
        (struct icmp *) ((char *) ip_header + 4 * ip_header->ip_hl);
    uint32_t hdrlen = sizeof(struct ether_header) + 4 * ip_header->ip_hl +
                      4; // after checksum

    if (icmp_header->icmp_type == ICMP_ECHOREPLY) {
        fs_add_uint64(fs, "success", 1);
        fs_add_string(fs, "clas", (char *) "echoreply", 0);
        fs_add_string(fs, "desc", (char *) "no code", 0);
    } else {
        // Use inner IP header values for unsuccessful ICMP replies
        struct ip *ip_inner_header =
            (struct ip *) ((char *) icmp_header +
                           ICMP_TIMXCEED_UNREACH_HEADER_SIZE);
        fs_modify_string(fs, "saddr",
                         make_ip_str(ip_inner_header->ip_dst.s_addr), 1);

        fs_add_bool(fs, "success", 0);
        fs_add_string(fs, "clas",
                      (char *) get_icmp_type_str(icmp_header->icmp_type), 0);
        fs_add_string(fs, "desc",
                      (char *) get_icmp_type_code_str(icmp_header->icmp_type,
                                                      icmp_header->icmp_code),
                      0);
    }

    fs_add_uint64(fs, "type", icmp_header->icmp_type);
    fs_add_uint64(fs, "code", icmp_header->icmp_code);
    fs_add_uint64(fs, "icmp_id", ntohs(icmp_header->icmp_id));
    fs_add_uint64(fs, "seq", ntohs(icmp_header->icmp_seq));
    fs_add_string(fs, "outersaddr", make_ip_str(ip_header->ip_src.s_addr), 1);

    int datalen = len - hdrlen;

    if (datalen > 0) {
        const uint8_t *data = (uint8_t *) &packet[hdrlen];
        fs_add_binary(fs, "data", (size_t) datalen, (void *) data, 0);
    } else {
        fs_add_null(fs, "data");
    }
}

static fielddef_t fields[] = {
    {.name = "success",
     .type = "bool",
     .desc = "did probe module classify response as success"},
    {.name = "clas",
     .type = "string",
     .desc = "packet classification (type str):\n"
             "\t\t\te.g., `echoreply', `other'\n"
             "\t\t\tuse `--probe-args=icmp-type-code-str' to list"},
    {.name = "desc",
     .type = "string",
     .desc = "ICMP message detail(code str):\n"
             "\t\t\tuse `--probe-args=icmp-type-code-str' to list"},
    {.name = "type", .type = "int", .desc = "ICMP message type"},
    {.name = "code", .type = "int", .desc = "ICMP message sub type code"},
    {.name = "icmp_id", .type = "int", .desc = "ICMP id number"},
    {.name = "seq", .type = "int", .desc = "ICMP sequence number"},
    {.name = "outersaddr",
     .type = "string",
     .desc = "outer src address of icmp reply packet"},
    {.name = "data", .type = "binary", .desc = "ICMP payload"}};

probe_module_t module_icmp_echo = {
    .ipv46_flag      = 4,
    .name            = "icmp_echo",
    .packet_length   = 14 + 20 + 8 + 8,
    .pcap_filter     = "icmp and icmp[0]!=8",
    .pcap_snaplen    = 14 + 2 * (20 + 8) + 8,
    .port_args       = 0,
    .global_init     = &icmp_echo_global_init,
    .close           = &icmp_echo_global_cleanup,
    .thread_init     = &icmp_echo_thread_init,
    .make_packet     = &icmp_echo_make_packet,
    .print_packet    = &icmp_echo_print_packet,
    .process_packet  = &icmp_echo_process_packet,
    .validate_packet = &icmp_echo_validate_packet,
    .output_type     = OUTPUT_TYPE_STATIC,
    .fields          = fields,
    .numfields       = sizeof(fields) / sizeof(fields[0]),
    .helptext        = "Probe module that sends ICMP echo requests to hosts.\n"
                "Payload of ICMP packets will consist of 8 bytes zero unless "
                "you customize it with:\n"
                "    --probe-args=file:/path_to_payload_file\n"
                "    --probe-args=text:SomeText\n"
                "    --probe-args=hex:5061796c6f6164\n"
                "    --probe-args=icmp-type-code-str",
};
