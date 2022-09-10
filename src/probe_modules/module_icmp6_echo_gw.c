/*
 * XMap Copyright 2021 Xiang Li from Network and Information Security Lab
 * Tsinghua University
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

// probe module for performing ICMPv6 echo request (ping) scans for gateway
// discovery

#include "module_icmp6.h"

probe_module_t module_icmp6_echo_gw;

static const char *icmp6_usage_error =
    "unknown ICMPv6 probe specification (expected file:/path or text:STRING or "
    "hex:01020304 or icmpv6-type-code-str)";

static size_t       icmp6_payload_len         = 0;
static const size_t icmp6_payload_default_len = 8;
static char        *icmp6_payload             = NULL;

static int icmp6_echo_gw_global_init(struct state_conf *conf) {
    if (!(conf->probe_args && strlen(conf->probe_args) > 0)) {
        icmp6_payload     = xmalloc(icmp6_payload_default_len);
        icmp6_payload_len = icmp6_payload_default_len;
        return EXIT_SUCCESS;
    }

    if (strcmp(conf->probe_args, "icmp-type-code-str") == 0) {
        print_icmp6_type_code_str();
        exit(EXIT_SUCCESS);
    }

    char *c = strchr(conf->probe_args, ':');
    if (!c) {
        log_error("icmp6", icmp6_usage_error);
        return EXIT_FAILURE;
    }
    ++c;

    if (strncmp(conf->probe_args, "text", 4) == 0) {
        icmp6_payload     = strdup(c);
        icmp6_payload_len = strlen(icmp6_payload);
    } else if (strncmp(conf->probe_args, "file", 4) == 0) {
        FILE *inp = fopen(c, "rb");
        if (!inp) {
            log_error("icmp6", "could not open ICMPv6 data file '%s'", c);
            free(icmp6_payload);
            return EXIT_FAILURE;
        }
        if (fseek(inp, 0, SEEK_END)) {
            log_error("icmp6", "unable to get size of ICMPv6 data file '%s'",
                      c);
            free(icmp6_payload);
            return EXIT_FAILURE;
        }
        size_t input_size = ftell(inp);
        if (input_size > ICMP6_MAX_PAYLOAD_LEN) {
            log_error(
                "icmp6",
                "input file larger than %d bytes and will not fit on the wire "
                "(%llu bytes provided)",
                ICMP6_MAX_PAYLOAD_LEN, input_size);
            free(icmp6_payload);
            return EXIT_FAILURE;
        }
        if (fseek(inp, 0, SEEK_SET)) {
            log_error("icmp6", "unable to read ICMPv6 data file '%s'", c);
            free(icmp6_payload);
            return EXIT_FAILURE;
        }
        icmp6_payload     = xmalloc(ICMP6_MAX_PAYLOAD_LEN);
        icmp6_payload_len = fread(icmp6_payload, 1, ICMP6_MAX_PAYLOAD_LEN, inp);
        fclose(inp);
    } else if (strncmp(conf->probe_args, "hex", 3) == 0) {
        if (strlen(c) % 2 != 0) {
            log_error("icmp6",
                      "invalid hex input (length must be a multiple of 2)");
            free(icmp6_payload);
            return EXIT_FAILURE;
        }
        icmp6_payload_len = strlen(c) / 2;
        icmp6_payload     = xmalloc(icmp6_payload_len);

        unsigned int n;
        for (size_t i = 0; i < icmp6_payload_len; i++) {
            if (sscanf(c + (i * 2), "%2x", &n) != 1) {
                log_error("icmp6", "non-hex character: '%c'", c[i * 2]);
                free(icmp6_payload);
                return EXIT_FAILURE;
            }
            icmp6_payload[i] = (char) (n & 0xff);
        }
    } else {
        log_error("icmp6", icmp6_usage_error);
        free(icmp6_payload);
        return EXIT_FAILURE;
    }

    if (icmp6_payload_len > ICMP6_MAX_PAYLOAD_LEN) {
        log_error("icmp6",
                  "reducing ICMPv6 payload must be at most %d bytes to fit on "
                  "the wire (%d were provided)\n",
                  ICMP6_MAX_PAYLOAD_LEN, icmp6_payload_len);
        free(icmp6_payload);
        return EXIT_FAILURE;
    }

    module_icmp6_echo_gw.packet_length = sizeof(struct ether_header) +
                                         sizeof(struct ip6_hdr) + ICMP6_MINLEN +
                                         icmp6_payload_len;
    assert(module_icmp6_echo_gw.packet_length <=
           1500 + sizeof(struct ether_header));
    module_icmp6_echo_gw.pcap_snaplen =
        sizeof(struct ether_header) +
        2 * (sizeof(struct ip6_hdr) + ICMP6_MINLEN) + icmp6_payload_len;

    return EXIT_SUCCESS;
}

static int icmp6_echo_gw_global_cleanup(UNUSED struct state_conf *xconf,
                                        UNUSED struct state_send *xsend,
                                        UNUSED struct state_recv *xrecv) {
    if (icmp6_payload) {
        free(icmp6_payload);
        icmp6_payload = NULL;
    }

    return EXIT_SUCCESS;
}

static int icmp6_echo_gw_thread_init(void *buf, macaddr_t *src, macaddr_t *gw,
                                     UNUSED void **arg_ptr) {
    memset(buf, 0, MAX_PACKET_SIZE);

    struct ether_header *eth_header = (struct ether_header *) buf;
    make_eth6_header(eth_header, src, gw);

    struct ip6_hdr *ip6_header  = (struct ip6_hdr *) (&eth_header[1]);
    uint16_t        payload_len = sizeof(struct icmp6_hdr) + icmp6_payload_len;
    make_ip6_header(ip6_header, IPPROTO_ICMPV6, payload_len);

    struct icmp6_hdr *icmp6_header = (struct icmp6_hdr *) (&ip6_header[1]);
    make_icmp6_header(icmp6_header);

    char *payload = (char *) icmp6_header + ICMP6_MINLEN;
    memcpy(payload, icmp6_payload, icmp6_payload_len);

    return EXIT_SUCCESS;
}

static int icmp6_echo_gw_make_packet(void *buf, UNUSED size_t *buf_len,
                                     ipaddr_n_t *src_ip, ipaddr_n_t *dst_ip,
                                     UNUSED port_h_t dst_port, uint8_t ttl,
                                     UNUSED int       probe_num,
                                     UNUSED index_h_t index, UNUSED void *arg) {
    struct ether_header *eth_header   = (struct ether_header *) buf;
    struct ip6_hdr      *ip6_header   = (struct ip6_hdr *) (&eth_header[1]);
    struct icmp6_hdr    *icmp6_header = (struct icmp6_hdr *) (&ip6_header[1]);

    uint8_t validation[VALIDATE_BYTES];
    validate_gen(src_ip, dst_ip, 0, validation);

    uint16_t icmp6_idnum  = get_icmp_idnum(validation);
    uint16_t icmp6_seqnum = get_icmp_seqnum(validation);

    uint8_t *ip6_src = (uint8_t *) &(ip6_header->ip6_src);
    uint8_t *ip6_dst = (uint8_t *) &(ip6_header->ip6_dst);
    for (int i = 0; i < 16; i++) {
        ip6_src[i] = src_ip[i];
        ip6_dst[i] = dst_ip[i];
    }
    ip6_header->ip6_hlim = ttl;

    icmp6_header->icmp6_id  = icmp6_idnum;
    icmp6_header->icmp6_seq = icmp6_seqnum;

    icmp6_header->icmp6_cksum = 0;
    icmp6_header->icmp6_cksum =
        (uint16_t) icmp6_checksum((struct in6_addr *) &(ip6_header->ip6_src),
                                  (struct in6_addr *) &(ip6_header->ip6_dst),
                                  icmp6_header, icmp6_payload_len);

    return EXIT_SUCCESS;
}

static void icmp6_echo_gw_print_packet(FILE *fp, void *packet) {
    struct ether_header *eth_header   = (struct ether_header *) packet;
    struct ip6_hdr      *ip6_header   = (struct ip6_hdr *) &eth_header[1];
    struct icmp6_hdr    *icmp6_header = (struct icmp6_hdr *) (&ip6_header[1]);

    fprintf_eth_header(fp, eth_header);
    fprintf_ip6_header(fp, ip6_header);
    fprintf(fp,
            "ICMPv6\n"
            "\tType(1B)\t\t: %u\n"
            "\tCode(1B)\t\t: %u\n"
            "\tChecksum(2B)\t\t: 0x%04x\n"
            "\tIdentifier(2B)\t\t: n:%d (0x%04x) h:%d (0x%04x)\n"
            "\tSequence number(2B)\t: n:%d (0x%04x) h:%d (0x%04x)\n",
            icmp6_header->icmp6_type, icmp6_header->icmp6_code,
            icmp6_header->icmp6_cksum, icmp6_header->icmp6_id,
            icmp6_header->icmp6_id, ntohs(icmp6_header->icmp6_id),
            ntohs(icmp6_header->icmp6_id), icmp6_header->icmp6_seq,
            icmp6_header->icmp6_seq, ntohs(icmp6_header->icmp6_seq),
            ntohs(icmp6_header->icmp6_seq));
    fprintf(fp, "------------------------------------------------------\n");
}

static int icmp6_echo_gw_validate_packet(const struct ip *ip_hdr, uint32_t len,
                                         UNUSED int    *is_repeat,
                                         UNUSED void   *buf,
                                         UNUSED size_t *buf_len,
                                         UNUSED uint8_t ttl) {
    struct ip6_hdr *ip6_header = (struct ip6_hdr *) ip_hdr;

    if (ip6_header->ip6_nxt != IPPROTO_ICMPV6) {
        return 0;
    }
    // IPv6 header is fixed length at 40 bytes + ICMPv6 header
    if ((sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) +
         icmp6_payload_len) > len) {
        // buffer not large enough to contain expected icmp header
        return 0;
    }

    // ICMPv6 header
    struct icmp6_hdr *icmp6_header = (struct icmp6_hdr *) (&ip6_header[1]);
    uint16_t          icmp6_idnum  = icmp6_header->icmp6_id;
    uint16_t          icmp6_seqnum = icmp6_header->icmp6_seq;

    // ICMPv6 validation is tricky: for some packet types, we must look inside
    // the payload
    uint8_t validation[VALIDATE_BYTES];
    if (icmp6_header->icmp6_type == ICMP6_TIME_EXCEEDED ||
        icmp6_header->icmp6_type == ICMP6_DST_UNREACH ||
        icmp6_header->icmp6_type == ICMP6_PACKET_TOO_BIG ||
        icmp6_header->icmp6_type == ICMP6_PARAM_PROB) {

        // IPv6 + ICMP6 headers + inner headers + payload (validation)
        if (2 * sizeof(struct ip6_hdr) + 2 * sizeof(struct icmp6_hdr) +
                icmp6_payload_len >
            len) {
            return 0;
        }

        // Use inner headers for validation
        struct ip6_hdr *ip6_inner_header = (struct ip6_hdr *) &icmp6_header[1];
        struct icmp6_hdr *icmp6_inner_header =
            (struct icmp6_hdr *) &ip6_inner_header[1];

        // Regenerate validation and icmpv6 id based off inner payload
        icmp6_idnum  = icmp6_inner_header->icmp6_id;
        icmp6_seqnum = icmp6_inner_header->icmp6_seq;

        // Send original src and dst IP as data in ICMPv6 payload and regenerate
        // the validation here
        validate_gen((const uint8_t *) &(ip6_inner_header->ip6_src),
                     (const uint8_t *) &(ip6_inner_header->ip6_dst), 0,
                     validation);
    } else if (icmp6_header->icmp6_type == ICMP6_ECHO_REPLY) {
        validate_gen((const uint8_t *) &(ip6_header->ip6_dst),
                     (const uint8_t *) &(ip6_header->ip6_src), 0, validation);
    }

    // validate icmp id and seqnum
    if (icmp6_idnum != get_icmp_idnum(validation)) {
        return 0;
    }
    if (icmp6_seqnum != get_icmp_seqnum(validation)) {
        return 0;
    }

    // whether repeat: reply ip
    char ip_port_str[xconf.ipv46_bytes];
    memcpy(ip_port_str, (char *) &(ip6_header->ip6_src), xconf.ipv46_bytes);
    if (bloom_filter_check_string(&xrecv.bf, (const char *) ip_port_str,
                                  xconf.ipv46_bytes) == BLOOM_FAILURE) {
        bloom_filter_add_string(&xrecv.bf, (const char *) ip_port_str,
                                xconf.ipv46_bytes);
        *is_repeat = 0;
    }

    return 1;
}

static void icmp6_echo_gw_process_packet(const u_char *packet, uint32_t len,
                                         fieldset_t            *fs,
                                         UNUSED struct timespec ts) {
    struct ip6_hdr *ip6_header =
        (struct ip6_hdr *) &packet[sizeof(struct ether_header)];
    struct icmp6_hdr *icmp6_header = (struct icmp6_hdr *) (&ip6_header[1]);
    uint32_t hdrlen = sizeof(struct ether_header) + sizeof(struct ip6_hdr) +
                      4; // after checksum

    if (icmp6_header->icmp6_type == ICMP6_ECHO_REPLY) {
        fs_add_uint64(fs, "success", 0);
        fs_add_string(fs, "clas", (char *) "echoreply", 0);
        fs_add_string(fs, "desc", (char *) "no code", 0);
    } else {
        // Use inner IPv6 header values for unsuccessful ICMPv6 replies
        struct ip6_hdr *ip6_inner_header = (struct ip6_hdr *) &icmp6_header[1];
        fs_modify_string(
            fs, "saddr",
            make_ipv6_str((struct in6_addr *) &(ip6_inner_header->ip6_dst)), 1);

        fs_add_uint64(fs, "success", 1);
        fs_add_string(fs, "clas",
                      (char *) get_icmp6_type_str(icmp6_header->icmp6_type), 0);
        fs_add_string(fs, "desc",
                      (char *) get_icmp6_type_code_str(
                          icmp6_header->icmp6_type, icmp6_header->icmp6_code),
                      0);
    }

    fs_add_uint64(fs, "type", icmp6_header->icmp6_type);
    fs_add_uint64(fs, "code", icmp6_header->icmp6_code);
    fs_add_uint64(fs, "icmp_id", ntohs(icmp6_header->icmp6_id));
    fs_add_uint64(fs, "seq", ntohs(icmp6_header->icmp6_seq));
    fs_add_string(fs, "outersaddr",
                  make_ipv6_str((struct in6_addr *) &(ip6_header->ip6_src)), 1);

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
     .type = "int",
     .desc = "did probe module classify response as a reply not from target "
             "itself"},
    {.name = "clas",
     .type = "string",
     .desc = "packet classification(type str):\n"
             "\t\t\te.g., `echoreply', `other'\n"
             "\t\t\tuse `--probe-args=icmp-type-code-str' to list"},
    {.name = "desc",
     .type = "string",
     .desc = "ICMPv6 message detail(code str):\n"
             "\t\t\tuse `--probe-args=icmp-type-code-str' to list"},
    {.name = "type", .type = "int", .desc = "ICMPv6 message type"},
    {.name = "code", .type = "int", .desc = "ICMPv6 message sub type code"},
    {.name = "icmp_id", .type = "int", .desc = "ICMPv6 id number"},
    {.name = "seq", .type = "int", .desc = "ICMPv6 sequence number"},
    {.name = "outersaddr",
     .type = "string",
     .desc = "outer src address of ICMPv6 reply packet"},
    {.name = "data", .type = "binary", .desc = "ICMPv6 payload"},
};

probe_module_t module_icmp6_echo_gw = {
    .ipv46_flag    = 6,
    .name          = "icmp_echo_gw",
    .packet_length = 14 + 40 + 8 + 8,
    .pcap_filter   = "icmp6 && (ip6[40] == 129 || ip6[40] == 3 || ip6[40] == 1 "
                     "|| ip6[40] == 2 || ip6[40] == 4)",
    .pcap_snaplen  = 14 + 2 * (40 + 8) + 8,
    .port_args     = 0,
    .global_init   = &icmp6_echo_gw_global_init,
    .close         = &icmp6_echo_gw_global_cleanup,
    .thread_init   = &icmp6_echo_gw_thread_init,
    .make_packet   = &icmp6_echo_gw_make_packet,
    .print_packet  = &icmp6_echo_gw_print_packet,
    .process_packet  = &icmp6_echo_gw_process_packet,
    .validate_packet = &icmp6_echo_gw_validate_packet,
    .output_type     = OUTPUT_TYPE_STATIC,
    .fields          = fields,
    .numfields       = sizeof(fields) / sizeof(fields[0]),
    .helptext = "Probe module that sends ICMPv6 echo requests to hosts for "
                "discovering gateway.\n"
                "And the following argus should be set:\n"
                "    --iid-module=low_fill\n"
                "Payload of ICMPv6 packets will consist of 8 bytes zero unless "
                "you customize it with:\n"
                "    --probe-args=file:/path_to_payload_file\n"
                "    --probe-args=text:SomeText\n"
                "    --probe-args=hex:5061796c6f6164\n"
                "    --probe-args=icmp-type-code-str",
};
