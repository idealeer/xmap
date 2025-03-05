/*
 * XMap Copyright 2021 Xiang Li from Network and Information Security Lab
 * Tsinghua University
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

/* Module for scanning for open UDP DNS resolvers.
 *
 * This module optionally takes in an argument of the form:
 * LABEL_TYPE:RECURSE:INPUT_SRC:TYPE,QUESTION, e.g., raw:recurse:text:A,qq.com,
 * str:www:recurse:text:A,qq.com;AAAA,qq.com, random:recurse:file:file_name
 *      LABEL_TYPE: raw, str, time, random, dst-ip
 *      RECURSE: recurse, no-recurse
 *      INPUT_SRC: text, file
 *      TYPE: A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, RRSIG, ANY, SIG, SRV,
 *            DS, DNSKEY, TLSA, SVCB, HTTPS, CAA, and HTTPSSVC
 *      file: TYPE,QUESTION;TYPE,QUESTION in each line
 *
 * Given no arguments it will default to asking for an A record for
 * www.qq.com.
 *
 * This module does minimal answer verification. It only verifies that the
 * response roughly looks like a DNS response. It will not, for example,
 * require the QR bit be set to 1. All such analysis should happen offline.
 * Specifically, to be included in the output it requires:
 * And it is marked as success.
 * - That the ports match and the packet is complete.
 * - That the ID field matches.
 * To be marked as app_success it also requires:
 * - That the QR bit be 1 and rcode == 0.
 *
 * Usage: xmap -p 53 --probe-module=dnsaecsv --probe-args="raw:text:A,qq.com"
 *			-O json --output-fields=* 8.8.8.8
 *
 * We also support multiple questions, of the form:
 * "A,example.com;AAAA,www.example.com" This requires --target-index=X, where X
 * matches the number of questions in --probe-args, and --output-filter="" to
 * remove the implicit "filter_duplicates" configuration flag.
 *
 * Based on a deprecated udp_dns module.
 */

#include <assert.h>
#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../lib/blocklist.h"
#include "../../lib/includes.h"
#include "../../lib/xalloc.h"
#include "../aesrand.h"
#include "../fieldset.h"
#include "logger.h"
#include "module_udp.h"
#include "packet.h"
#include "packet_icmp.h"
#include "probe_modules.h"
#include "utility.h"
#include "validate.h"

#include "module_dns.h"

#define DNS_SEND_LEN 512 // This is arbitrary
#define UDP_HEADER_LEN 8
#define PCAP_SNAPLEN 1500 // This is even more arbitrary
#define UNUSED __attribute__((unused))
#define MAX_QTYPE 65535
#define ICMP_UNREACH_HEADER_SIZE 8
#define BAD_QTYPE_STR "BAD QTYPE"
#define BAD_QTYPE_VAL -1
#define MAX_LABEL_RECURSION 10
#define DNS_QR_ANSWER 1

// Note: each label has a max length of 63 bytes. So someone has to be doing
// something really annoying. Will raise a warning.
// THIS INCLUDES THE NULL BYTE
#define MAX_NAME_LENGTH 512

#if defined(__NetBSD__) && !defined(__cplusplus) && defined(bool)
#undef bool
#endif

typedef uint8_t bool;

// xmap boilerplate
probe_module_t module_dnsaecsv;
static int     dns_num_ports_aecsv;

const char     default_domain_aecsv[] = "www.qq.com";
const uint16_t default_qtype_aecsv    = DNS_QTYPE_A;
const char    *dnsaecsv_usage_error =
    "unknown DNS probe specification (expected "
    "raw/time/random:recurse/no-recurse:text:TYPE,QUESTION or "
    "raw/time/random:recurse/no-recurse:file:file_name or "
    "str:some_text:recurse/no-recurse:text:TYPE,QUESTION or "
    "str:some_text:recurse/no-recurse:file:file_name)";

const unsigned char *charset_alpha_lower_aecsv =
    (unsigned char *) "abcdefghijklmnopqrstuvwxyz";

static char    **dns_packets_aecsv;
static uint16_t *dns_packet_lens_aecsv; // Not including udp header
static uint16_t *qname_lens_aecsv;      // domain_len list
static char    **qnames_aecsv;          // domain list for query
static uint16_t *qtypes_aecsv;          // query_type list
static char    **domains_aecsv;         // domain strs
static int       num_questions_aecsv   = 0;
static int       index_questions_aecsv = 0;

const char      default_option_qname_aecsv[]   = {0x00};
static int      default_option_qname_len_aecsv = 1;
static uint16_t default_option_udpsize_aecsv   = 4096;
const char      default_option_rdata_aecsv[];
static int      default_option_rdata_len_aecsv = 11; // for ipv4/24/0

/* Array of qtypes_aecsv we support. Jumping through some hops (1 level of
 * indirection) so the per-packet processing time is fast. Keep this in sync
 * with: dns_qtype (.h) qtype_strid_to_qtype_aecsv (below)
 * qtype_qtype_to_strid_aecsv (below, and setup_qtype_str_map_aecsv())
 */
const char *qtype_strs_aecsv[]   = {"A",    "NS",    "CNAME", "SOA",      "PTR",
                                    "MX",   "TXT",   "AAAA",  "RRSIG",    "ANY",
                                    "SIG",  "SRV",   "DS",    "DNSKEY",   "TLSA",
                                    "SVCB", "HTTPS", "CAA",   "HTTPSSVC", "OPT"};
const int   qtype_strs_len_aecsv = 20;

const dns_qtype qtype_strid_to_qtype_aecsv[] = {
    DNS_QTYPE_A,     DNS_QTYPE_NS,     DNS_QTYPE_CNAME,    DNS_QTYPE_SOA,
    DNS_QTYPE_PTR,   DNS_QTYPE_MX,     DNS_QTYPE_TXT,      DNS_QTYPE_AAAA,
    DNS_QTYPE_RRSIG, DNS_QTYPE_ALL,    DNS_QTYPE_SIG,      DNS_QTYPE_SRV,
    DNS_QTYPE_DS,    DNS_QTYPE_DNSKEY, DNS_QTYPE_TLSA,     DNS_QTYPE_SVCB,
    DNS_QTYPE_HTTPS, DNS_QTYPE_CAA,    DNS_QTYPE_HTTPSSVC, DNS_QTYPE_OPT};

int8_t qtype_qtype_to_strid_aecsv[65536] = {BAD_QTYPE_VAL};

void setup_qtype_str_map_aecsv() {
    qtype_qtype_to_strid_aecsv[DNS_QTYPE_A]        = 0;
    qtype_qtype_to_strid_aecsv[DNS_QTYPE_NS]       = 1;
    qtype_qtype_to_strid_aecsv[DNS_QTYPE_CNAME]    = 2;
    qtype_qtype_to_strid_aecsv[DNS_QTYPE_SOA]      = 3;
    qtype_qtype_to_strid_aecsv[DNS_QTYPE_PTR]      = 4;
    qtype_qtype_to_strid_aecsv[DNS_QTYPE_MX]       = 5;
    qtype_qtype_to_strid_aecsv[DNS_QTYPE_TXT]      = 6;
    qtype_qtype_to_strid_aecsv[DNS_QTYPE_AAAA]     = 7;
    qtype_qtype_to_strid_aecsv[DNS_QTYPE_RRSIG]    = 8;
    qtype_qtype_to_strid_aecsv[DNS_QTYPE_ALL]      = 9;
    qtype_qtype_to_strid_aecsv[DNS_QTYPE_SIG]      = 10;
    qtype_qtype_to_strid_aecsv[DNS_QTYPE_SRV]      = 11;
    qtype_qtype_to_strid_aecsv[DNS_QTYPE_DS]       = 12;
    qtype_qtype_to_strid_aecsv[DNS_QTYPE_DNSKEY]   = 13;
    qtype_qtype_to_strid_aecsv[DNS_QTYPE_TLSA]     = 14;
    qtype_qtype_to_strid_aecsv[DNS_QTYPE_SVCB]     = 15;
    qtype_qtype_to_strid_aecsv[DNS_QTYPE_HTTPS]    = 16;
    qtype_qtype_to_strid_aecsv[DNS_QTYPE_CAA]      = 17;
    qtype_qtype_to_strid_aecsv[DNS_QTYPE_HTTPSSVC] = 18;
    qtype_qtype_to_strid_aecsv[DNS_QTYPE_OPT]      = 19;
}

static uint16_t qtype_str_to_code_aecsv(const char *str) {
    for (int i = 0; i < qtype_strs_len_aecsv; i++) {
        if (strcmp(qtype_strs_aecsv[i], str) == 0)
            return qtype_strid_to_qtype_aecsv[i];
    }

    return 0;
}

static char    *label_aecsv      = NULL;
static uint16_t label_len_aecsv  = 0;
static uint16_t label_type_aecsv = DNS_LTYPE_RAW;
static uint16_t recursive_aecsv  = 1;

static uint16_t domain_to_qname_aecsv(char **qname_handle, const char *domain) {
    if (domain[0] == '.') {
        char *qname   = xmalloc(1);
        qname[0]      = 0x00;
        *qname_handle = qname;
        return 1;
    }

    // String + 1byte header + null byte
    uint16_t len   = strlen(domain) + 1 + 1;
    char    *qname = xmalloc(len);
    // Add a . before the domain. This will make the following simpler.
    qname[0] = '.';
    // Move the domain into the qname buffer.
    strcpy(qname + 1, domain);

    for (int i = 0; i < len; i++) {
        if (qname[i] == '.') {
            int j;
            for (j = i + 1; j < (len - 1); j++) {
                if (qname[j] == '.') {
                    break;
                }
            }
            qname[i] = j - i - 1;
        }
    }
    *qname_handle = qname;
    assert((*qname_handle)[len - 1] == '\0');

    return len;
}

static int build_global_dns_packets_aecsv(char **domains, int num_domains) {
    for (int i = 0; i < num_domains; i++) {
        qname_lens_aecsv[i] =
            domain_to_qname_aecsv(&qnames_aecsv[i], domains[i]);
        if (domains[i] != (char *) default_domain_aecsv) {
            free(domains[i]);
        }
        dns_packet_lens_aecsv[i] =
            sizeof(dns_header) + qname_lens_aecsv[i] +
            sizeof(dns_question_tail) + default_option_qname_len_aecsv +
            sizeof(dns_option_tail) + default_option_rdata_len_aecsv;
        if (dns_packet_lens_aecsv[i] > DNS_SEND_LEN) {
            log_fatal("dnsaecsv", "DNS packet bigger (%d) than our limit (%d)",
                      dns_packet_lens_aecsv[i], DNS_SEND_LEN);
            return EXIT_FAILURE;
        }

        dns_packets_aecsv[i]            = xmalloc(dns_packet_lens_aecsv[i]);
        dns_header        *dns_header_p = (dns_header *) dns_packets_aecsv[i];
        char              *qname_p = dns_packets_aecsv[i] + sizeof(dns_header);
        dns_question_tail *tail_p =
            (dns_question_tail *) (dns_packets_aecsv[i] + sizeof(dns_header) +
                                   qname_lens_aecsv[i]);
        char *option_qname_p =
            (char *) (dns_packets_aecsv[i] + sizeof(dns_header) +
                      qname_lens_aecsv[i] + sizeof(dns_question_tail));
        dns_option_tail *option_tail_p =
            (dns_option_tail *) (dns_packets_aecsv[i] + sizeof(dns_header) +
                                 qname_lens_aecsv[i] +
                                 sizeof(dns_question_tail) +
                                 default_option_qname_len_aecsv);
        dns_option_ecs *option_ecs_p =
            (dns_option_ecs *) (dns_packets_aecsv[i] + sizeof(dns_header) +
                                qname_lens_aecsv[i] +
                                sizeof(dns_question_tail) +
                                default_option_qname_len_aecsv +
                                sizeof(dns_option_tail));

        // All other header fields should be 0. Except id, which we set
        // per thread. Please recurse as needed.
        dns_header_p->rd = recursive_aecsv; // Is one bit. Don't need htons
        // We have 1 question
        dns_header_p->qdcount = htons(1);
        memcpy(qname_p, qnames_aecsv[i], qname_lens_aecsv[i]);
        // Set the qtype to what we passed from args
        tail_p->qtype = htons(qtypes_aecsv[i]);
        // Set the qclass to The Internet (TM) (R) (I hope you're happy
        // now Zakir)
        tail_p->qclass = htons(0x01);
        // MAGIC NUMBER. Let's be honest. This is only ever 1

        // option, others set to 0
        dns_header_p->arcount = htons(1);
        memcpy(option_qname_p, default_option_qname_aecsv,
               default_option_qname_len_aecsv);
        option_tail_p->type    = htons(DNS_QTYPE_OPT);
        option_tail_p->udpsize = htons(default_option_udpsize_aecsv);
        option_tail_p->dlength = htons(default_option_rdata_len_aecsv);

        // ecs
        option_ecs_p->optcode    = htons(DNS_OPTCODE_ECS);   // 8
        option_ecs_p->optlength  = htons(7);                 // fixed for /24
        option_ecs_p->family     = htons(DNS_ADDRFAMILY_IP); // IPv4
        option_ecs_p->srcnmask   = 24;                       // source netmask
        option_ecs_p->scpnmask   = 0;                        // scope netmask
        uint8_t client_subnet[3] = {
            202, // first byte
            0,   // second byte
            0    // third byte
        };
        memcpy(option_ecs_p->cs, client_subnet, 3);
    }

    return EXIT_SUCCESS;
}

static uint16_t get_name_helper_aecsv(const char *data, uint16_t data_len,
                                      const char *payload, uint16_t payload_len,
                                      char *name, uint16_t name_len,
                                      uint16_t recursion_level) {
    log_trace("dnsaecsv",
              "_get_name_helper IN, datalen: %d namelen: %d recusion: %d",
              data_len, name_len, recursion_level);
    if (data_len == 0 || name_len == 0 || payload_len == 0) {
        log_trace("dnsaecsv",
                  "_get_name_helper OUT, err. 0 length field. datalen %d "
                  "namelen %d payloadlen %d",
                  data_len, name_len, payload_len);
        return 0;
    }
    if (recursion_level > MAX_LABEL_RECURSION) {
        log_trace("dnsaecsv", "_get_name_helper OUT. ERR, MAX RECUSION");
        return 0;
    }

    uint16_t bytes_consumed = 0;
    // The start of data is either a sequence of labels or a ptr.
    while (data_len > 0) {
        uint8_t byte = data[0];
        // Is this a pointer?
        if (byte >= 0xc0) {
            log_trace("dnsaecsv", "_get_name_helper, ptr encountered");
            // Do we have enough bytes to check ahead?
            if (data_len < 2) {
                log_trace("dnsaecsv",
                          "_get_name_helper OUT. ptr byte encountered. "
                          "No offset. ERR.");
                return 0;
            }
            // No. ntohs isn't needed here. It's because of
            // the upper 2 bits indicating a pointer.
            uint16_t offset = ((byte & 0x03) << 8) | (uint8_t) data[1];
            log_trace("dnsaecsv", "_get_name_helper. ptr offset 0x%x", offset);
            if (offset >= payload_len) {
                log_trace(
                    "dnsaecsv",
                    "_get_name_helper OUT. offset exceeded payload len %d ERR",
                    payload_len);
                return 0;
            }

            // We need to add a dot if we are:
            // -- Not first level recursion.
            // -- have consumed bytes
            if (recursion_level > 0 || bytes_consumed > 0) {

                if (name_len < 1) {
                    log_warn("dnsaecsv",
                             "Exceeded static name field allocation.");
                    return 0;
                }

                name[0] = '.';
                name++;
                name_len--;
            }

            uint16_t rec_bytes_consumed = get_name_helper_aecsv(
                payload + offset, payload_len - offset, payload, payload_len,
                name, name_len, recursion_level + 1);
            // We are done so don't bother to increment the
            // pointers.
            if (rec_bytes_consumed == 0) {
                log_trace("dnsaecsv",
                          "_get_name_helper OUT. rec level %d failed",
                          recursion_level);
                return 0;
            } else {
                bytes_consumed += 2;
                log_trace("dnsaecsv",
                          "_get_name_helper OUT. rec level %d success. %d rec "
                          "bytes consumed. %d bytes consumed.",
                          recursion_level, rec_bytes_consumed, bytes_consumed);
                return bytes_consumed;
            }
        } else if (byte == '\0') {
            // don't bother with pointer incrementation. We're done.
            bytes_consumed += 1;
            log_trace("dnsaecsv",
                      "_get_name_helper OUT. rec level %d success. %d bytes "
                      "consumed.",
                      recursion_level, bytes_consumed);
            return bytes_consumed;
        } else {
            log_trace("dnsaecsv", "_get_name_helper, segment 0x%hx encountered",
                      byte);
            // We've now consumed a byte.
            ++data;
            --data_len;
            // Mark byte consumed after we check for first
            // iteration. Do we have enough data left (must have
            // null byte too)?
            if ((byte + 1) > data_len) {
                log_trace("dnsaecsv",
                          "_get_name_helper OUT. ERR. Not enough data "
                          "for segment %hd");
                return 0;
            }
            // If we've consumed any bytes and are in a label, we're
            // in a label chain. We need to add a dot.
            if (bytes_consumed > 0) {

                if (name_len < 1) {
                    log_warn("dnsaecsv",
                             "Exceeded static name field allocation.");
                    return 0;
                }

                name[0] = '.';
                name++;
                name_len--;
            }
            // Now we've consumed a byte.
            ++bytes_consumed;
            // Did we run out of our arbitrary buffer?
            if (byte > name_len) {
                log_warn("dnsaecsv", "Exceeded static name field allocation.");
                return 0;
            }

            assert(data_len > 0);
            memcpy(name, data, byte);
            name += byte;
            name_len -= byte;
            data_len -= byte;
            data += byte;
            bytes_consumed += byte;
            // Handled in the byte+1 check above.
            assert(data_len > 0);
        }
    }
    // We should never get here.
    // For each byte we either have:
    // -- a ptr, which terminates
    // -- a null byte, which terminates
    // -- a segment length which either terminates or ensures we keep
    // looping
    assert(0);
    return 0;
}

// data: Where we are in the dns payload
// payload: the entire udp payload
static char *get_name_aecsv(const char *data, uint16_t data_len,
                            const char *payload, uint16_t payload_len,
                            uint16_t *bytes_consumed) {
    log_trace("dnsaecsv", "call to get_name_aecsv, data_len: %d", data_len);
    char *name      = xmalloc(MAX_NAME_LENGTH);
    *bytes_consumed = get_name_helper_aecsv(
        data, data_len, payload, payload_len, name, MAX_NAME_LENGTH - 1, 0);
    if (*bytes_consumed == 0) {
        free(name);
        return NULL;
    }
    // Our memset ensured null byte.
    assert(name[MAX_NAME_LENGTH - 1] == '\0');
    log_trace(
        "dnsaecsv",
        "return success from get_name_aecsv, bytes_consumed: %d, string: %s",
        *bytes_consumed, name);

    return name;
}

static bool process_response_question_aecsv(char **data, uint16_t *data_len,
                                            const char *payload,
                                            uint16_t    payload_len,
                                            fieldset_t *list) {
    // Payload is the start of the DNS packet, including header
    // data is handle to the start of this RR
    // data_len is a pointer to the how much total data we have to work
    // with. This is awful. I'm bad and should feel bad.
    uint16_t bytes_consumed = 0;
    char    *question_name =
        get_name_aecsv(*data, *data_len, payload, payload_len, &bytes_consumed);
    // Error.
    if (question_name == NULL) {
        return 1;
    }
    assert(bytes_consumed > 0);
    if ((bytes_consumed + sizeof(dns_question_tail)) > *data_len) {
        free(question_name);
        return 1;
    }

    dns_question_tail *tail   = (dns_question_tail *) (*data + bytes_consumed);
    uint16_t           qtype  = ntohs(tail->qtype);
    uint16_t           qclass = ntohs(tail->qclass);
    // Build our new question fieldset
    fieldset_t *qfs = fs_new_fieldset();
    fs_add_unsafe_string(qfs, "name", question_name, 1);
    fs_add_uint64(qfs, "qtype", qtype);

    if (qtype > MAX_QTYPE ||
        qtype_qtype_to_strid_aecsv[qtype] == BAD_QTYPE_VAL) {
        fs_add_string(qfs, "qtype_str", (char *) BAD_QTYPE_STR, 0);
    } else {
        // I've written worse things than this 3rd arg. But I want to be
        // fast.
        fs_add_string(
            qfs, "qtype_str",
            (char *) qtype_strs_aecsv[qtype_qtype_to_strid_aecsv[qtype]], 0);
    }

    fs_add_uint64(qfs, "qclass", qclass);
    // Now we're adding the new fs to the list.
    fs_add_fieldset(list, NULL, qfs);
    // Now update the pointers.
    *data     = *data + bytes_consumed + sizeof(dns_question_tail);
    *data_len = *data_len - bytes_consumed - sizeof(dns_question_tail);

    return 0;
}

static bool process_response_answer_aecsv(char **data, uint16_t *data_len,
                                          const char *payload,
                                          uint16_t    payload_len,
                                          fieldset_t *list) {
    log_trace("dnsaecsv", "call to process_response_answer_aecsv, data_len: %d",
              *data_len);
    // Payload is the start of the DNS packet, including header
    // data is handle to the start of this RR
    // data_len is a pointer to the how much total data we have to work
    // with. This is awful. I'm bad and should feel bad.
    uint16_t bytes_consumed = 0;
    char    *answer_name =
        get_name_aecsv(*data, *data_len, payload, payload_len, &bytes_consumed);
    // Error.
    if (answer_name == NULL) {
        return 1;
    }
    assert(bytes_consumed > 0);
    if ((bytes_consumed + sizeof(dns_answer_tail)) > *data_len) {
        free(answer_name);
        return 1;
    }

    dns_answer_tail *tail = (dns_answer_tail *) (*data + bytes_consumed);
    uint16_t         type = ntohs(tail->type);
    uint16_t class        = ntohs(tail->class);
    uint32_t ttl          = ntohl(tail->ttl);
    uint16_t rdlength     = ntohs(tail->rdlength);
    char    *rdata        = tail->rdata;

    if ((rdlength + bytes_consumed + sizeof(dns_answer_tail)) > *data_len) {
        free(answer_name);
        return 1;
    }
    // Build our new question fieldset
    fieldset_t *afs = fs_new_fieldset();
    fs_add_unsafe_string(afs, "name", answer_name, 1);
    fs_add_uint64(afs, "type", type);
    if (type > MAX_QTYPE || qtype_qtype_to_strid_aecsv[type] == BAD_QTYPE_VAL) {
        fs_add_string(afs, "type_str", (char *) BAD_QTYPE_STR, 0);
    } else {
        // I've written worse things than this 3rd arg. But I want to be
        // fast.
        fs_add_string(
            afs, "type_str",
            (char *) qtype_strs_aecsv[qtype_qtype_to_strid_aecsv[type]], 0);
    }
    if (type != DNS_QTYPE_OPT) {
        fs_add_uint64(afs, "class", class);
        fs_add_uint64(afs, "ttl", ttl);
        fs_add_uint64(afs, "rdlength", rdlength);
    }

    // XXX Fill this out for the other types we care about.
    if (type == DNS_QTYPE_NS || type == DNS_QTYPE_CNAME) {
        uint16_t rdata_bytes_consumed = 0;
        char *rdata_name = get_name_aecsv(rdata, rdlength, payload, payload_len,
                                          &rdata_bytes_consumed);
        if (rdata_name == NULL) {
            fs_add_uint64(afs, "rdata_is_parsed", 0);
            fs_add_binary(afs, "rdata", rdlength, rdata, 0);
        } else {
            fs_add_uint64(afs, "rdata_is_parsed", 1);
            fs_add_unsafe_string(afs, "rdata", rdata_name, 1);
        }
    } else if (type == DNS_QTYPE_MX) {
        uint16_t rdata_bytes_consumed = 0;
        if (rdlength <= 4) {
            fs_add_uint64(afs, "rdata_is_parsed", 0);
            fs_add_binary(afs, "rdata", rdlength, rdata, 0);
        } else {
            char *rdata_name =
                get_name_aecsv(rdata + 2, rdlength - 2, payload, payload_len,
                               &rdata_bytes_consumed);
            if (rdata_name == NULL) {
                fs_add_uint64(afs, "rdata_is_parsed", 0);
                fs_add_binary(afs, "rdata", rdlength, rdata, 0);
            } else {
                // (largest value 16bit) + " " + answer + null
                char *rdata_with_pref = xmalloc(5 + 1 + strlen(rdata_name) + 1);

                uint8_t num_printed = snprintf(rdata_with_pref, 6, "%hu ",
                                               ntohs(*(uint16_t *) rdata));
                memcpy(rdata_with_pref + num_printed, rdata_name,
                       strlen(rdata_name));
                fs_add_uint64(afs, "rdata_is_parsed", 1);
                fs_add_unsafe_string(afs, "rdata", rdata_with_pref, 1);
            }
        }
    } else if (type == DNS_QTYPE_TXT) {
        if (rdlength >= 1 && (rdlength - 1) != *(uint8_t *) rdata) {
            log_warn("dnsaecsv",
                     "TXT record with wrong TXT len. Not processing.");
            fs_add_uint64(afs, "rdata_is_parsed", 0);
            fs_add_binary(afs, "rdata", rdlength, rdata, 0);
        } else if (rdlength < 1) {
            fs_add_uint64(afs, "rdata_is_parsed", 0);
            fs_add_binary(afs, "rdata", rdlength, rdata, 0);
        } else {
            fs_add_uint64(afs, "rdata_is_parsed", 1);
            char *txt = xmalloc(rdlength);
            memcpy(txt, rdata + 1, rdlength - 1);
            fs_add_unsafe_string(afs, "rdata", txt, 1);
        }
    } else if (type == DNS_QTYPE_A) {
        if (rdlength != 4) {
            log_warn("dnsaecsv",
                     "A record with IP of length %d. Not processing.",
                     rdlength);
            fs_add_uint64(afs, "rdata_is_parsed", 0);
            fs_add_binary(afs, "rdata", rdlength, rdata, 0);
        } else {
            fs_add_uint64(afs, "rdata_is_parsed", 1);
            char *addr = strdup(inet_ntoa(*(struct in_addr *) rdata));
            fs_add_unsafe_string(afs, "rdata", addr, 1);
        }
    } else if (type == DNS_QTYPE_AAAA) {
        if (rdlength != 16) {
            log_warn("dnsaecsv",
                     "AAAA record with IP of length %d. Not processing.",
                     rdlength);
            fs_add_uint64(afs, "rdata_is_parsed", 0);
            fs_add_binary(afs, "rdata", rdlength, rdata, 0);
        } else {
            fs_add_uint64(afs, "rdata_is_parsed", 1);
            char *ipv6_str = xmalloc(INET6_ADDRSTRLEN);

            inet_ntop(AF_INET6, (struct sockaddr_in6 *) rdata, ipv6_str,
                      INET6_ADDRSTRLEN);

            fs_add_unsafe_string(afs, "rdata", ipv6_str, 1);
        }
    } else if (type == DNS_QTYPE_SIG || type == DNS_QTYPE_SRV ||
               type == DNS_QTYPE_DS || type == DNS_QTYPE_DNSKEY ||
               type == DNS_QTYPE_TLSA || type == DNS_QTYPE_SVCB ||
               type == DNS_QTYPE_HTTPS || type == DNS_QTYPE_CAA ||
               type == DNS_QTYPE_HTTPSSVC) {
        if (rdlength >= 1 && (rdlength - 1) != *(uint8_t *) rdata) {
            log_warn(
                "dnsaecsv",
                "SRV-like record with wrong SRV-like len. Not processing.");
            fs_add_uint64(afs, "rdata_is_parsed", 0);
            fs_add_binary(afs, "rdata", rdlength, rdata, 0);
        } else if (rdlength < 1) {
            fs_add_uint64(afs, "rdata_is_parsed", 0);
            fs_add_binary(afs, "rdata", rdlength, rdata, 0);
        } else {
            fs_add_uint64(afs, "rdata_is_parsed", 1);
            char *txt = xmalloc(rdlength);
            memcpy(txt, rdata + 1, rdlength - 1);
            fs_add_unsafe_string(afs, "rdata", txt, 1);
        }
    } else if (type == DNS_QTYPE_OPT) {
        dns_option_tail *option_tail =
            (dns_option_tail *) (*data + bytes_consumed);
        uint16_t udpsize  = ntohs(option_tail->udpsize);
        uint8_t  ercode   = option_tail->ercode;
        uint8_t  eversion = option_tail->eversion;
        uint16_t dodnssec = option_tail->dodnssec;
        uint16_t option_z =
            (((option_tail->dodnssec << 7) + option_tail->z1) << 8) +
            option_tail->z2;
        uint16_t option_dlength = ntohs(option_tail->dlength);
        char    *option_data    = option_tail->data;

        fs_add_uint64(afs, "udpsize", udpsize);
        fs_add_uint64(afs, "ercode", ercode);
        fs_add_uint64(afs, "eversion", eversion);
        fs_add_uint64(afs, "dodnssec", dodnssec);
        fs_add_uint64(afs, "z", option_z);
        fs_add_uint64(afs, "dlength", option_dlength);
        fs_add_binary(afs, "data", option_dlength, option_data, 0);

        if (option_dlength >= 4) {
            dns_option_ecs *ecs_tail = (dns_option_ecs *) option_data;
            uint16_t        optcode  = ntohs(ecs_tail->optcode);

            fs_add_uint64(afs, "optcode", optcode);

            if (optcode == DNS_OPTCODE_ECS) {
                fs_add_string(afs, "optcode_str", "ECS", 0);

                uint16_t optlength = ntohs(ecs_tail->optlength);
                uint16_t family    = ntohs(ecs_tail->family);
                uint8_t  srcnmask  = ecs_tail->srcnmask;
                uint8_t  scpnmask  = ecs_tail->scpnmask;

                fs_add_uint64(afs, "optlength", optlength);
                fs_add_uint64(afs, "family", family);
                fs_add_uint64(afs, "srcnmask", srcnmask);
                fs_add_uint64(afs, "scpnmask", scpnmask);

                if (family == DNS_ADDRFAMILY_IP) {
                    uint8_t ip_raw[4] = {00};
                    memcpy(ip_raw, ecs_tail->cs, optlength - 4);

                    fs_add_string(afs, "cs",
                                  make_ip_str((uint32_t) ip_raw[3] << 24 |
                                              (uint32_t) ip_raw[2] << 16 |
                                              (uint32_t) ip_raw[1] << 8 |
                                              (uint32_t) ip_raw[0]),
                                  1);
                } else if (family == DNS_ADDRFAMILY_IP6) {
                    uint8_t ip_raw[16] = {0x00};
                    memcpy(ip_raw, ecs_tail->cs, optlength - 4);

                    fs_add_string(afs, "cs",
                                  make_ipv6_str((struct in6_addr *) ip_raw), 1);
                }
            }
        }
    } else {
        fs_add_uint64(afs, "rdata_is_parsed", 0);
        fs_add_binary(afs, "rdata", rdlength, rdata, 0);
    }
    // Now we're adding the new fs to the list.
    fs_add_fieldset(list, NULL, afs);
    // Now update the pointers.
    *data     = *data + bytes_consumed + sizeof(dns_answer_tail) + rdlength;
    *data_len = *data_len - bytes_consumed - sizeof(dns_answer_tail) - rdlength;
    log_trace("dnsaecsv",
              "return success from process_response_answer_aecsv, data_len: %d",
              *data_len);

    return 0;
}

static int load_question_from_str_aecsv(const char *type_q_str) {
    char *probe_q_delimiter_p   = NULL;
    char *probe_arg_delimiter_p = NULL;
    while (1) {
        probe_q_delimiter_p   = strchr(type_q_str, ',');
        probe_arg_delimiter_p = strchr(type_q_str, ';');

        if (probe_q_delimiter_p == NULL) return EXIT_SUCCESS;

        if (probe_q_delimiter_p == type_q_str ||
            type_q_str + strlen(type_q_str) == (probe_q_delimiter_p + 1)) {
            log_error("dnsaecsv", dnsaecsv_usage_error);
            return EXIT_FAILURE;
        }

        if (index_questions_aecsv >= num_questions_aecsv) {
            log_error("dnsaecsv", "less probes than questions configured. Add "
                                  "additional questions.");
            return EXIT_FAILURE;
        }

        int domain_len = 0;

        if (probe_arg_delimiter_p) {
            domain_len = probe_arg_delimiter_p - probe_q_delimiter_p - 1;
        } else {
            domain_len = strlen(probe_q_delimiter_p) - 1;
        }
        assert(domain_len > 0);

        if (label_type_aecsv == DNS_LTYPE_STR) {
            domains_aecsv[index_questions_aecsv] =
                xmalloc(label_len_aecsv + 1 + domain_len + 1);
            strncpy(domains_aecsv[index_questions_aecsv], label_aecsv,
                    label_len_aecsv);
            domains_aecsv[index_questions_aecsv][label_len_aecsv] = '.';
            strncpy(domains_aecsv[index_questions_aecsv] + label_len_aecsv + 1,
                    probe_q_delimiter_p + 1, domain_len);
            domains_aecsv[index_questions_aecsv]
                         [label_len_aecsv + 1 + domain_len] = '\0';
        } else {
            domains_aecsv[index_questions_aecsv] = xmalloc(domain_len + 1);
            strncpy(domains_aecsv[index_questions_aecsv],
                    probe_q_delimiter_p + 1, domain_len);
            domains_aecsv[index_questions_aecsv][domain_len] = '\0';
        }

        char *qtype_str = xmalloc(probe_q_delimiter_p - type_q_str + 1);
        strncpy(qtype_str, type_q_str, probe_q_delimiter_p - type_q_str);
        qtype_str[probe_q_delimiter_p - type_q_str] = '\0';

        qtypes_aecsv[index_questions_aecsv] =
            qtype_str_to_code_aecsv(strupr(qtype_str));
        if (!qtypes_aecsv[index_questions_aecsv]) {
            log_error("dnsaecsv", "incorrect qtype supplied: %s", qtype_str);
            free(qtype_str);
            return EXIT_FAILURE;
        }
        free(qtype_str);

        index_questions_aecsv++;
        if (probe_arg_delimiter_p)
            type_q_str = probe_q_delimiter_p + domain_len + 2;
        else
            type_q_str = probe_q_delimiter_p + domain_len + 1;
    }
}

static int load_question_from_file_aecsv(const char *file) {
    log_debug("dnsaecsv", "load dns query domains from file");

    FILE *fp = fopen(file, "r");
    if (fp == NULL) {
        log_error("dnsaecsv", "null dns domain file");
        return EXIT_FAILURE;
    }

    char  line[1024];
    int   line_len = 1024;
    char *ret, *pos;

    while (!feof(fp)) {
        ret = fgets(line, line_len, fp);
        if (ret == NULL) return EXIT_SUCCESS;
        pos = strchr(line, '\n');
        if (pos != NULL) *pos = '\0';
        if (load_question_from_str_aecsv(line)) return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int dns_random_bytes_aecsv(char *dst, int len, const unsigned char *charset,
                           int charset_len, aesrand_t *aes) {
    int i;
    for (i = 0; i < len; i++) {
        *dst++ = charset[(aesrand_getword(aes) & 0xFFFFFFFF) % charset_len];
    }

    return i;
}

/*
 * Start of required xmap exports.
 */

static int dnsaecsv_global_init(struct state_conf *conf) {
    num_questions_aecsv = conf->target_index_num;

    if (!conf->probe_args) {
        conf->target_index_num = 1;
        num_questions_aecsv    = 1;
    }

    if (num_questions_aecsv < 1) {
        log_fatal("dnsaecsv", "invalid number of probes for the DNS module: %d",
                  num_questions_aecsv);
    }

    // Setup the global structures
    dns_packets_aecsv     = xmalloc(sizeof(char *) * num_questions_aecsv);
    dns_packet_lens_aecsv = xmalloc(sizeof(uint16_t) * num_questions_aecsv);
    qname_lens_aecsv      = xmalloc(sizeof(uint16_t) * num_questions_aecsv);
    qnames_aecsv          = xmalloc(sizeof(char *) * num_questions_aecsv);
    qtypes_aecsv          = xmalloc(sizeof(uint16_t) * num_questions_aecsv);
    domains_aecsv         = xmalloc(sizeof(char *) * num_questions_aecsv);

    for (int i = 0; i < num_questions_aecsv; i++) {
        domains_aecsv[i] = (char *) default_domain_aecsv;
        qtypes_aecsv[i]  = default_qtype_aecsv;
    }

    // This is xmap boilerplate. Why do I have to write this?
    dns_num_ports_aecsv = conf->source_port_last - conf->source_port_first + 1;
    setup_qtype_str_map_aecsv();

    if (conf->probe_args &&
        strlen(conf->probe_args) > 0) { // no parameters passed in. Use defaults
        char *c = strchr(conf->probe_args, ':');
        if (!c) {
            log_error("dnsaecsv", dnsaecsv_usage_error);
            return EXIT_FAILURE;
        }
        ++c;

        // label type
        if (strncasecmp(conf->probe_args, "raw", 3) == 0) {
            label_type_aecsv = DNS_LTYPE_RAW;
            log_debug("dnsaecsv", "raw label prefix");
        } else if (strncasecmp(conf->probe_args, "time", 4) == 0) {
            label_type_aecsv = DNS_LTYPE_TIME;
            log_debug("dnsaecsv", "time label prefix");
        } else if (strncasecmp(conf->probe_args, "random", 6) == 0) {
            label_type_aecsv = DNS_LTYPE_RANDOM;
            log_debug("dnsaecsv", "random label prefix");
        } else if (strncasecmp(conf->probe_args, "str", 3) == 0) {
            label_type_aecsv = DNS_LTYPE_STR;
            conf->probe_args = c;
            c                = strchr(conf->probe_args, ':');
            if (!c) {
                log_error("dnsaecsv", dnsaecsv_usage_error);
                return EXIT_FAILURE;
            }
            label_len_aecsv = c - conf->probe_args;
            label_aecsv     = xmalloc(label_len_aecsv);
            strncpy(label_aecsv, conf->probe_args, label_len_aecsv);
            ++c;
            log_debug("dnsaecsv", "label prefix: %s, len: %d", label_aecsv,
                      label_len_aecsv);
        } else if (strncasecmp(conf->probe_args, "dst-ip", 6) == 0) {
            label_type_aecsv = DNS_LTYPE_SRCIP;
            log_debug("dnsaecsv", "dst-ip label prefix");
        } else {
            log_error("dnsaecsv", dnsaecsv_usage_error);
            return EXIT_FAILURE;
        }

        conf->probe_args = c;
        c                = strchr(conf->probe_args, ':');
        if (!c) {
            log_error("dnsaecsv", dnsaecsv_usage_error);
            return EXIT_FAILURE;
        }
        ++c;

        // recursive query
        if (strncasecmp(conf->probe_args, "recurse", 7) == 0) {
            recursive_aecsv = 1;
        } else if (strncasecmp(conf->probe_args, "no-recurse", 10) == 0) {
            recursive_aecsv = 0;
        } else {
            log_error("dnsaecsv", dnsaecsv_usage_error);
            return EXIT_FAILURE;
        }

        conf->probe_args = c;
        c                = strchr(conf->probe_args, ':');
        if (!c) {
            log_error("dnsaecsv", dnsaecsv_usage_error);
            return EXIT_FAILURE;
        }
        ++c;

        // input query
        if (strncasecmp(conf->probe_args, "text", 4) == 0) {
            if (load_question_from_str_aecsv(c)) return EXIT_FAILURE;
        } else if (strncasecmp(conf->probe_args, "file", 4) == 0) {
            if (load_question_from_file_aecsv(c)) return EXIT_FAILURE;
        } else {
            log_error("dnsaecsv", dnsaecsv_usage_error);
            return EXIT_FAILURE;
        }

        if (index_questions_aecsv < num_questions_aecsv) {
            log_error("dnsaecsv", "more probes than questions configured. Add "
                                  "additional probes.");
            return EXIT_FAILURE;
        }
    }

    if (label_type_aecsv == DNS_LTYPE_RAW || label_type_aecsv == DNS_LTYPE_STR)
        return build_global_dns_packets_aecsv(domains_aecsv,
                                              num_questions_aecsv);
    else
        return EXIT_SUCCESS;
}

static int dnsaecsv_global_cleanup(UNUSED struct state_conf *xconf,
                                   UNUSED struct state_send *xsend,
                                   UNUSED struct state_recv *xrecv) {
    if (dns_packets_aecsv) {
        for (int i = 0; i < num_questions_aecsv; i++) {
            if (dns_packets_aecsv[i]) {
                free(dns_packets_aecsv[i]);
            }
        }
        free(dns_packets_aecsv);
    }
    dns_packets_aecsv = NULL;

    if (qnames_aecsv) {
        for (int i = 0; i < num_questions_aecsv; i++) {
            if (qnames_aecsv[i]) {
                free(qnames_aecsv[i]);
            }
        }
        free(qnames_aecsv);
    }
    qnames_aecsv = NULL;

    if (dns_packet_lens_aecsv) {
        free(dns_packet_lens_aecsv);
    }

    if (qname_lens_aecsv) {
        free(qname_lens_aecsv);
    }

    if (qtypes_aecsv) {
        free(qtypes_aecsv);
    }

    free(label_aecsv);

    return EXIT_SUCCESS;
}

int dnsaecsv_thread_init(void *buf, macaddr_t *src, macaddr_t *gw,
                         void **arg_ptr) {
    memset(buf, 0, MAX_PACKET_SIZE);

    // Setup assuming num_questions_aecsv == 0
    struct ether_header *eth_header = (struct ether_header *) buf;
    make_eth_header(eth_header, src, gw);

    struct ip *ip_header = (struct ip *) (&eth_header[1]);
    uint16_t   ip_len =
        sizeof(struct ip) + sizeof(struct udphdr) + dns_packet_lens_aecsv[0];
    make_ip_header(ip_header, IPPROTO_UDP, ip_len);

    struct udphdr *udp_header = (struct udphdr *) (&ip_header[1]);
    uint16_t       udp_len = sizeof(struct udphdr) + dns_packet_lens_aecsv[0];
    make_udp_header(udp_header, udp_len);

    char *payload                 = (char *) (&udp_header[1]);
    module_dnsaecsv.packet_length = sizeof(struct ether_header) +
                                    sizeof(struct ip) + sizeof(struct udphdr) +
                                    dns_packet_lens_aecsv[0];
    assert(module_dnsaecsv.packet_length <= MAX_PACKET_SIZE);

    memcpy(payload, dns_packets_aecsv[0], dns_packet_lens_aecsv[0]);

    // Seed our random number generator with the global generator
    uint32_t   seed = aesrand_getword(xconf.aes);
    aesrand_t *aes  = aesrand_init_from_seed(seed);
    *arg_ptr        = aes;

    return EXIT_SUCCESS;
}

int dnsaecsv_make_packet(void *buf, size_t *buf_len, ipaddr_n_t *src_ip,
                         ipaddr_n_t *dst_ip, port_h_t dst_port, uint8_t ttl,
                         int probe_num, index_h_t index, void *arg) {
    struct ether_header *eth_header = (struct ether_header *) buf;
    struct ip           *ip_header  = (struct ip *) (&eth_header[1]);
    struct udphdr       *udp_header = (struct udphdr *) (&ip_header[1]);

    uint8_t validation[VALIDATE_BYTES];
    validate_gen(src_ip, dst_ip, dst_port, validation);

    port_h_t src_port =
        get_src_port(dns_num_ports_aecsv, probe_num, validation);
    uint16_t dns_txid = get_dnsa_txid(validation, probe_num);

    if (label_type_aecsv == DNS_LTYPE_RAW ||
        label_type_aecsv == DNS_LTYPE_STR) {
        // For num_questions_aecsv == 1, we handle this in per-thread init. Do
        // less work
        if (num_questions_aecsv > 1) {
            uint16_t ip_len = sizeof(struct ip) + sizeof(struct udphdr) +
                              dns_packet_lens_aecsv[index];
            make_ip_header(ip_header, IPPROTO_UDP, ip_len);

            uint16_t udp_len =
                sizeof(struct udphdr) + dns_packet_lens_aecsv[index];
            make_udp_header(udp_header, udp_len);

            char *payload = (char *) (&udp_header[1]);
            *buf_len      = sizeof(struct ether_header) + sizeof(struct ip) +
                       sizeof(struct udphdr) + dns_packet_lens_aecsv[index];

            assert(*buf_len <= MAX_PACKET_SIZE);

            memcpy(payload, dns_packets_aecsv[index],
                   dns_packet_lens_aecsv[index]);
        }

        ip_header->ip_src.s_addr = *(uint32_t *) src_ip;
        ip_header->ip_dst.s_addr = *(uint32_t *) dst_ip;
        ip_header->ip_ttl        = ttl;

        udp_header->uh_sport = htons(src_port);
        udp_header->uh_dport = htons(dst_port);

        dns_header *dns_header_p = (dns_header *) (&udp_header[1]);

        dns_header_p->id = dns_txid;

        udp_header->uh_sum = 0;
        udp_header->uh_sum = udp_checksum(ip_header->ip_src.s_addr,
                                          ip_header->ip_dst.s_addr, udp_header);

        ip_header->ip_sum = 0;
        ip_header->ip_sum = ip_checksum_((unsigned short *) ip_header);
    } else {
        char *new_domain        = xmalloc(MAX_NAME_LENGTH);
        int   new_label_max_len = 64;
        char *new_label         = xmalloc(new_label_max_len);
        memset(new_label, 0, new_label_max_len);

        switch (label_type_aecsv) {
        case DNS_LTYPE_TIME: {
            struct timeval t;
            gettimeofday(&t, NULL);
            snprintf(new_label, 18, "%u-%06u", (uint64_t) t.tv_sec,
                     (uint64_t) t.tv_usec);
            new_label[17] = '\0';
            break;
        }
        case DNS_LTYPE_RANDOM: {
            aesrand_t *aes = (aesrand_t *) arg;
            dns_random_bytes_aecsv(new_label, 8, charset_alpha_lower_aecsv, 26,
                                   aes);
            new_label[8] = '\0';
            break;
        }
        case DNS_LTYPE_SRCIP: {
            //            snprintf(new_label, new_label_max_len,
            //            "%u-%u-%u-%u-%u-%u-%u",
            //                     probe_num + 1, dst_ip[0], dst_ip[1],
            //                     dst_ip[2], dst_ip[3], src_port, dns_txid);
            snprintf(new_label, new_label_max_len, "pr-%02x%02x%02x%02x",
                     dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3]);
            new_label[strlen(new_label)] = '\0';
            break;
        }
        default:
            log_fatal("dnsaecsv", dnsaecsv_usage_error);
            return EXIT_FAILURE;
        }

        snprintf(new_domain, MAX_NAME_LENGTH, "%s-%s", new_label,
                 domains_aecsv[index]);

        // dns packet
        free(qnames_aecsv[index]);

        qname_lens_aecsv[index] =
            domain_to_qname_aecsv(&qnames_aecsv[index], new_domain);
        dns_packet_lens_aecsv[index] =
            sizeof(dns_header) + qname_lens_aecsv[index] +
            sizeof(dns_question_tail) + default_option_qname_len_aecsv +
            sizeof(dns_option_tail) + default_option_rdata_len_aecsv;
        if (dns_packet_lens_aecsv[index] > DNS_SEND_LEN) {
            log_fatal("dnsaecsv", "DNS packet bigger (%d) than our limit (%d)",
                      dns_packet_lens_aecsv[index], DNS_SEND_LEN);
            return EXIT_FAILURE;
        }

        free(dns_packets_aecsv[index]);

        dns_packets_aecsv[index] = xmalloc(dns_packet_lens_aecsv[index]);
        dns_header *dns_header_p = (dns_header *) dns_packets_aecsv[index];
        char       *qname_p = dns_packets_aecsv[index] + sizeof(dns_header);
        dns_question_tail *tail_p =
            (dns_question_tail *) (dns_packets_aecsv[index] +
                                   sizeof(dns_header) +
                                   qname_lens_aecsv[index]);
        char *option_qname_p =
            (char *) (dns_packets_aecsv[index] + sizeof(dns_header) +
                      qname_lens_aecsv[index] + sizeof(dns_question_tail));
        dns_option_tail *option_tail_p =
            (dns_option_tail *) (dns_packets_aecsv[index] + sizeof(dns_header) +
                                 qname_lens_aecsv[index] +
                                 sizeof(dns_question_tail) +
                                 default_option_qname_len_aecsv);
        dns_option_ecs *option_ecs_p =
            (dns_option_ecs *) (dns_packets_aecsv[index] + sizeof(dns_header) +
                                qname_lens_aecsv[index] +
                                sizeof(dns_question_tail) +
                                default_option_qname_len_aecsv +
                                sizeof(dns_option_tail));

        // All other header fields should be 0. Except id, which we set
        // per thread. Please recurse as needed.
        dns_header_p->rd = recursive_aecsv; // Is one bit. Don't need htons
        // We have 1 question
        dns_header_p->qdcount = htons(1);
        memcpy(qname_p, qnames_aecsv[index], qname_lens_aecsv[index]);
        // Set the qtype to what we passed from args
        tail_p->qtype = htons(qtypes_aecsv[index]);
        // Set the qclass to The Internet (TM) (R) (I hope you're happy
        // now Zakir)
        tail_p->qclass = htons(0x01);
        // MAGIC NUMBER. Let's be honest. This is only ever 1

        // option, others set to 0
        dns_header_p->arcount = htons(1);
        memcpy(option_qname_p, default_option_qname_aecsv,
               default_option_qname_len_aecsv);
        option_tail_p->type    = htons(DNS_QTYPE_OPT);
        option_tail_p->udpsize = htons(default_option_udpsize_aecsv);
        option_tail_p->dlength = htons(default_option_rdata_len_aecsv);

        // ecs
        option_ecs_p->optcode    = htons(DNS_OPTCODE_ECS);   // 8
        option_ecs_p->optlength  = htons(7);                 // fixed for /24
        option_ecs_p->family     = htons(DNS_ADDRFAMILY_IP); // IPv4
        option_ecs_p->srcnmask   = 24;                       // source netmask
        option_ecs_p->scpnmask   = 0;                        // scope netmask
        uint8_t client_subnet[3] = {
            src_ip[0],                             // First byte
            (src_ip[1] + (probe_num / 256)) % 256, // Second byte
            (src_ip[2] + probe_num) % 256          // Third byte
        };
        memcpy(option_ecs_p->cs, client_subnet, 3);

        // packet
        uint16_t ip_len = sizeof(struct ip) + sizeof(struct udphdr) +
                          dns_packet_lens_aecsv[index];
        make_ip_header(ip_header, IPPROTO_UDP, ip_len);

        uint16_t udp_len = sizeof(struct udphdr) + dns_packet_lens_aecsv[index];
        make_udp_header(udp_header, udp_len);

        char *payload = (char *) (&udp_header[1]);
        *buf_len      = sizeof(struct ether_header) + sizeof(struct ip) +
                   sizeof(struct udphdr) + dns_packet_lens_aecsv[index];

        assert(*buf_len <= MAX_PACKET_SIZE);

        memcpy(payload, dns_packets_aecsv[index], dns_packet_lens_aecsv[index]);

        ip_header->ip_src.s_addr = *(uint32_t *) src_ip;
        ip_header->ip_dst.s_addr = *(uint32_t *) dst_ip;
        ip_header->ip_ttl        = ttl;

        udp_header->uh_sport = htons(src_port);
        udp_header->uh_dport = htons(dst_port);

        dns_header_p = (dns_header *) (&udp_header[1]);

        dns_header_p->id = dns_txid;

        udp_header->uh_sum = 0;
        udp_header->uh_sum = udp_checksum(ip_header->ip_src.s_addr,
                                          ip_header->ip_dst.s_addr, udp_header);

        ip_header->ip_sum = 0;
        ip_header->ip_sum = ip_checksum_((unsigned short *) ip_header);

        free(new_domain);
        free(new_label);
    }

    return EXIT_SUCCESS;
}

void dnsaecsv_print_packet(FILE *fp, void *packet) {
    struct ether_header *eth_header   = (struct ether_header *) packet;
    struct ip           *ip_header    = (struct ip *) (&eth_header[1]);
    struct udphdr       *udp_header   = (struct udphdr *) (&ip_header[1]);
    dns_header          *dns_header_p = (dns_header *) (&udp_header[1]);

    uint16_t udp_len        = ntohs(udp_header->uh_ulen);
    char    *data           = ((char *) dns_header_p) + sizeof(dns_header);
    uint16_t data_len       = udp_len - sizeof(udp_header) - sizeof(dns_header);
    uint16_t bytes_consumed = 0;
    char *question_name = get_name_aecsv(data, data_len, (char *) dns_header_p,
                                                       udp_len, &bytes_consumed);
    char *qname         = ((char *) dns_header_p) + sizeof(dns_header);
    int   qname_len     = strlen(qname) + 1;
    dns_question_tail *tail_p =
        (dns_question_tail *) ((char *) dns_header_p + sizeof(dns_header) +
                               qname_len);
    char *option_qname_p = (char *) (tail_p + sizeof(dns_question_tail));
    dns_option_tail *option_tail_p =
        (dns_option_tail *) (option_qname_p + default_option_qname_len_aecsv);

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
    fprintf(
        fp,
        "DNS\n"
        "\tTransaction ID(2B)\t: 0x%04x\n"
        "\tFlags(2B)\t\t: 0x%04x\n"
        "\tQuestions(2B)\t\t: %u\n"
        "\tAnswer RRs(2B)\t\t: %u\n"
        "\tAuthority RRs(2B)\t: %u\n"
        "\tAdditional RRs(2B)\t: %u\n"
        "\tQueries\t\t\t: \n"
        "\t\t\t\t: %s: type %s, class IN\n"
        "\tAdditional records\t: \n"
        "\t\t\t\t: Name\t\t\t: ROOT\n"
        "\t\t\t\t: Type\t\t\t: OPT\n"
        "\t\t\t\t: UDP payload size\t: %u\n"
        "\t\t\t\t: Extended rcode\t: 0x00\n"
        "\t\t\t\t: EDNS0 version\t\t: 0\n"
        "\t\t\t\t: DO bit\t\t: 0\n"
        "\t\t\t\t: Reserved\t\t: 0x0000\n"
        "\t\t\t\t: Data length\t\t: 0\n",
        ntohs(dns_header_p->id), ntohs(dns_header_p->rd),
        ntohs(dns_header_p->qdcount), ntohs(dns_header_p->ancount),
        ntohs(dns_header_p->nscount), ntohs(dns_header_p->arcount),
        question_name,
        qtype_strs_aecsv[qtype_qtype_to_strid_aecsv[(uint16_t) tail_p->qtype]],
        ntohs(option_tail_p->udpsize));
    fprintf(
        fp,
        "------------------------------------------------------------------\n");

    free(question_name);
}

int dnsaecsv_validate_packet(const struct ip *ip_hdr, uint32_t len,
                             UNUSED int *is_repeat, UNUSED void *buf,
                             UNUSED size_t *buf_len, UNUSED uint8_t ttl) {
    dns_header *dns_header_p;
    if (ip_hdr->ip_p == IPPROTO_UDP) {
        if ((4 * ip_hdr->ip_hl + sizeof(struct udphdr)) > len) {
            // buffer not large enough to contain expected udp
            // header
            return PACKET_INVALID;
        }

        struct udphdr *udp_header =
            (struct udphdr *) ((char *) ip_hdr + 4 * ip_hdr->ip_hl);
        uint16_t sport = ntohs(udp_header->uh_dport);
        uint16_t dport = ntohs(udp_header->uh_sport);

        if (!xconf.target_port_flag[dport]) {
            return PACKET_INVALID;
        }

        uint8_t validation[VALIDATE_BYTES];
        validate_gen((uint8_t *) &(ip_hdr->ip_dst.s_addr),
                     (uint8_t *) &(ip_hdr->ip_src.s_addr), dport, validation);

        if (!check_dns_src_port(sport, dns_num_ports_aecsv, validation)) {
            return PACKET_INVALID;
        }

        dns_header_p = (dns_header *) (&udp_header[1]);

        if (!check_dnsa_txid(dns_header_p->id, validation)) {
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
