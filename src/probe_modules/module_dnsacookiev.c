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
 * Usage: xmap -p 53 --probe-module=dnsacookiev --probe-args="raw:text:A,qq.com"
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
probe_module_t module_dnsacookiev;
static int     dns_num_ports_acookiev;

const char     default_domain_acookiev[] = "www.qq.com";
const uint16_t default_qtype_acookiev    = DNS_QTYPE_A;
const char    *dnsacookiev_usage_error =
    "unknown DNS probe specification (expected "
    "raw/time/random:recurse/no-recurse:text:TYPE,QUESTION or "
    "raw/time/random:recurse/no-recurse:file:file_name or "
    "str:some_text:recurse/no-recurse:text:TYPE,QUESTION or "
    "str:some_text:recurse/no-recurse:file:file_name)";

const unsigned char *charset_alpha_lower_acookiev =
    (unsigned char *) "abcdefghijklmnopqrstuvwxyz";

static char    **dns_packets_acookiev;
static uint16_t *dns_packet_lens_acookiev; // Not including udp header
static uint16_t *qname_lens_acookiev;      // domain_len list
static char    **qnames_acookiev;          // domain list for query
static uint16_t *qtypes_acookiev;          // query_type list
static char    **domains_acookiev;         // domain strs
static int       num_questions_acookiev   = 0;
static int       index_questions_acookiev = 0;

const char      default_option_qname_acookiev[]   = {0x00};
static int      default_option_qname_len_acookiev = 1;
static uint16_t default_option_udpsize_acookiev   = 4096;
const char      default_option_rdata_acookiev[];
static int      default_option_rdata_len_acookiev = 20; // for cookie

/* Array of qtypes_acookiev we support. Jumping through some hops (1 level of
 * indirection) so the per-packet processing time is fast. Keep this in sync
 * with: dns_qtype (.h) qtype_strid_to_qtype_acookiev (below)
 * qtype_qtype_to_strid_acookiev (below, and setup_qtype_str_map_acookiev())
 */
const char *qtype_strs_acookiev[] = {
    "A",    "NS",    "CNAME", "SOA", "PTR",      "MX", "TXT",
    "AAAA", "RRSIG", "ANY",   "SIG", "SRV",      "DS", "DNSKEY",
    "TLSA", "SVCB",  "HTTPS", "CAA", "HTTPSSVC", "OPT"};
const int qtype_strs_len_acookiev = 20;

const dns_qtype qtype_strid_to_qtype_acookiev[] = {
    DNS_QTYPE_A,     DNS_QTYPE_NS,     DNS_QTYPE_CNAME,    DNS_QTYPE_SOA,
    DNS_QTYPE_PTR,   DNS_QTYPE_MX,     DNS_QTYPE_TXT,      DNS_QTYPE_AAAA,
    DNS_QTYPE_RRSIG, DNS_QTYPE_ALL,    DNS_QTYPE_SIG,      DNS_QTYPE_SRV,
    DNS_QTYPE_DS,    DNS_QTYPE_DNSKEY, DNS_QTYPE_TLSA,     DNS_QTYPE_SVCB,
    DNS_QTYPE_HTTPS, DNS_QTYPE_CAA,    DNS_QTYPE_HTTPSSVC, DNS_QTYPE_OPT};

int8_t qtype_qtype_to_strid_acookiev[65536] = {BAD_QTYPE_VAL};

void setup_qtype_str_map_acookiev() {
    qtype_qtype_to_strid_acookiev[DNS_QTYPE_A]        = 0;
    qtype_qtype_to_strid_acookiev[DNS_QTYPE_NS]       = 1;
    qtype_qtype_to_strid_acookiev[DNS_QTYPE_CNAME]    = 2;
    qtype_qtype_to_strid_acookiev[DNS_QTYPE_SOA]      = 3;
    qtype_qtype_to_strid_acookiev[DNS_QTYPE_PTR]      = 4;
    qtype_qtype_to_strid_acookiev[DNS_QTYPE_MX]       = 5;
    qtype_qtype_to_strid_acookiev[DNS_QTYPE_TXT]      = 6;
    qtype_qtype_to_strid_acookiev[DNS_QTYPE_AAAA]     = 7;
    qtype_qtype_to_strid_acookiev[DNS_QTYPE_RRSIG]    = 8;
    qtype_qtype_to_strid_acookiev[DNS_QTYPE_ALL]      = 9;
    qtype_qtype_to_strid_acookiev[DNS_QTYPE_SIG]      = 10;
    qtype_qtype_to_strid_acookiev[DNS_QTYPE_SRV]      = 11;
    qtype_qtype_to_strid_acookiev[DNS_QTYPE_DS]       = 12;
    qtype_qtype_to_strid_acookiev[DNS_QTYPE_DNSKEY]   = 13;
    qtype_qtype_to_strid_acookiev[DNS_QTYPE_TLSA]     = 14;
    qtype_qtype_to_strid_acookiev[DNS_QTYPE_SVCB]     = 15;
    qtype_qtype_to_strid_acookiev[DNS_QTYPE_HTTPS]    = 16;
    qtype_qtype_to_strid_acookiev[DNS_QTYPE_CAA]      = 17;
    qtype_qtype_to_strid_acookiev[DNS_QTYPE_HTTPSSVC] = 18;
    qtype_qtype_to_strid_acookiev[DNS_QTYPE_OPT]      = 19;
}

static uint16_t qtype_str_to_code_acookiev(const char *str) {
    for (int i = 0; i < qtype_strs_len_acookiev; i++) {
        if (strcmp(qtype_strs_acookiev[i], str) == 0)
            return qtype_strid_to_qtype_acookiev[i];
    }

    return 0;
}

static char    *label_acookiev      = NULL;
static uint16_t label_len_acookiev  = 0;
static uint16_t label_type_acookiev = DNS_LTYPE_RAW;
static uint16_t recursive_acookiev  = 1;

static uint16_t domain_to_qname_acookiev(char      **qname_handle,
                                         const char *domain) {
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

static int build_global_dns_packets_acookiev(char **domains, int num_domains) {
    for (int i = 0; i < num_domains; i++) {
        qname_lens_acookiev[i] =
            domain_to_qname_acookiev(&qnames_acookiev[i], domains[i]);
        if (domains[i] != (char *) default_domain_acookiev) {
            free(domains[i]);
        }
        dns_packet_lens_acookiev[i] =
            sizeof(dns_header) + qname_lens_acookiev[i] +
            sizeof(dns_question_tail) + default_option_qname_len_acookiev +
            sizeof(dns_option_tail) + default_option_rdata_len_acookiev;
        if (dns_packet_lens_acookiev[i] > DNS_SEND_LEN) {
            log_fatal("dnsacookiev",
                      "DNS packet bigger (%d) than our limit (%d)",
                      dns_packet_lens_acookiev[i], DNS_SEND_LEN);
            return EXIT_FAILURE;
        }

        dns_packets_acookiev[i]  = xmalloc(dns_packet_lens_acookiev[i]);
        dns_header *dns_header_p = (dns_header *) dns_packets_acookiev[i];
        char       *qname_p      = dns_packets_acookiev[i] + sizeof(dns_header);
        dns_question_tail *tail_p =
            (dns_question_tail *) (dns_packets_acookiev[i] +
                                   sizeof(dns_header) + qname_lens_acookiev[i]);
        char *option_qname_p =
            (char *) (dns_packets_acookiev[i] + sizeof(dns_header) +
                      qname_lens_acookiev[i] + sizeof(dns_question_tail));
        dns_option_tail *option_tail_p =
            (dns_option_tail *) (dns_packets_acookiev[i] + sizeof(dns_header) +
                                 qname_lens_acookiev[i] +
                                 sizeof(dns_question_tail) +
                                 default_option_qname_len_acookiev);
        dns_option_cookie *option_cookie_p =
            (dns_option_cookie *) (dns_packets_acookiev[i] +
                                   sizeof(dns_header) + qname_lens_acookiev[i] +
                                   sizeof(dns_question_tail) +
                                   default_option_qname_len_acookiev +
                                   sizeof(dns_option_tail));

        // All other header fields should be 0. Except id, which we set
        // per thread. Please recurse as needed.
        dns_header_p->rd = recursive_acookiev; // Is one bit. Don't need htons
        // We have 1 question
        dns_header_p->qdcount = htons(1);
        memcpy(qname_p, qnames_acookiev[i], qname_lens_acookiev[i]);
        // Set the qtype to what we passed from args
        tail_p->qtype = htons(qtypes_acookiev[i]);
        // Set the qclass to The Internet (TM) (R) (I hope you're happy
        // now Zakir)
        tail_p->qclass = htons(0x01);
        // MAGIC NUMBER. Let's be honest. This is only ever 1

        // option, others set to 0
        dns_header_p->arcount = htons(1);
        memcpy(option_qname_p, default_option_qname_acookiev,
               default_option_qname_len_acookiev);
        option_tail_p->type    = htons(DNS_QTYPE_OPT);
        option_tail_p->udpsize = htons(default_option_udpsize_acookiev);
        option_tail_p->dlength = htons(default_option_rdata_len_acookiev);

        // cookie
        option_cookie_p->optcode   = htons(DNS_OPTCODE_COOKIE); // 8
        option_cookie_p->optlength = htons(16);                 // fixed
        uint8_t cookie[8]          = {
            0, 1, 2, 3, 4, 5, 6, 7,
        };
        memcpy(option_cookie_p->clientcookie, cookie, 8); // client cookie
        memcpy(option_cookie_p->servercookie, cookie, 8); // server cookie
    }

    return EXIT_SUCCESS;
}

static uint16_t get_name_helper_acookiev(const char *data, uint16_t data_len,
                                         const char *payload,
                                         uint16_t payload_len, char *name,
                                         uint16_t name_len,
                                         uint16_t recursion_level) {
    log_trace("dnsacookiev",
              "_get_name_helper IN, datalen: %d namelen: %d recusion: %d",
              data_len, name_len, recursion_level);
    if (data_len == 0 || name_len == 0 || payload_len == 0) {
        log_trace("dnsacookiev",
                  "_get_name_helper OUT, err. 0 length field. datalen %d "
                  "namelen %d payloadlen %d",
                  data_len, name_len, payload_len);
        return 0;
    }
    if (recursion_level > MAX_LABEL_RECURSION) {
        log_trace("dnsacookiev", "_get_name_helper OUT. ERR, MAX RECUSION");
        return 0;
    }

    uint16_t bytes_consumed = 0;
    // The start of data is either a sequence of labels or a ptr.
    while (data_len > 0) {
        uint8_t byte = data[0];
        // Is this a pointer?
        if (byte >= 0xc0) {
            log_trace("dnsacookiev", "_get_name_helper, ptr encountered");
            // Do we have enough bytes to check ahead?
            if (data_len < 2) {
                log_trace("dnsacookiev",
                          "_get_name_helper OUT. ptr byte encountered. "
                          "No offset. ERR.");
                return 0;
            }
            // No. ntohs isn't needed here. It's because of
            // the upper 2 bits indicating a pointer.
            uint16_t offset = ((byte & 0x03) << 8) | (uint8_t) data[1];
            log_trace("dnsacookiev", "_get_name_helper. ptr offset 0x%x",
                      offset);
            if (offset >= payload_len) {
                log_trace(
                    "dnsacookiev",
                    "_get_name_helper OUT. offset exceeded payload len %d ERR",
                    payload_len);
                return 0;
            }

            // We need to add a dot if we are:
            // -- Not first level recursion.
            // -- have consumed bytes
            if (recursion_level > 0 || bytes_consumed > 0) {

                if (name_len < 1) {
                    log_warn("dnsacookiev",
                             "Exceeded static name field allocation.");
                    return 0;
                }

                name[0] = '.';
                name++;
                name_len--;
            }

            uint16_t rec_bytes_consumed = get_name_helper_acookiev(
                payload + offset, payload_len - offset, payload, payload_len,
                name, name_len, recursion_level + 1);
            // We are done so don't bother to increment the
            // pointers.
            if (rec_bytes_consumed == 0) {
                log_trace("dnsacookiev",
                          "_get_name_helper OUT. rec level %d failed",
                          recursion_level);
                return 0;
            } else {
                bytes_consumed += 2;
                log_trace("dnsacookiev",
                          "_get_name_helper OUT. rec level %d success. %d rec "
                          "bytes consumed. %d bytes consumed.",
                          recursion_level, rec_bytes_consumed, bytes_consumed);
                return bytes_consumed;
            }
        } else if (byte == '\0') {
            // don't bother with pointer incrementation. We're done.
            bytes_consumed += 1;
            log_trace("dnsacookiev",
                      "_get_name_helper OUT. rec level %d success. %d bytes "
                      "consumed.",
                      recursion_level, bytes_consumed);
            return bytes_consumed;
        } else {
            log_trace("dnsacookiev",
                      "_get_name_helper, segment 0x%hx encountered", byte);
            // We've now consumed a byte.
            ++data;
            --data_len;
            // Mark byte consumed after we check for first
            // iteration. Do we have enough data left (must have
            // null byte too)?
            if ((byte + 1) > data_len) {
                log_trace("dnsacookiev",
                          "_get_name_helper OUT. ERR. Not enough data "
                          "for segment %hd");
                return 0;
            }
            // If we've consumed any bytes and are in a label, we're
            // in a label chain. We need to add a dot.
            if (bytes_consumed > 0) {

                if (name_len < 1) {
                    log_warn("dnsacookiev",
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
                log_warn("dnsacookiev",
                         "Exceeded static name field allocation.");
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
static char *get_name_acookiev(const char *data, uint16_t data_len,
                               const char *payload, uint16_t payload_len,
                               uint16_t *bytes_consumed) {
    log_trace("dnsacookiev", "call to get_name_acookiev, data_len: %d",
              data_len);
    char *name      = xmalloc(MAX_NAME_LENGTH);
    *bytes_consumed = get_name_helper_acookiev(
        data, data_len, payload, payload_len, name, MAX_NAME_LENGTH - 1, 0);
    if (*bytes_consumed == 0) {
        free(name);
        return NULL;
    }
    // Our memset ensured null byte.
    assert(name[MAX_NAME_LENGTH - 1] == '\0');
    log_trace(
        "dnsacookiev",
        "return success from get_name_acookiev, bytes_consumed: %d, string: %s",
        *bytes_consumed, name);

    return name;
}

static bool process_response_question_acookiev(char **data, uint16_t *data_len,
                                               const char *payload,
                                               uint16_t    payload_len,
                                               fieldset_t *list) {
    // Payload is the start of the DNS packet, including header
    // data is handle to the start of this RR
    // data_len is a pointer to the how much total data we have to work
    // with. This is awful. I'm bad and should feel bad.
    uint16_t bytes_consumed = 0;
    char    *question_name  = get_name_acookiev(*data, *data_len, payload,
                                                payload_len, &bytes_consumed);
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
        qtype_qtype_to_strid_acookiev[qtype] == BAD_QTYPE_VAL) {
        fs_add_string(qfs, "qtype_str", (char *) BAD_QTYPE_STR, 0);
    } else {
        // I've written worse things than this 3rd arg. But I want to be
        // fast.
        fs_add_string(
            qfs, "qtype_str",
            (char *) qtype_strs_acookiev[qtype_qtype_to_strid_acookiev[qtype]],
            0);
    }

    fs_add_uint64(qfs, "qclass", qclass);
    // Now we're adding the new fs to the list.
    fs_add_fieldset(list, NULL, qfs);
    // Now update the pointers.
    *data     = *data + bytes_consumed + sizeof(dns_question_tail);
    *data_len = *data_len - bytes_consumed - sizeof(dns_question_tail);

    return 0;
}

static bool process_response_answer_acookiev(char **data, uint16_t *data_len,
                                             const char *payload,
                                             uint16_t    payload_len,
                                             fieldset_t *list) {
    log_trace("dnsacookiev",
              "call to process_response_answer_acookiev, data_len: %d",
              *data_len);
    // Payload is the start of the DNS packet, including header
    // data is handle to the start of this RR
    // data_len is a pointer to the how much total data we have to work
    // with. This is awful. I'm bad and should feel bad.
    uint16_t bytes_consumed = 0;
    char    *answer_name    = get_name_acookiev(*data, *data_len, payload,
                                                payload_len, &bytes_consumed);
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
    if (type > MAX_QTYPE ||
        qtype_qtype_to_strid_acookiev[type] == BAD_QTYPE_VAL) {
        fs_add_string(afs, "type_str", (char *) BAD_QTYPE_STR, 0);
    } else {
        // I've written worse things than this 3rd arg. But I want to be
        // fast.
        fs_add_string(
            afs, "type_str",
            (char *) qtype_strs_acookiev[qtype_qtype_to_strid_acookiev[type]],
            0);
    }
    if (type != DNS_QTYPE_OPT) {
        fs_add_uint64(afs, "class", class);
        fs_add_uint64(afs, "ttl", ttl);
        fs_add_uint64(afs, "rdlength", rdlength);
    }

    // XXX Fill this out for the other types we care about.
    if (type == DNS_QTYPE_NS || type == DNS_QTYPE_CNAME) {
        uint16_t rdata_bytes_consumed = 0;
        char    *rdata_name           = get_name_acookiev(
            rdata, rdlength, payload, payload_len, &rdata_bytes_consumed);
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
                get_name_acookiev(rdata + 2, rdlength - 2, payload, payload_len,
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
            log_warn("dnsacookiev",
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
            log_warn("dnsacookiev",
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
            log_warn("dnsacookiev",
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
                "dnsacookiev",
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
            dns_option_cookie *cookie_tail = (dns_option_cookie *) option_data;
            uint16_t           optcode     = ntohs(cookie_tail->optcode);

            fs_add_uint64(afs, "optcode", optcode);

            if (optcode == DNS_OPTCODE_COOKIE) {
                fs_add_string(afs, "optcode_str", "COOKIE", 0);

                uint16_t optlength = ntohs(cookie_tail->optlength);
                fs_add_uint64(afs, "optlength", optlength);

                fs_add_binary(afs, "clientcookie", 8, cookie_tail->clientcookie,
                              0);
                fs_add_binary(afs, "servercookie", optlength - 8,
                              cookie_tail->servercookie, 0);
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
    log_trace(
        "dnsacookiev",
        "return success from process_response_answer_acookiev, data_len: %d",
        *data_len);

    return 0;
}

static int load_question_from_str_acookiev(const char *type_q_str) {
    char *probe_q_delimiter_p   = NULL;
    char *probe_arg_delimiter_p = NULL;
    while (1) {
        probe_q_delimiter_p   = strchr(type_q_str, ',');
        probe_arg_delimiter_p = strchr(type_q_str, ';');

        if (probe_q_delimiter_p == NULL) return EXIT_SUCCESS;

        if (probe_q_delimiter_p == type_q_str ||
            type_q_str + strlen(type_q_str) == (probe_q_delimiter_p + 1)) {
            log_error("dnsacookiev", dnsacookiev_usage_error);
            return EXIT_FAILURE;
        }

        if (index_questions_acookiev >= num_questions_acookiev) {
            log_error("dnsacookiev",
                      "less probes than questions configured. Add "
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

        if (label_type_acookiev == DNS_LTYPE_STR) {
            domains_acookiev[index_questions_acookiev] =
                xmalloc(label_len_acookiev + 1 + domain_len + 1);
            strncpy(domains_acookiev[index_questions_acookiev], label_acookiev,
                    label_len_acookiev);
            domains_acookiev[index_questions_acookiev][label_len_acookiev] =
                '.';
            strncpy(domains_acookiev[index_questions_acookiev] +
                        label_len_acookiev + 1,
                    probe_q_delimiter_p + 1, domain_len);
            domains_acookiev[index_questions_acookiev]
                            [label_len_acookiev + 1 + domain_len] = '\0';
        } else {
            domains_acookiev[index_questions_acookiev] =
                xmalloc(domain_len + 1);
            strncpy(domains_acookiev[index_questions_acookiev],
                    probe_q_delimiter_p + 1, domain_len);
            domains_acookiev[index_questions_acookiev][domain_len] = '\0';
        }

        char *qtype_str = xmalloc(probe_q_delimiter_p - type_q_str + 1);
        strncpy(qtype_str, type_q_str, probe_q_delimiter_p - type_q_str);
        qtype_str[probe_q_delimiter_p - type_q_str] = '\0';

        qtypes_acookiev[index_questions_acookiev] =
            qtype_str_to_code_acookiev(strupr(qtype_str));
        if (!qtypes_acookiev[index_questions_acookiev]) {
            log_error("dnsacookiev", "incorrect qtype supplied: %s", qtype_str);
            free(qtype_str);
            return EXIT_FAILURE;
        }
        free(qtype_str);

        index_questions_acookiev++;
        if (probe_arg_delimiter_p)
            type_q_str = probe_q_delimiter_p + domain_len + 2;
        else
            type_q_str = probe_q_delimiter_p + domain_len + 1;
    }
}

static int load_question_from_file_acookiev(const char *file) {
    log_debug("dnsacookiev", "load dns query domains from file");

    FILE *fp = fopen(file, "r");
    if (fp == NULL) {
        log_error("dnsacookiev", "null dns domain file");
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
        if (load_question_from_str_acookiev(line)) return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int dns_random_bytes_acookiev(char *dst, int len, const unsigned char *charset,
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

static int dnsacookiev_global_init(struct state_conf *conf) {
    num_questions_acookiev = conf->target_index_num;

    if (!conf->probe_args) {
        conf->target_index_num = 1;
        num_questions_acookiev = 1;
    }

    if (num_questions_acookiev < 1) {
        log_fatal("dnsacookiev",
                  "invalid number of probes for the DNS module: %d",
                  num_questions_acookiev);
    }

    // Setup the global structures
    dns_packets_acookiev = xmalloc(sizeof(char *) * num_questions_acookiev);
    dns_packet_lens_acookiev =
        xmalloc(sizeof(uint16_t) * num_questions_acookiev);
    qname_lens_acookiev = xmalloc(sizeof(uint16_t) * num_questions_acookiev);
    qnames_acookiev     = xmalloc(sizeof(char *) * num_questions_acookiev);
    qtypes_acookiev     = xmalloc(sizeof(uint16_t) * num_questions_acookiev);
    domains_acookiev    = xmalloc(sizeof(char *) * num_questions_acookiev);

    for (int i = 0; i < num_questions_acookiev; i++) {
        domains_acookiev[i] = (char *) default_domain_acookiev;
        qtypes_acookiev[i]  = default_qtype_acookiev;
    }

    // This is xmap boilerplate. Why do I have to write this?
    dns_num_ports_acookiev =
        conf->source_port_last - conf->source_port_first + 1;
    setup_qtype_str_map_acookiev();

    if (conf->probe_args &&
        strlen(conf->probe_args) > 0) { // no parameters passed in. Use defaults
        char *c = strchr(conf->probe_args, ':');
        if (!c) {
            log_error("dnsacookiev", dnsacookiev_usage_error);
            return EXIT_FAILURE;
        }
        ++c;

        // label type
        if (strncasecmp(conf->probe_args, "raw", 3) == 0) {
            label_type_acookiev = DNS_LTYPE_RAW;
            log_debug("dnsacookiev", "raw label prefix");
        } else if (strncasecmp(conf->probe_args, "time", 4) == 0) {
            label_type_acookiev = DNS_LTYPE_TIME;
            log_debug("dnsacookiev", "time label prefix");
        } else if (strncasecmp(conf->probe_args, "random", 6) == 0) {
            label_type_acookiev = DNS_LTYPE_RANDOM;
            log_debug("dnsacookiev", "random label prefix");
        } else if (strncasecmp(conf->probe_args, "str", 3) == 0) {
            label_type_acookiev = DNS_LTYPE_STR;
            conf->probe_args    = c;
            c                   = strchr(conf->probe_args, ':');
            if (!c) {
                log_error("dnsacookiev", dnsacookiev_usage_error);
                return EXIT_FAILURE;
            }
            label_len_acookiev = c - conf->probe_args;
            label_acookiev     = xmalloc(label_len_acookiev);
            strncpy(label_acookiev, conf->probe_args, label_len_acookiev);
            ++c;
            log_debug("dnsacookiev", "label prefix: %s, len: %d",
                      label_acookiev, label_len_acookiev);
        } else if (strncasecmp(conf->probe_args, "dst-ip", 6) == 0) {
            label_type_acookiev = DNS_LTYPE_SRCIP;
            log_debug("dnsacookiev", "dst-ip label prefix");
        } else {
            log_error("dnsacookiev", dnsacookiev_usage_error);
            return EXIT_FAILURE;
        }

        conf->probe_args = c;
        c                = strchr(conf->probe_args, ':');
        if (!c) {
            log_error("dnsacookiev", dnsacookiev_usage_error);
            return EXIT_FAILURE;
        }
        ++c;

        // recursive query
        if (strncasecmp(conf->probe_args, "recurse", 7) == 0) {
            recursive_acookiev = 1;
        } else if (strncasecmp(conf->probe_args, "no-recurse", 10) == 0) {
            recursive_acookiev = 0;
        } else {
            log_error("dnsacookiev", dnsacookiev_usage_error);
            return EXIT_FAILURE;
        }

        conf->probe_args = c;
        c                = strchr(conf->probe_args, ':');
        if (!c) {
            log_error("dnsacookiev", dnsacookiev_usage_error);
            return EXIT_FAILURE;
        }
        ++c;

        // input query
        if (strncasecmp(conf->probe_args, "text", 4) == 0) {
            if (load_question_from_str_acookiev(c)) return EXIT_FAILURE;
        } else if (strncasecmp(conf->probe_args, "file", 4) == 0) {
            if (load_question_from_file_acookiev(c)) return EXIT_FAILURE;
        } else {
            log_error("dnsacookiev", dnsacookiev_usage_error);
            return EXIT_FAILURE;
        }

        if (index_questions_acookiev < num_questions_acookiev) {
            log_error("dnsacookiev",
                      "more probes than questions configured. Add "
                      "additional probes.");
            return EXIT_FAILURE;
        }
    }

    if (label_type_acookiev == DNS_LTYPE_RAW ||
        label_type_acookiev == DNS_LTYPE_STR)
        return build_global_dns_packets_acookiev(domains_acookiev,
                                                 num_questions_acookiev);
    else
        return EXIT_SUCCESS;
}

static int dnsacookiev_global_cleanup(UNUSED struct state_conf *xconf,
                                      UNUSED struct state_send *xsend,
                                      UNUSED struct state_recv *xrecv) {
    if (dns_packets_acookiev) {
        for (int i = 0; i < num_questions_acookiev; i++) {
            if (dns_packets_acookiev[i]) {
                free(dns_packets_acookiev[i]);
            }
        }
        free(dns_packets_acookiev);
    }
    dns_packets_acookiev = NULL;

    if (qnames_acookiev) {
        for (int i = 0; i < num_questions_acookiev; i++) {
            if (qnames_acookiev[i]) {
                free(qnames_acookiev[i]);
            }
        }
        free(qnames_acookiev);
    }
    qnames_acookiev = NULL;

    if (dns_packet_lens_acookiev) {
        free(dns_packet_lens_acookiev);
    }

    if (qname_lens_acookiev) {
        free(qname_lens_acookiev);
    }

    if (qtypes_acookiev) {
        free(qtypes_acookiev);
    }

    free(label_acookiev);

    return EXIT_SUCCESS;
}

int dnsacookiev_thread_init(void *buf, macaddr_t *src, macaddr_t *gw,
                            void **arg_ptr) {
    memset(buf, 0, MAX_PACKET_SIZE);

    // Setup assuming num_questions_acookiev == 0
    struct ether_header *eth_header = (struct ether_header *) buf;
    make_eth_header(eth_header, src, gw);

    struct ip *ip_header = (struct ip *) (&eth_header[1]);
    uint16_t   ip_len =
        sizeof(struct ip) + sizeof(struct udphdr) + dns_packet_lens_acookiev[0];
    make_ip_header(ip_header, IPPROTO_UDP, ip_len);

    struct udphdr *udp_header = (struct udphdr *) (&ip_header[1]);
    uint16_t udp_len = sizeof(struct udphdr) + dns_packet_lens_acookiev[0];
    make_udp_header(udp_header, udp_len);

    char *payload = (char *) (&udp_header[1]);
    module_dnsacookiev.packet_length =
        sizeof(struct ether_header) + sizeof(struct ip) +
        sizeof(struct udphdr) + dns_packet_lens_acookiev[0];
    assert(module_dnsacookiev.packet_length <= MAX_PACKET_SIZE);

    memcpy(payload, dns_packets_acookiev[0], dns_packet_lens_acookiev[0]);

    // Seed our random number generator with the global generator
    uint32_t   seed = aesrand_getword(xconf.aes);
    aesrand_t *aes  = aesrand_init_from_seed(seed);
    *arg_ptr        = aes;

    return EXIT_SUCCESS;
}

int dnsacookiev_make_packet(void *buf, size_t *buf_len, ipaddr_n_t *src_ip,
                            ipaddr_n_t *dst_ip, port_h_t dst_port, uint8_t ttl,
                            int probe_num, index_h_t index, void *arg) {
    struct ether_header *eth_header = (struct ether_header *) buf;
    struct ip           *ip_header  = (struct ip *) (&eth_header[1]);
    struct udphdr       *udp_header = (struct udphdr *) (&ip_header[1]);

    uint8_t validation[VALIDATE_BYTES];
    validate_gen(src_ip, dst_ip, dst_port, validation);

    port_h_t src_port =
        get_src_port(dns_num_ports_acookiev, probe_num, validation);
    uint16_t dns_txid = get_dnsa_txid(validation, probe_num);

    if (label_type_acookiev == DNS_LTYPE_RAW ||
        label_type_acookiev == DNS_LTYPE_STR) {
        // For num_questions_acookiev == 1, we handle this in per-thread init.
        // Do less work
        if (num_questions_acookiev > 1) {
            uint16_t ip_len = sizeof(struct ip) + sizeof(struct udphdr) +
                              dns_packet_lens_acookiev[index];
            make_ip_header(ip_header, IPPROTO_UDP, ip_len);

            uint16_t udp_len =
                sizeof(struct udphdr) + dns_packet_lens_acookiev[index];
            make_udp_header(udp_header, udp_len);

            char *payload = (char *) (&udp_header[1]);
            *buf_len      = sizeof(struct ether_header) + sizeof(struct ip) +
                       sizeof(struct udphdr) + dns_packet_lens_acookiev[index];

            assert(*buf_len <= MAX_PACKET_SIZE);

            memcpy(payload, dns_packets_acookiev[index],
                   dns_packet_lens_acookiev[index]);
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

        switch (label_type_acookiev) {
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
            dns_random_bytes_acookiev(new_label, 8,
                                      charset_alpha_lower_acookiev, 26, aes);
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
            log_fatal("dnsacookiev", dnsacookiev_usage_error);
            return EXIT_FAILURE;
        }

        snprintf(new_domain, MAX_NAME_LENGTH, "%s-%s", new_label,
                 domains_acookiev[index]);

        // dns packet
        free(qnames_acookiev[index]);

        qname_lens_acookiev[index] =
            domain_to_qname_acookiev(&qnames_acookiev[index], new_domain);
        dns_packet_lens_acookiev[index] =
            sizeof(dns_header) + qname_lens_acookiev[index] +
            sizeof(dns_question_tail) + default_option_qname_len_acookiev +
            sizeof(dns_option_tail) + default_option_rdata_len_acookiev;
        if (dns_packet_lens_acookiev[index] > DNS_SEND_LEN) {
            log_fatal("dnsacookiev",
                      "DNS packet bigger (%d) than our limit (%d)",
                      dns_packet_lens_acookiev[index], DNS_SEND_LEN);
            return EXIT_FAILURE;
        }

                free(dns_packets_acookiev[index]);

                dns_packets_acookiev[index] = xmalloc(dns_packet_lens_acookiev[index]);
                dns_header *dns_header_p = (dns_header *) dns_packets_acookiev[index];
                char       *qname_p = dns_packets_acookiev[index] + sizeof(dns_header);
                dns_question_tail *tail_p =
                    (dns_question_tail *) (dns_packets_acookiev[index] +
                                           sizeof(dns_header) +
                                           qname_lens_acookiev[index]);
                char *option_qname_p =
                    (char *) (dns_packets_acookiev[index] + sizeof(dns_header) +
                              qname_lens_acookiev[index] + sizeof(dns_question_tail));
                dns_option_tail *option_tail_p =
                    (dns_option_tail *) (dns_packets_acookiev[index] +
                                         sizeof(dns_header) +
                                         qname_lens_acookiev[index] +
                                         sizeof(dns_question_tail) +
                                         default_option_qname_len_acookiev);
                dns_option_cookie *option_cookie_p =
                    (dns_option_cookie *) (dns_packets_acookiev[index] +
                                           sizeof(dns_header) +
                                           qname_lens_acookiev[index] +
                                           sizeof(dns_question_tail) +
                                           default_option_qname_len_acookiev +
                                           sizeof(dns_option_tail));

                // All other header fields should be 0. Except id, which we set
                // per thread. Please recurse as needed.
                dns_header_p->rd = recursive_acookiev; // Is one bit. Don't need htons
                // We have 1 question
                dns_header_p->qdcount = htons(1);
                memcpy(qname_p, qnames_acookiev[index], qname_lens_acookiev[index]);
                // Set the qtype to what we passed from args
                tail_p->qtype = htons(qtypes_acookiev[index]);
                // Set the qclass to The Internet (TM) (R) (I hope you're happy
                // now Zakir)
                tail_p->qclass = htons(0x01);
                // MAGIC NUMBER. Let's be honest. This is only ever 1

                // option, others set to 0
                dns_header_p->arcount = htons(1);
                memcpy(option_qname_p, default_option_qname_acookiev,
                       default_option_qname_len_acookiev);
                option_tail_p->type    = htons(DNS_QTYPE_OPT);
                option_tail_p->udpsize = htons(default_option_udpsize_acookiev);
                option_tail_p->dlength = htons(default_option_rdata_len_acookiev);

                // cookie
                option_cookie_p->optcode   = htons(DNS_OPTCODE_COOKIE); // 8
                option_cookie_p->optlength = htons(16);                 // fixed
                uint8_t cookie[8]          = {
                    0x00,
                    0x01,
                    0x02,
                    0x03,
                    src_ip[0],
                    src_ip[1],
                    (src_ip[2] + (probe_num / 256)) % 256,
                    (src_ip[3] + probe_num) % 256,
                };
                memcpy(option_cookie_p->clientcookie, cookie, 8);
                memcpy(option_cookie_p->servercookie, cookie, 8);
