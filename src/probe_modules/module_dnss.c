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
 *      TYPE: A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, RRSIG, and ANY
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
 * Usage: xmap -p 53 --probe-module=dnss --probe-args="raw:text:A,qq.com"
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
#define MAX_QTYPE 255
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
probe_module_t module_dnss;
static int     dns_num_ports_s;

const char     default_domain_s[] = "www.qq.com";
const uint16_t default_qtype_s    = DNS_QTYPE_A;
const char    *dnss_usage_error =
    "unknown DNS probe specification (expected "
    "raw/time/random:recurse/no-recurse:text:TYPE,QUESTION or "
    "raw/time/random:recurse/no-recurse:file:file_name or "
    "str:some_text:recurse/no-recurse:text:TYPE,QUESTION or "
    "str:some_text:recurse/no-recurse:file:file_name)";

const unsigned char *charset_alpha_lower_s =
    (unsigned char *) "abcdefghijklmnopqrstuvwxyz";

static char    **dns_packets_s;
static uint16_t *dns_packet_lens_s; // Not including udp header
static uint16_t *qname_lens_s;      // domain_len list
static char    **qnames_s;          // domain list for query
static uint16_t *qtypes_s;          // query_type list
static char    **domains_s;         // domain strs
static int       num_questions_s   = 0;
static int       index_questions_s = 0;

/* Array of qtypes_s we support. Jumping through some hops (1 level of
 * indirection) so the per-packet processing time is fast. Keep this in sync
 * with: dns_qtype (.h) qtype_strid_to_qtype_s (below) qtype_qtype_to_strid_s
 * (below, and setup_qtype_str_map_s())
 */
const char *qtype_strs_s[]   = {"A",  "NS",  "CNAME", "SOA",   "PTR",
                                "MX", "TXT", "AAAA",  "RRSIG", "ANY"};
const int   qtype_strs_len_s = 10;

const dns_qtype qtype_strid_to_qtype_s[] = {
    DNS_QTYPE_A,     DNS_QTYPE_NS, DNS_QTYPE_CNAME, DNS_QTYPE_SOA,
    DNS_QTYPE_PTR,   DNS_QTYPE_MX, DNS_QTYPE_TXT,   DNS_QTYPE_AAAA,
    DNS_QTYPE_RRSIG, DNS_QTYPE_ALL};

int8_t qtype_qtype_to_strid_s[256] = {BAD_QTYPE_VAL};

void setup_qtype_str_map_s() {
    qtype_qtype_to_strid_s[DNS_QTYPE_A]     = 0;
    qtype_qtype_to_strid_s[DNS_QTYPE_NS]    = 1;
    qtype_qtype_to_strid_s[DNS_QTYPE_CNAME] = 2;
    qtype_qtype_to_strid_s[DNS_QTYPE_SOA]   = 3;
    qtype_qtype_to_strid_s[DNS_QTYPE_PTR]   = 4;
    qtype_qtype_to_strid_s[DNS_QTYPE_MX]    = 5;
    qtype_qtype_to_strid_s[DNS_QTYPE_TXT]   = 6;
    qtype_qtype_to_strid_s[DNS_QTYPE_AAAA]  = 7;
    qtype_qtype_to_strid_s[DNS_QTYPE_RRSIG] = 8;
    qtype_qtype_to_strid_s[DNS_QTYPE_ALL]   = 9;
}

static uint16_t qtype_str_to_code_s(const char *str) {
    for (int i = 0; i < qtype_strs_len_s; i++) {
        if (strcmp(qtype_strs_s[i], str) == 0) return qtype_strid_to_qtype_s[i];
    }

    return 0;
}

static char    *label_s      = NULL;
static uint16_t label_len_s  = 0;
static uint16_t label_type_s = DNS_LTYPE_RAW;
static uint16_t recursive_s  = 1;

char additional_section_dnssec[11] = {0x00, 0x00, 0x29, 0x10, 0x00, 0x00,
                                      0x00, 0x80, 0x00, 0x00, 0x00};

static uint16_t domain_to_qname_s(char **qname_handle, const char *domain) {
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

static int build_global_dns_packets_s(char **domains, int num_domains) {
    for (int i = 0; i < num_domains; i++) {
        qname_lens_s[i] = domain_to_qname_s(&qnames_s[i], domains[i]);
        if (domains[i] != (char *) default_domain_s) {
            free(domains[i]);
        }
        dns_packet_lens_s[i] = sizeof(dns_header) + qname_lens_s[i] +
                               sizeof(dns_question_tail) + 11;
        if (dns_packet_lens_s[i] > DNS_SEND_LEN) {
            log_fatal("dnss", "DNS packet bigger (%d) than our limit (%d)",
                      dns_packet_lens_s[i], DNS_SEND_LEN);
            return EXIT_FAILURE;
        }

        dns_packets_s[i]                = xmalloc(dns_packet_lens_s[i]);
        dns_header        *dns_header_p = (dns_header *) dns_packets_s[i];
        char              *qname_p      = dns_packets_s[i] + sizeof(dns_header);
        dns_question_tail *tail_p =
            (dns_question_tail *) (dns_packets_s[i] + sizeof(dns_header) +
                                   qname_lens_s[i]);
        char *additional_p = dns_packets_s[i] + sizeof(dns_header) +
                             qname_lens_s[i] + sizeof(dns_question_tail);

        // All other header fields should be 0. Except id, which we set
        // per thread. Please recurse as needed.
        dns_header_p->rd = recursive_s; // Is one bit. Don't need htons
        // We have 1 question
        dns_header_p->qdcount = htons(1);
        memcpy(qname_p, qnames_s[i], qname_lens_s[i]);
        // Set the qtype to what we passed from args
        tail_p->qtype = htons(qtypes_s[i]);
        // Set the qclass to The Internet (TM) (R) (I hope you're happy
        // now Zakir)
        tail_p->qclass = htons(0x01);
        // MAGIC NUMBER. Let's be honest. This is only ever 1
        // We have 1 additional
        dns_header_p->arcount = htons(1);
        memcpy(additional_p, additional_section_dnssec, 11);
    }

    return EXIT_SUCCESS;
}

static uint16_t get_name_helper_s(const char *data, uint16_t data_len,
                                  const char *payload, uint16_t payload_len,
                                  char *name, uint16_t name_len,
                                  uint16_t recursion_level) {
    log_trace("dnss",
              "_get_name_helper IN, datalen: %d namelen: %d recusion: %d",
              data_len, name_len, recursion_level);
    if (data_len == 0 || name_len == 0 || payload_len == 0) {
        log_trace("dnss",
                  "_get_name_helper OUT, err. 0 length field. datalen %d "
                  "namelen %d payloadlen %d",
                  data_len, name_len, payload_len);
        return 0;
    }
    if (recursion_level > MAX_LABEL_RECURSION) {
        log_trace("dnss", "_get_name_helper OUT. ERR, MAX RECUSION");
        return 0;
    }

    uint16_t bytes_consumed = 0;
    // The start of data is either a sequence of labels or a ptr.
    while (data_len > 0) {
        uint8_t byte = data[0];
        // Is this a pointer?
        if (byte >= 0xc0) {
            log_trace("dnss", "_get_name_helper, ptr encountered");
            // Do we have enough bytes to check ahead?
            if (data_len < 2) {
                log_trace("dnss", "_get_name_helper OUT. ptr byte encountered. "
                                  "No offset. ERR.");
                return 0;
            }
            // No. ntohs isn't needed here. It's because of
            // the upper 2 bits indicating a pointer.
            uint16_t offset = ((byte & 0x03) << 8) | (uint8_t) data[1];
            log_trace("dnss", "_get_name_helper. ptr offset 0x%x", offset);
            if (offset >= payload_len) {
                log_trace(
                    "dnss",
                    "_get_name_helper OUT. offset exceeded payload len %d ERR",
                    payload_len);
                return 0;
            }

            // We need to add a dot if we are:
            // -- Not first level recursion.
            // -- have consumed bytes
            if (recursion_level > 0 || bytes_consumed > 0) {

                if (name_len < 1) {
                    log_warn("dnss", "Exceeded static name field allocation.");
                    return 0;
                }

                name[0] = '.';
                name++;
                name_len--;
            }

            uint16_t rec_bytes_consumed = get_name_helper_s(
                payload + offset, payload_len - offset, payload, payload_len,
                name, name_len, recursion_level + 1);
            // We are done so don't bother to increment the
            // pointers.
            if (rec_bytes_consumed == 0) {
                log_trace("dnss", "_get_name_helper OUT. rec level %d failed",
                          recursion_level);
                return 0;
            } else {
                bytes_consumed += 2;
                log_trace("dnss",
                          "_get_name_helper OUT. rec level %d success. %d rec "
                          "bytes consumed. %d bytes consumed.",
                          recursion_level, rec_bytes_consumed, bytes_consumed);
                return bytes_consumed;
            }
        } else if (byte == '\0') {
            // don't bother with pointer incrementation. We're done.
            bytes_consumed += 1;
            log_trace("dnss",
                      "_get_name_helper OUT. rec level %d success. %d bytes "
                      "consumed.",
                      recursion_level, bytes_consumed);
            return bytes_consumed;
        } else {
            log_trace("dnss", "_get_name_helper, segment 0x%hx encountered",
                      byte);
            // We've now consumed a byte.
            ++data;
            --data_len;
            // Mark byte consumed after we check for first
            // iteration. Do we have enough data left (must have
            // null byte too)?
            if ((byte + 1) > data_len) {
                log_trace("dnss", "_get_name_helper OUT. ERR. Not enough data "
                                  "for segment %hd");
                return 0;
            }
            // If we've consumed any bytes and are in a label, we're
            // in a label chain. We need to add a dot.
            if (bytes_consumed > 0) {

                if (name_len < 1) {
                    log_warn("dnss", "Exceeded static name field allocation.");
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
                log_warn("dnss", "Exceeded static name field allocation.");
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
static char *get_name_s(const char *data, uint16_t data_len,
                        const char *payload, uint16_t payload_len,
                        uint16_t *bytes_consumed) {
    log_trace("dnss", "call to get_name_s, data_len: %d", data_len);
    char *name      = xmalloc(MAX_NAME_LENGTH);
    *bytes_consumed = get_name_helper_s(data, data_len, payload, payload_len,
                                        name, MAX_NAME_LENGTH - 1, 0);
    if (*bytes_consumed == 0) {
        free(name);
        return NULL;
    }
    // Our memset ensured null byte.
    assert(name[MAX_NAME_LENGTH - 1] == '\0');
    log_trace("dnss",
              "return success from get_name_s, bytes_consumed: %d, string: %s",
              *bytes_consumed, name);

    return name;
}

static bool process_response_question_s(char **data, uint16_t *data_len,
                                        const char *payload,
                                        uint16_t    payload_len,
                                        fieldset_t *list) {
    // Payload is the start of the DNS packet, including header
    // data is handle to the start of this RR
    // data_len is a pointer to the how much total data we have to work
    // with. This is awful. I'm bad and should feel bad.
    uint16_t bytes_consumed = 0;
    char    *question_name =
        get_name_s(*data, *data_len, payload, payload_len, &bytes_consumed);
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

    if (qtype > MAX_QTYPE || qtype_qtype_to_strid_s[qtype] == BAD_QTYPE_VAL) {
        fs_add_string(qfs, "qtype_str", (char *) BAD_QTYPE_STR, 0);
    } else {
        // I've written worse things than this 3rd arg. But I want to be
        // fast.
        fs_add_string(qfs, "qtype_str",
                      (char *) qtype_strs_s[qtype_qtype_to_strid_s[qtype]], 0);
    }

    fs_add_uint64(qfs, "qclass", qclass);
    // Now we're adding the new fs to the list.
    fs_add_fieldset(list, NULL, qfs);
    // Now update the pointers.
    *data     = *data + bytes_consumed + sizeof(dns_question_tail);
    *data_len = *data_len - bytes_consumed - sizeof(dns_question_tail);

    return 0;
}

static bool process_response_answer_s(char **data, uint16_t *data_len,
                                      const char *payload, uint16_t payload_len,
                                      fieldset_t *list) {
    log_trace("dnss", "call to process_response_answer_s, data_len: %d",
              *data_len);
    // Payload is the start of the DNS packet, including header
    // data is handle to the start of this RR
    // data_len is a pointer to the how much total data we have to work
    // with. This is awful. I'm bad and should feel bad.
    uint16_t bytes_consumed = 0;
    char    *answer_name =
        get_name_s(*data, *data_len, payload, payload_len, &bytes_consumed);
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
    if (type > MAX_QTYPE || qtype_qtype_to_strid_s[type] == BAD_QTYPE_VAL) {
        fs_add_string(afs, "type_str", (char *) BAD_QTYPE_STR, 0);
    } else {
        // I've written worse things than this 3rd arg. But I want to be
        // fast.
        fs_add_string(afs, "type_str",
                      (char *) qtype_strs_s[qtype_qtype_to_strid_s[type]], 0);
    }
    fs_add_uint64(afs, "class", class);
    fs_add_uint64(afs, "ttl", ttl);
    fs_add_uint64(afs, "rdlength", rdlength);

    // XXX Fill this out for the other types we care about.
    if (type == DNS_QTYPE_NS || type == DNS_QTYPE_CNAME) {
        uint16_t rdata_bytes_consumed = 0;
        char    *rdata_name = get_name_s(rdata, rdlength, payload, payload_len,
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
            char *rdata_name = get_name_s(rdata + 2, rdlength - 2, payload,
                                          payload_len, &rdata_bytes_consumed);
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
            log_warn("dnss", "TXT record with wrong TXT len. Not processing.");
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
            log_warn("dnss", "A record with IP of length %d. Not processing.",
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
            log_warn("dnss",
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
    } else {
        fs_add_uint64(afs, "rdata_is_parsed", 0);
        fs_add_binary(afs, "rdata", rdlength, rdata, 0);
    }
    // Now we're adding the new fs to the list.
    fs_add_fieldset(list, NULL, afs);
    // Now update the pointers.
    *data     = *data + bytes_consumed + sizeof(dns_answer_tail) + rdlength;
    *data_len = *data_len - bytes_consumed - sizeof(dns_answer_tail) - rdlength;
    log_trace("dnss",
              "return success from process_response_answer_s, data_len: %d",
              *data_len);

    return 0;
}

static int load_question_from_str_s(const char *type_q_str) {
    char *probe_q_delimiter_p   = NULL;
    char *probe_arg_delimiter_p = NULL;
    while (1) {
        probe_q_delimiter_p   = strchr(type_q_str, ',');
        probe_arg_delimiter_p = strchr(type_q_str, ';');

        if (probe_q_delimiter_p == NULL) return EXIT_SUCCESS;

        if (probe_q_delimiter_p == type_q_str ||
            type_q_str + strlen(type_q_str) == (probe_q_delimiter_p + 1)) {
            log_error("dnss", dnss_usage_error);
            return EXIT_FAILURE;
        }

        if (index_questions_s >= num_questions_s) {
            log_error("dnss", "less probes than questions configured. Add "
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

        if (label_type_s == DNS_LTYPE_STR) {
            domains_s[index_questions_s] =
                xmalloc(label_len_s + 1 + domain_len + 1);
            strncpy(domains_s[index_questions_s], label_s, label_len_s);
            domains_s[index_questions_s][label_len_s] = '.';
            strncpy(domains_s[index_questions_s] + label_len_s + 1,
                    probe_q_delimiter_p + 1, domain_len);
            domains_s[index_questions_s][label_len_s + 1 + domain_len] = '\0';
        } else {
            domains_s[index_questions_s] = xmalloc(domain_len + 1);
            strncpy(domains_s[index_questions_s], probe_q_delimiter_p + 1,
                    domain_len);
            domains_s[index_questions_s][domain_len] = '\0';
        }

        char *qtype_str = xmalloc(probe_q_delimiter_p - type_q_str + 1);
        strncpy(qtype_str, type_q_str, probe_q_delimiter_p - type_q_str);
        qtype_str[probe_q_delimiter_p - type_q_str] = '\0';

        qtypes_s[index_questions_s] = qtype_str_to_code_s(strupr(qtype_str));
        if (!qtypes_s[index_questions_s]) {
            log_error("dnss", "incorrect qtype supplied. %s", qtype_str);
            free(qtype_str);
            return EXIT_FAILURE;
        }
        free(qtype_str);

        index_questions_s++;
        if (probe_arg_delimiter_p)
            type_q_str = probe_q_delimiter_p + domain_len + 2;
        else
            type_q_str = probe_q_delimiter_p + domain_len + 1;
    }
}

static int load_question_from_file_s(const char *file) {
    log_debug("dnss", "load dns query domains from file");

    FILE *fp = fopen(file, "r");
    if (fp == NULL) {
        log_error("dnss", "null dns domain file");
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
        if (load_question_from_str_s(line)) return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int dns_random_bytes_s(char *dst, int len, const unsigned char *charset,
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

static int dnss_global_init(struct state_conf *conf) {
    num_questions_s = conf->target_index_num;

    if (!conf->probe_args) {
        conf->target_index_num = 1;
        num_questions_s        = 1;
    }

    if (num_questions_s < 1) {
        log_fatal("dnss", "invalid number of probes for the DNS module: %d",
                  num_questions_s);
    }

    // Setup the global structures
    dns_packets_s     = xmalloc(sizeof(char *) * num_questions_s);
    dns_packet_lens_s = xmalloc(sizeof(uint16_t) * num_questions_s);
    qname_lens_s      = xmalloc(sizeof(uint16_t) * num_questions_s);
    qnames_s          = xmalloc(sizeof(char *) * num_questions_s);
    qtypes_s          = xmalloc(sizeof(uint16_t) * num_questions_s);
    domains_s         = xmalloc(sizeof(char *) * num_questions_s);

    for (int i = 0; i < num_questions_s; i++) {
        domains_s[i] = (char *) default_domain_s;
        qtypes_s[i]  = default_qtype_s;
    }

    // This is xmap boilerplate. Why do I have to write this?
    dns_num_ports_s = conf->source_port_last - conf->source_port_first + 1;
    setup_qtype_str_map_s();

    if (conf->probe_args &&
        strlen(conf->probe_args) > 0) { // no parameters passed in. Use defaults
        char *c = strchr(conf->probe_args, ':');
        if (!c) {
            log_error("dnss", dnss_usage_error);
            return EXIT_FAILURE;
        }
        ++c;

        // label type
        if (strncasecmp(conf->probe_args, "raw", 3) == 0) {
            label_type_s = DNS_LTYPE_RAW;
            log_debug("dnss", "raw label prefix");
        } else if (strncasecmp(conf->probe_args, "time", 4) == 0) {
            label_type_s = DNS_LTYPE_TIME;
            log_debug("dnss", "time label prefix");
        } else if (strncasecmp(conf->probe_args, "random", 6) == 0) {
            label_type_s = DNS_LTYPE_RANDOM;
            log_debug("dnss", "random label prefix");
        } else if (strncasecmp(conf->probe_args, "str", 3) == 0) {
            label_type_s     = DNS_LTYPE_STR;
            conf->probe_args = c;
            c                = strchr(conf->probe_args, ':');
            if (!c) {
                log_error("dnss", dnss_usage_error);
                return EXIT_FAILURE;
            }
            label_len_s = c - conf->probe_args;
            label_s     = xmalloc(label_len_s);
            strncpy(label_s, conf->probe_args, label_len_s);
            ++c;
            log_debug("dnss", "label prefix: %s, len: %d", label_s,
                      label_len_s);
        } else if (strncasecmp(conf->probe_args, "dst-ip", 6) == 0) {
            label_type_s = DNS_LTYPE_SRCIP;
            log_debug("dnss", "dst-ip label prefix");
        } else {
            log_error("dnss", dnss_usage_error);
            return EXIT_FAILURE;
        }

        conf->probe_args = c;
        c                = strchr(conf->probe_args, ':');
        if (!c) {
            log_error("dnss", dnss_usage_error);
            return EXIT_FAILURE;
        }
        ++c;

        // recursive query
        if (strncasecmp(conf->probe_args, "recurse", 7) == 0) {
            recursive_s = 1;
        } else if (strncasecmp(conf->probe_args, "no-recurse", 10) == 0) {
            recursive_s = 0;
        } else {
            log_error("dnss", dnss_usage_error);
            return EXIT_FAILURE;
        }

        conf->probe_args = c;
        c                = strchr(conf->probe_args, ':');
        if (!c) {
            log_error("dnss", dnss_usage_error);
            return EXIT_FAILURE;
        }
        ++c;

        // input query
        if (strncasecmp(conf->probe_args, "text", 4) == 0) {
            if (load_question_from_str_s(c)) return EXIT_FAILURE;
        } else if (strncasecmp(conf->probe_args, "file", 4) == 0) {
            if (load_question_from_file_s(c)) return EXIT_FAILURE;
        } else {
            log_error("dnss", dnss_usage_error);
            return EXIT_FAILURE;
        }

        if (index_questions_s < num_questions_s) {
            log_error("dnss", "more probes than questions configured. Add "
                              "additional probes.");
            return EXIT_FAILURE;
        }
    }

    if (label_type_s == DNS_LTYPE_RAW || label_type_s == DNS_LTYPE_STR)
        return build_global_dns_packets_s(domains_s, num_questions_s);
    else
        return EXIT_SUCCESS;
}

static int dnss_global_cleanup(UNUSED struct state_conf *xconf,
                               UNUSED struct state_send *xsend,
                               UNUSED struct state_recv *xrecv) {
    if (dns_packets_s) {
        for (int i = 0; i < num_questions_s; i++) {
            if (dns_packets_s[i]) {
                free(dns_packets_s[i]);
            }
        }
        free(dns_packets_s);
    }
    dns_packets_s = NULL;

    if (qnames_s) {
        for (int i = 0; i < num_questions_s; i++) {
            if (qnames_s[i]) {
                free(qnames_s[i]);
            }
        }
        free(qnames_s);
    }
    qnames_s = NULL;

    if (dns_packet_lens_s) {
        free(dns_packet_lens_s);
    }

    if (qname_lens_s) {
        free(qname_lens_s);
    }

    if (qtypes_s) {
        free(qtypes_s);
    }

    free(label_s);

    return EXIT_SUCCESS;
}

int dnss_thread_init(void *buf, macaddr_t *src, macaddr_t *gw, void **arg_ptr) {
    memset(buf, 0, MAX_PACKET_SIZE);

    // Setup assuming num_questions_s == 0
    struct ether_header *eth_header = (struct ether_header *) buf;
    make_eth_header(eth_header, src, gw);

    struct ip *ip_header = (struct ip *) (&eth_header[1]);
    uint16_t   ip_len =
        sizeof(struct ip) + sizeof(struct udphdr) + dns_packet_lens_s[0];
    make_ip_header(ip_header, IPPROTO_UDP, ip_len);

    struct udphdr *udp_header = (struct udphdr *) (&ip_header[1]);
    uint16_t       udp_len    = sizeof(struct udphdr) + dns_packet_lens_s[0];
    make_udp_header(udp_header, udp_len);

    char *payload             = (char *) (&udp_header[1]);
    module_dnss.packet_length = sizeof(struct ether_header) +
                                sizeof(struct ip) + sizeof(struct udphdr) +
                                dns_packet_lens_s[0];
    assert(module_dnss.packet_length <= MAX_PACKET_SIZE);

    memcpy(payload, dns_packets_s[0], dns_packet_lens_s[0]);

    // Seed our random number generator with the global generator
    uint32_t   seed = aesrand_getword(xconf.aes);
    aesrand_t *aes  = aesrand_init_from_seed(seed);
    *arg_ptr        = aes;

    return EXIT_SUCCESS;
}

int dnss_make_packet(void *buf, size_t *buf_len, ipaddr_n_t *src_ip,
                     ipaddr_n_t *dst_ip, port_h_t dst_port, uint8_t ttl,
                     int probe_num, index_h_t index, void *arg) {
    struct ether_header *eth_header = (struct ether_header *) buf;
    struct ip           *ip_header  = (struct ip *) (&eth_header[1]);
    struct udphdr       *udp_header = (struct udphdr *) (&ip_header[1]);

    uint8_t validation[VALIDATE_BYTES];
    validate_gen(src_ip, dst_ip, dst_port, validation);

    port_h_t src_port = get_src_port(dns_num_ports_s, probe_num, validation);
    uint16_t dns_txid = get_dns_txid(validation);

    if (label_type_s == DNS_LTYPE_RAW || label_type_s == DNS_LTYPE_STR) {
        // For num_questions_s == 1, we handle this in per-thread init. Do less
        // work
        if (num_questions_s > 1) {
            uint16_t ip_len = sizeof(struct ip) + sizeof(struct udphdr) +
                              dns_packet_lens_s[index];
            make_ip_header(ip_header, IPPROTO_UDP, ip_len);

            uint16_t udp_len = sizeof(struct udphdr) + dns_packet_lens_s[index];
            make_udp_header(udp_header, udp_len);

            char *payload = (char *) (&udp_header[1]);
            *buf_len      = sizeof(struct ether_header) + sizeof(struct ip) +
                       sizeof(struct udphdr) + dns_packet_lens_s[index];

            assert(*buf_len <= MAX_PACKET_SIZE);

            memcpy(payload, dns_packets_s[index], dns_packet_lens_s[index]);
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

        switch (label_type_s) {
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
            dns_random_bytes_s(new_label, 8, charset_alpha_lower_s, 26, aes);
            new_label[8] = '\0';
            break;
        }
        case DNS_LTYPE_SRCIP: {
            //            snprintf(new_label, new_label_max_len,
            //            "%u-%u-%u-%u-%u-%u-%u",
            //                     probe_num + 1, dst_ip[0], dst_ip[1],
            //                     dst_ip[2], dst_ip[3], src_port, dns_txid);
            snprintf(new_label, new_label_max_len, "%02x%02x%02x%02x",
                     dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3]);
            new_label[strlen(new_label)] = '\0';
            break;
        }
        default:
            log_fatal("dnss", dnss_usage_error);
            return EXIT_FAILURE;
        }

        snprintf(new_domain, MAX_NAME_LENGTH, "%s-%s", new_label,
                 domains_s[index]);

        // dns packet
        free(qnames_s[index]);

        qname_lens_s[index] = domain_to_qname_s(&qnames_s[index], new_domain);
        dns_packet_lens_s[index] = sizeof(dns_header) + qname_lens_s[index] +
                                   sizeof(dns_question_tail);
        if (dns_packet_lens_s[index] > DNS_SEND_LEN) {
            log_fatal("dnss", "DNS packet bigger (%d) than our limit (%d)",
                      dns_packet_lens_s[index], DNS_SEND_LEN);
            return EXIT_FAILURE;
        }

        free(dns_packets_s[index]);

        dns_packets_s[index]            = xmalloc(dns_packet_lens_s[index]);
        dns_header        *dns_header_p = (dns_header *) dns_packets_s[index];
        char              *qname_p = dns_packets_s[index] + sizeof(dns_header);
        dns_question_tail *tail_p =
            (dns_question_tail *) (dns_packets_s[index] + sizeof(dns_header) +
                                   qname_lens_s[index]);

        // All other header fields should be 0. Except id, which we set
        // per thread. Please recurse as needed.
        dns_header_p->rd = recursive_s; // Is one bit. Don't need htons
        // We have 1 question
        dns_header_p->qdcount = htons(1);
        memcpy(qname_p, qnames_s[index], qname_lens_s[index]);
        // Set the qtype to what we passed from args
        tail_p->qtype = htons(qtypes_s[index]);
        // Set the qclass to The Internet (TM) (R) (I hope you're happy
        // now Zakir)
        tail_p->qclass = htons(0x01);
        // MAGIC NUMBER. Let's be honest. This is only ever 1

        // packet
        uint16_t ip_len = sizeof(struct ip) + sizeof(struct udphdr) +
                          dns_packet_lens_s[index];
        make_ip_header(ip_header, IPPROTO_UDP, ip_len);

        uint16_t udp_len = sizeof(struct udphdr) + dns_packet_lens_s[index];
        make_udp_header(udp_header, udp_len);

        char *payload = (char *) (&udp_header[1]);
        *buf_len      = sizeof(struct ether_header) + sizeof(struct ip) +
                   sizeof(struct udphdr) + dns_packet_lens_s[index];

        assert(*buf_len <= MAX_PACKET_SIZE);

        memcpy(payload, dns_packets_s[index], dns_packet_lens_s[index]);

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

void dnss_print_packet(FILE *fp, void *packet) {
    struct ether_header *eth_header   = (struct ether_header *) packet;
    struct ip           *ip_header    = (struct ip *) (&eth_header[1]);
    struct udphdr       *udp_header   = (struct udphdr *) (&ip_header[1]);
    dns_header          *dns_header_p = (dns_header *) (&udp_header[1]);

    uint16_t udp_len        = ntohs(udp_header->uh_ulen);
    char    *data           = ((char *) dns_header_p) + sizeof(dns_header);
    uint16_t data_len       = udp_len - sizeof(udp_header) - sizeof(dns_header);
    uint16_t bytes_consumed = 0;
    char    *question_name  = get_name_s(data, data_len, (char *) dns_header_p,
                                         udp_len, &bytes_consumed);
    char    *qname          = ((char *) dns_header_p) + sizeof(dns_header);
    int      qname_len      = strlen(qname) + 1;
    dns_question_tail *tail_p =
        (dns_question_tail *) ((char *) dns_header_p + sizeof(dns_header) +
                               qname_len);

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
    fprintf(fp,
            "DNS\n"
            "\tTransaction ID(2B)\t: 0x%04x\n"
            "\tFlags(2B)\t\t: 0x%04x\n"
            "\tQuestions(2B)\t\t: %u\n"
            "\tAnswer RRs(2B)\t\t: %u\n"
            "\tAuthority RRs(2B)\t: %u\n"
            "\tAdditional RRs(2B)\t: %u\n"
            "\tQueries\t\t\t: \n"
            "\t\t\t\t: %s: type %s, class IN\n",
            ntohs(dns_header_p->id), ntohs(dns_header_p->rd),
            ntohs(dns_header_p->qdcount), ntohs(dns_header_p->ancount),
            ntohs(dns_header_p->nscount), ntohs(dns_header_p->arcount),
            question_name, qtype_strs_s[qtype_qtype_to_strid_s[tail_p->qtype]]);
    fprintf(fp, "------------------------------------------------------\n");

    free(question_name);
}

int dnss_validate_packet(const struct ip *ip_hdr, uint32_t len,
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

        if (!check_dns_src_port(sport, dns_num_ports_s, validation)) {
            return PACKET_INVALID;
        }

        dns_header_p = (dns_header *) (&udp_header[1]);

        if (!check_dns_txid(dns_header_p->id, validation)) {
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
        uint16_t sport = ntohs(udp_inner_header->uh_sport);
        uint16_t dport = ntohs(udp_inner_header->uh_dport);

        if (!xconf.target_port_flag[dport]) {
            return PACKET_INVALID;
        }

        uint8_t validation[VALIDATE_BYTES];
        validate_gen((uint8_t *) &(ip_inner_header->ip_src.s_addr),
                     (uint8_t *) &(ip_inner_header->ip_dst.s_addr), dport,
                     validation);

        if (!check_dns_src_port(sport, dns_num_ports_s, validation)) {
            return PACKET_INVALID;
        }

        dns_header_p = (dns_header *) (&udp_inner_header[1]);

        if (!check_dns_txid(dns_header_p->id, validation)) {
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

    char              *qname     = ((char *) dns_header_p) + sizeof(dns_header);
    int                qname_len = strlen(qname) + 1;
    dns_question_tail *tail_p =
        (dns_question_tail *) ((char *) dns_header_p + sizeof(dns_header) +
                               qname_len);

    int   ip_type_domain_len = xconf.ipv46_bytes + 2 + strlen(qname);
    char *ip_type_domain     = xmalloc(ip_type_domain_len);
    memcpy(ip_type_domain, (char *) &(ip_hdr->ip_src.s_addr),
           xconf.ipv46_bytes);
    ip_type_domain[xconf.ipv46_bytes]     = (char) (tail_p->qtype >> 8u);
    ip_type_domain[xconf.ipv46_bytes + 1] = (char) (tail_p->qtype & 0xffu);
    memcpy(ip_type_domain + xconf.ipv46_bytes + 2, qname, strlen(qname));
    if (bloom_filter_check_string(&xrecv.bf, (const char *) ip_type_domain,
                                  ip_type_domain_len) == BLOOM_FAILURE) {
        bloom_filter_add_string(&xrecv.bf, (const char *) ip_type_domain,
                                ip_type_domain_len);
        *is_repeat = 0;
    }
    free(ip_type_domain);

    // Looks good.
    return PACKET_VALID;
}

void dnss_process_packet(const u_char *packet, uint32_t len, fieldset_t *fs,
                         UNUSED struct timespec ts) {
    struct ip *ip_header = (struct ip *) &packet[sizeof(struct ether_header)];
    if (ip_header->ip_p == IPPROTO_UDP) {
        struct udphdr *udp_header =
            (struct udphdr *) ((char *) ip_header + ip_header->ip_hl * 4);
        uint16_t udp_len = ntohs(udp_header->uh_ulen);

        dns_header *dns_header_p = (dns_header *) &udp_header[1];
        uint16_t    qr           = dns_header_p->qr;
        uint16_t    rcode        = dns_header_p->rcode;
        // Success: Has the right validation bits and the right Q
        // App success: has qr and rcode bits right
        // Any app level parsing issues: dns_parse_err

        // High level info
        fs_add_string(fs, "clas", (char *) "dns", 0);
        fs_add_bool(fs, "success", 1);
        fs_add_bool(fs, "app_success",
                    (qr == DNS_QR_ANSWER) && (rcode == DNS_RCODE_NOERR));

        // UDP info
        fs_add_uint64(fs, "sport", ntohs(udp_header->uh_sport));
        fs_add_uint64(fs, "dport", ntohs(udp_header->uh_dport));
        fs_add_uint64(fs, "udp_pkt_size", udp_len);

        // ICMP info
        fs_add_null(fs, "icmp_responder");
        fs_add_null(fs, "icmp_type");
        fs_add_null(fs, "icmp_code");
        fs_add_null(fs, "icmp_str");

        // DNS header
        fs_add_uint64(fs, "dns_id", ntohs(dns_header_p->id));
        fs_add_uint64(fs, "dns_rd", dns_header_p->rd);
        fs_add_uint64(fs, "dns_tc", dns_header_p->tc);
        fs_add_uint64(fs, "dns_aa", dns_header_p->aa);
        fs_add_uint64(fs, "dns_opcode", dns_header_p->opcode);
        fs_add_uint64(fs, "dns_qr", qr);
        fs_add_uint64(fs, "dns_rcode", rcode);
        fs_add_uint64(fs, "dns_cd", dns_header_p->cd);
        fs_add_uint64(fs, "dns_ad", dns_header_p->ad);
        fs_add_uint64(fs, "dns_z", dns_header_p->z);
        fs_add_uint64(fs, "dns_ra", dns_header_p->ra);
        fs_add_uint64(fs, "dns_qdcount", ntohs(dns_header_p->qdcount));
        fs_add_uint64(fs, "dns_ancount", ntohs(dns_header_p->ancount));
        fs_add_uint64(fs, "dns_nscount", ntohs(dns_header_p->nscount));
        fs_add_uint64(fs, "dns_arcount", ntohs(dns_header_p->arcount));

        // And now for the complicated part. Hierarchical data.
        char    *data     = ((char *) dns_header_p) + sizeof(dns_header);
        uint16_t data_len = udp_len - sizeof(udp_header) - sizeof(dns_header);
        bool     err      = 0;

        // Questions
        fieldset_t *list = fs_new_repeated_fieldset();
        for (int i = 0; i < ntohs(dns_header_p->qdcount) && !err; i++) {
            err = process_response_question_s(
                &data, &data_len, (char *) dns_header_p, udp_len, list);
        }
        fs_add_repeated(fs, "dns_questions", list);

        // Answers
        list = fs_new_repeated_fieldset();
        for (int i = 0; i < ntohs(dns_header_p->ancount) && !err; i++) {
            err = process_response_answer_s(
                &data, &data_len, (char *) dns_header_p, udp_len, list);
        }
        fs_add_repeated(fs, "dns_answers", list);

        // Authorities
        list = fs_new_repeated_fieldset();
        for (int i = 0; i < ntohs(dns_header_p->nscount) && !err; i++) {
            err = process_response_answer_s(
                &data, &data_len, (char *) dns_header_p, udp_len, list);
        }
        fs_add_repeated(fs, "dns_authorities", list);

        // Additionals
        list = fs_new_repeated_fieldset();
        for (int i = 0; i < ntohs(dns_header_p->arcount) && !err; i++) {
            err = process_response_answer_s(
                &data, &data_len, (char *) dns_header_p, udp_len, list);
        }
        fs_add_repeated(fs, "dns_additionals", list);

        // Do we have unconsumed data?
        fs_add_uint64(fs, "dns_unconsumed_bytes", data_len);
        if (data_len != 0) {
            err = 1;
        }

        // Did we parse OK?
        fs_add_uint64(fs, "dns_parse_err", err);

        // Now the raw stuff.
        fs_add_binary(fs, "raw_data", (udp_len - sizeof(struct udphdr)),
                      (void *) &udp_header[1], 0);

        return;
    } else if (ip_header->ip_p == IPPROTO_ICMP) {
        struct icmp *icmp_header =
            (struct icmp *) ((char *) ip_header + 4 * ip_header->ip_hl);
        struct ip *ip_inner_header =
            (struct ip *) ((char *) icmp_header + ICMP_UNREACH_HEADER_SIZE);

        // This is the packet we sent
        struct udphdr *udp_header =
            (struct udphdr *) ((char *) ip_inner_header +
                               4 * ip_inner_header->ip_hl);
        uint16_t udp_len = ntohs(udp_header->uh_ulen);

        // High level info
        fs_add_string(fs, "clas",
                      (char *) get_icmp_type_str(icmp_header->icmp_type), 0);
        fs_add_bool(fs, "success", 0);
        fs_add_bool(fs, "app_success", 0);

        // UDP info
        fs_add_uint64(fs, "sport", ntohs(udp_header->uh_sport));
        fs_add_uint64(fs, "dport", ntohs(udp_header->uh_dport));
        fs_add_uint64(fs, "udp_pkt_size", udp_len);

        // ICMP info
        // XXX This is legacy. not well tested.
        fs_add_string(fs, "icmp_responder",
                      make_ip_str(ip_header->ip_src.s_addr), 1);
        fs_add_uint64(fs, "icmp_type", icmp_header->icmp_type);
        fs_add_uint64(fs, "icmp_code", icmp_header->icmp_code);
        fs_add_string(fs, "icmp_str",
                      (char *) get_icmp_type_code_str(icmp_header->icmp_type,
                                                      icmp_header->icmp_code),
                      0);

        // DNS header
        fs_add_null(fs, "dns_id");
        fs_add_null(fs, "dns_rd");
        fs_add_null(fs, "dns_tc");
        fs_add_null(fs, "dns_aa");
        fs_add_null(fs, "dns_opcode");
        fs_add_null(fs, "dns_qr");
        fs_add_null(fs, "dns_rcode");
        fs_add_null(fs, "dns_cd");
        fs_add_null(fs, "dns_ad");
        fs_add_null(fs, "dns_z");
        fs_add_null(fs, "dns_ra");
        fs_add_null(fs, "dns_qdcount");
        fs_add_null(fs, "dns_ancount");
        fs_add_null(fs, "dns_nscount");
        fs_add_null(fs, "dns_arcount");

        fs_add_repeated(fs, "dns_questions", fs_new_repeated_fieldset());
        fs_add_repeated(fs, "dns_answers", fs_new_repeated_fieldset());
        fs_add_repeated(fs, "dns_authorities", fs_new_repeated_fieldset());
        fs_add_repeated(fs, "dns_additionals", fs_new_repeated_fieldset());

        fs_add_uint64(fs, "dns_unconsumed_bytes", 0);
        fs_add_uint64(fs, "dns_parse_err", 1);
        fs_add_binary(fs, "raw_data", len, (char *) packet, 0);

        return;
    } else {
        // This should not happen. Both the pcap filter and validate
        // packet prevent this.
        log_fatal("dnss", "Die. This can only happen if you "
                          "change the pcap filter and don't update the "
                          "process function.");
        return;
    }
}

static fielddef_t fields[] = {
    {.name = "clas", .type = "string", .desc = "packet protocol"},
    {.name = "success",
     .type = "bool",
     .desc = "Are the validation bits and question correct"},
    {.name = "app_success",
     .type = "bool",
     .desc = "Is the RA bit set with no error code?"},
    {.name = "sport", .type = "int", .desc = "UDP source port"},
    {.name = "dport", .type = "int", .desc = "UDP destination port"},
    {.name = "udp_pkt_size", .type = "int", .desc = "UDP packet length"},
    {.name = "icmp_responder",
     .type = "string",
     .desc = "Source IP of ICMP_UNREACH message"},
    {.name = "icmp_type", .type = "int", .desc = "icmp message type"},
    {.name = "icmp_code", .type = "int", .desc = "icmp message sub type code"},
    {.name = "icmp_str",
     .type = "string",
     .desc = "for icmp_unreach responses, "
             "the string version of icmp_code (e.g. network-unreach)"},
    {.name = "dns_id", .type = "int", .desc = "DNS transaction ID"},
    {.name = "dns_rd", .type = "int", .desc = "DNS recursion desired"},
    {.name = "dns_tc", .type = "int", .desc = "DNS packet truncated"},
    {.name = "dns_aa", .type = "int", .desc = "DNS authoritative answer"},
    {.name = "dns_opcode", .type = "int", .desc = "DNS opcode (query type)"},
    {.name = "dns_qr", .type = "int", .desc = "DNS query(0) or response (1)"},
    {.name = "dns_rcode", .type = "int", .desc = "DNS response code"},
    {.name = "dns_cd", .type = "int", .desc = "DNS checking disabled"},
    {.name = "dns_ad", .type = "int", .desc = "DNS authenticated data"},
    {.name = "dns_z", .type = "int", .desc = "DNS reserved"},
    {.name = "dns_ra", .type = "int", .desc = "DNS recursion available"},
    {.name = "dns_qdcount", .type = "int", .desc = "DNS number questions"},
    {.name = "dns_ancount", .type = "int", .desc = "DNS number answer RR's"},
    {.name = "dns_nscount",
     .type = "int",
     .desc = "DNS number NS RR's in authority section"},
    {.name = "dns_arcount",
     .type = "int",
     .desc = "DNS number additional RR's"},
    {.name = "dns_questions", .type = "repeated", .desc = "DNS question list"},
    {.name = "dns_answers", .type = "repeated", .desc = "DNS answer list"},
    {.name = "dns_authorities",
     .type = "repeated",
     .desc = "DNS authority list"},
    {.name = "dns_additionals",
     .type = "repeated",
     .desc = "DNS additional list"},
    {.name = "dns_parse_err",
     .type = "int",
     .desc = "Problem parsing the DNS response"},
    {.name = "dns_unconsumed_bytes",
     .type = "int",
     .desc = "Bytes left over when parsing"
             " the DNS response"},
    {.name = "raw_data", .type = "binary", .desc = "UDP payload"},
};

probe_module_t module_dnss = {
    .ipv46_flag      = 4,
    .name            = "dnss",
    .packet_length   = DNS_SEND_LEN + UDP_HEADER_LEN,
    .pcap_filter     = "udp || icmp",
    .pcap_snaplen    = PCAP_SNAPLEN,
    .port_args       = 1,
    .global_init     = &dnss_global_init,
    .thread_init     = &dnss_thread_init,
    .make_packet     = &dnss_make_packet,
    .print_packet    = &dnss_print_packet,
    .validate_packet = &dnss_validate_packet,
    .process_packet  = &dnss_process_packet,
    .close           = &dnss_global_cleanup,
    .output_type     = OUTPUT_TYPE_DYNAMIC,
    .fields          = fields,
    .numfields       = sizeof(fields) / sizeof(fields[0]),
    .helptext =
        "This module sends out DNS queries and parses responses with DNSSEC.\n"
        "By default, the module performs an A record lookup for www.qq.com.\n"
        "You can specify other queries using the --probe-args argument\n"
        "in the form: 'label_type:input_src:type,query;type,query', e.g.,\n"
        "'raw:text:A,qq.com;NS,qq.com'. The module supports\n"
        "sending the the following types of queries: A, NS, CNAME, SOA, PTR,\n"
        "MX, TXT, AAAA, RRSIG, and ANY. The module will accept and attempt\n"
        "to parse all DNS responses. There is currently support for parsing\n"
        "out full data from A, NS, CNAME, MX, TXT, and AAAA.\n"
        "Query format: label_type:recurse:input_src:type,query;type,query\n"
        "Any other types will be output in raw form.\n"
        "   label_type: raw, str, time, random, dst-ip\n"
        "       raw: do nothing to the query domain, e.g., qq.com\n"
        "       str: add the 'str' subdomain, e.g., www.qq.com\n"
        "       time: add the s+μs subdomain, e.g., 1620027515-568043.qq.com\n"
        "       random: add random subdomain, e.g., lefzwnrq.qq.com\n"
        "       dst-ip: add probe num + src ip, e.g., 1.1-2-3-4.qq.com\n"
        "   recurse: recurse, no-recurse\n"
        "       recurse: recursive query\n"
        "       no-recurse: non-recursive query\n"
        "   input_src: text, file\n"
        "       text: like A,qq.com;AAAA,qq.com\n"
        "       file: each line is like a text\n"
        "   type: A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, RRSIG, and ANY\n"
        "   query: A,qq.com;AAAA,qq.com\n"
        "Examples:\n"
        "   --probe-args=raw/time/random:recurse/no-recurse:text:type,query\n"
        "   --probe-args=raw/time/random:recurse/no-recurse:file:file_name\n"
        "   --probe-args=str:SomeText:recurse/no-recurse:text:type,query\n"
        "   --probe-args=str:SomeText:recurse/no-recurse:file:file_name\n"
        "   --probe-args=dst-ip:recurse/no-recurse:text:type,query\n"
        "   --probe-args=dst-ip:recurse/no-recurse:file:file_name"};
