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
 * Usage: xmap -p 53 --probe-module=dnsc --probe-args="raw:text:A,qq.com"
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
probe_module_t module_dnsc;
static int     dns_num_ports_c;

const char     default_domain_c[] = "www.qq.com";
const uint16_t default_qtype_c    = DNS_QTYPE_A;
const char    *dnsc_usage_error =
    "unknown DNS probe specification (expected "
    "raw/time/random:recurse/no-recurse:text:TYPE,QUESTION or "
    "raw/time/random:recurse/no-recurse:file:file_name or "
    "str:some_text:recurse/no-recurse:text:TYPE,QUESTION or "
    "str:some_text:recurse/no-recurse:file:file_name)";

const unsigned char *charset_alpha_lower_c =
    (unsigned char *) "abcdefghijklmnopqrstuvwxyz";

static char    **dns_packets_c;
static uint16_t *dns_packet_lens_c; // Not including udp header
static uint16_t *qname_lens_c;      // domain_len list
static char    **qnames_c;          // domain list for query
static uint16_t *qtypes_c;          // query_type list
static char    **domains_c;         // domain strs
static int       num_questions_c   = 0;
static int       index_questions_c = 0;

/* Array of qtypes_c we support. Jumping through some hops (1 level of
 * indirection) so the per-packet processing time is fast. Keep this in sync
 * with: dns_qtype (.h) qtype_strid_to_qtype_c (below) qtype_qtype_to_strid_c
 * (below, and setup_qtype_str_map_c())
 */
const char *qtype_strs_c[]   = {"A",    "NS",    "CNAME", "SOA",     "PTR",
                                "MX",   "TXT",   "AAAA",  "RRSIG",   "ANY",
                                "SIG",  "SRV",   "DS",    "DNSKEY",  "TLSA",
                                "SVCB", "HTTPS", "CAA",   "HTTPSSVC"};
const int   qtype_strs_len_c = 19;

const dns_qtype qtype_strid_to_qtype_c[] = {
    DNS_QTYPE_A,     DNS_QTYPE_NS,     DNS_QTYPE_CNAME,   DNS_QTYPE_SOA,
    DNS_QTYPE_PTR,   DNS_QTYPE_MX,     DNS_QTYPE_TXT,     DNS_QTYPE_AAAA,
    DNS_QTYPE_RRSIG, DNS_QTYPE_ALL,    DNS_QTYPE_SIG,     DNS_QTYPE_SRV,
    DNS_QTYPE_DS,    DNS_QTYPE_DNSKEY, DNS_QTYPE_TLSA,    DNS_QTYPE_SVCB,
    DNS_QTYPE_HTTPS, DNS_QTYPE_CAA,    DNS_QTYPE_HTTPSSVC};

int8_t qtype_qtype_to_strid_c[65536] = {BAD_QTYPE_VAL};

void setup_qtype_str_map_c() {
    qtype_qtype_to_strid_c[DNS_QTYPE_A]        = 0;
    qtype_qtype_to_strid_c[DNS_QTYPE_NS]       = 1;
    qtype_qtype_to_strid_c[DNS_QTYPE_CNAME]    = 2;
    qtype_qtype_to_strid_c[DNS_QTYPE_SOA]      = 3;
    qtype_qtype_to_strid_c[DNS_QTYPE_PTR]      = 4;
    qtype_qtype_to_strid_c[DNS_QTYPE_MX]       = 5;
    qtype_qtype_to_strid_c[DNS_QTYPE_TXT]      = 6;
    qtype_qtype_to_strid_c[DNS_QTYPE_AAAA]     = 7;
    qtype_qtype_to_strid_c[DNS_QTYPE_RRSIG]    = 8;
    qtype_qtype_to_strid_c[DNS_QTYPE_ALL]      = 9;
    qtype_qtype_to_strid_c[DNS_QTYPE_SIG]      = 10;
    qtype_qtype_to_strid_c[DNS_QTYPE_SRV]      = 11;
    qtype_qtype_to_strid_c[DNS_QTYPE_DS]       = 12;
    qtype_qtype_to_strid_c[DNS_QTYPE_DNSKEY]   = 13;
    qtype_qtype_to_strid_c[DNS_QTYPE_TLSA]     = 14;
    qtype_qtype_to_strid_c[DNS_QTYPE_SVCB]     = 15;
    qtype_qtype_to_strid_c[DNS_QTYPE_HTTPS]    = 16;
    qtype_qtype_to_strid_c[DNS_QTYPE_CAA]      = 17;
    qtype_qtype_to_strid_c[DNS_QTYPE_HTTPSSVC] = 18;
}

static uint16_t qtype_str_to_code_c(const char *str) {
    for (int i = 0; i < qtype_strs_len_c; i++) {
        if (strcmp(qtype_strs_c[i], str) == 0) return qtype_strid_to_qtype_c[i];
    }

    return 0;
}

static char    *label_c      = NULL;
static uint16_t label_len_c  = 0;
static uint16_t label_type_c = DNS_LTYPE_RAW;
static uint16_t recursive_c  = 1;

static uint16_t domain_to_qname_c(char **qname_handle, const char *domain) {
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

static int build_global_dns_packets_c(char **domains, int num_domains) {
    for (int i = 0; i < num_domains; i++) {
        qname_lens_c[i] = domain_to_qname_c(&qnames_c[i], domains[i]);
        if (domains[i] != (char *) default_domain_c) {
            free(domains[i]);
        }
        dns_packet_lens_c[i] =
            sizeof(dns_header) + qname_lens_c[i] + sizeof(dns_question_tail);
        if (dns_packet_lens_c[i] > DNS_SEND_LEN) {
            log_fatal("dnsc", "DNS packet bigger (%d) than our limit (%d)",
                      dns_packet_lens_c[i], DNS_SEND_LEN);
            return EXIT_FAILURE;
        }

        dns_packets_c[i]                = xmalloc(dns_packet_lens_c[i]);
        dns_header        *dns_header_p = (dns_header *) dns_packets_c[i];
        char              *qname_p      = dns_packets_c[i] + sizeof(dns_header);
        dns_question_tail *tail_p =
            (dns_question_tail *) (dns_packets_c[i] + sizeof(dns_header) +
                                   qname_lens_c[i]);

        // All other header fields should be 0. Except id, which we set
        // per thread. Please recurse as needed.
        dns_header_p->rd = recursive_c; // Is one bit. Don't need htons
        // We have 1 question
        dns_header_p->qdcount = htons(1);
        memcpy(qname_p, qnames_c[i], qname_lens_c[i]);
        // Set the qtype to what we passed from args
        tail_p->qtype = htons(qtypes_c[i]);
        // Set the qclass to The Internet (TM) (R) (I hope you're happy
        // now Zakir)
        tail_p->qclass = htons(0x01);
        // MAGIC NUMBER. Let's be honest. This is only ever 1
    }

    return EXIT_SUCCESS;
}

static uint16_t get_name_helper_c(const char *data, uint16_t data_len,
                                  const char *payload, uint16_t payload_len,
                                  char *name, uint16_t name_len,
                                  uint16_t recursion_level) {
    log_trace("dnsc",
              "_get_name_helper IN, datalen: %d namelen: %d recusion: %d",
              data_len, name_len, recursion_level);
    if (data_len == 0 || name_len == 0 || payload_len == 0) {
        log_trace("dnsc",
                  "_get_name_helper OUT, err. 0 length field. datalen %d "
                  "namelen %d payloadlen %d",
                  data_len, name_len, payload_len);
        return 0;
    }
    if (recursion_level > MAX_LABEL_RECURSION) {
        log_trace("dnsc", "_get_name_helper OUT. ERR, MAX RECUSION");
        return 0;
    }

    uint16_t bytes_consumed = 0;
    // The start of data is either a sequence of labels or a ptr.
    while (data_len > 0) {
        uint8_t byte = data[0];
        // Is this a pointer?
        if (byte >= 0xc0) {
            log_trace("dnsc", "_get_name_helper, ptr encountered");
            // Do we have enough bytes to check ahead?
            if (data_len < 2) {
                log_trace("dnsc", "_get_name_helper OUT. ptr byte encountered. "
                                  "No offset. ERR.");
                return 0;
            }
            // No. ntohs isn't needed here. It's because of
            // the upper 2 bits indicating a pointer.
            uint16_t offset = ((byte & 0x03) << 8) | (uint8_t) data[1];
            log_trace("dnsc", "_get_name_helper. ptr offset 0x%x", offset);
            if (offset >= payload_len) {
                log_trace(
                    "dnsc",
                    "_get_name_helper OUT. offset exceeded payload len %d ERR",
                    payload_len);
                return 0;
            }

            // We need to add a dot if we are:
            // -- Not first level recursion.
            // -- have consumed bytes
            if (recursion_level > 0 || bytes_consumed > 0) {

                if (name_len < 1) {
                    log_warn("dnsc", "Exceeded static name field allocation.");
                    return 0;
                }

                name[0] = '.';
                name++;
                name_len--;
            }

            uint16_t rec_bytes_consumed = get_name_helper_c(
                payload + offset, payload_len - offset, payload, payload_len,
                name, name_len, recursion_level + 1);
            // We are done so don't bother to increment the
            // pointers.
            if (rec_bytes_consumed == 0) {
                log_trace("dnsc", "_get_name_helper OUT. rec level %d failed",
                          recursion_level);
                return 0;
            } else {
                bytes_consumed += 2;
                log_trace("dnsc",
                          "_get_name_helper OUT. rec level %d success. %d rec "
                          "bytes consumed. %d bytes consumed.",
                          recursion_level, rec_bytes_consumed, bytes_consumed);
                return bytes_consumed;
            }
        } else if (byte == '\0') {
            // don't bother with pointer incrementation. We're done.
            bytes_consumed += 1;
            log_trace("dnsc",
                      "_get_name_helper OUT. rec level %d success. %d bytes "
                      "consumed.",
                      recursion_level, bytes_consumed);
            return bytes_consumed;
        } else {
            log_trace("dnsc", "_get_name_helper, segment 0x%hx encountered",
                      byte);
            // We've now consumed a byte.
            ++data;
            --data_len;
            // Mark byte consumed after we check for first
            // iteration. Do we have enough data left (must have
            // null byte too)?
            if ((byte + 1) > data_len) {
                log_trace("dnsc", "_get_name_helper OUT. ERR. Not enough data "
                                  "for segment %hd");
                return 0;
            }
            // If we've consumed any bytes and are in a label, we're
            // in a label chain. We need to add a dot.
            if (bytes_consumed > 0) {

                if (name_len < 1) {
                    log_warn("dnsc", "Exceeded static name field allocation.");
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
                log_warn("dnsc", "Exceeded static name field allocation.");
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
static char *get_name_c(const char *data, uint16_t data_len,
                        const char *payload, uint16_t payload_len,
                        uint16_t *bytes_consumed) {
    log_trace("dnsc", "call to get_name_c, data_len: %d", data_len);
    char *name      = xmalloc(MAX_NAME_LENGTH);
    *bytes_consumed = get_name_helper_c(data, data_len, payload, payload_len,
                                        name, MAX_NAME_LENGTH - 1, 0);
    if (*bytes_consumed == 0) {
        free(name);
        return NULL;
    }
    // Our memset ensured null byte.
    assert(name[MAX_NAME_LENGTH - 1] == '\0');
    log_trace("dnsc",
              "return success from get_name_c, bytes_consumed: %d, string: %s",
              *bytes_consumed, name);

    return name;
}

static bool process_response_question_c(char **data, uint16_t *data_len,
                                        const char *payload,
                                        uint16_t    payload_len,
                                        fieldset_t *list) {
    // Payload is the start of the DNS packet, including header
    // data is handle to the start of this RR
    // data_len is a pointer to the how much total data we have to work
    // with. This is awful. I'm bad and should feel bad.
    uint16_t bytes_consumed = 0;
    char    *question_name =
        get_name_c(*data, *data_len, payload, payload_len, &bytes_consumed);
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

    if (qtype > MAX_QTYPE || qtype_qtype_to_strid_c[qtype] == BAD_QTYPE_VAL) {
        fs_add_string(qfs, "qtype_str", (char *) BAD_QTYPE_STR, 0);
    } else {
        // I've written worse things than this 3rd arg. But I want to be
        // fast.
        fs_add_string(qfs, "qtype_str",
                      (char *) qtype_strs_c[qtype_qtype_to_strid_c[qtype]], 0);
    }

    fs_add_uint64(qfs, "qclass", qclass);
    // Now we're adding the new fs to the list.
    fs_add_fieldset(list, NULL, qfs);
    // Now update the pointers.
    *data     = *data + bytes_consumed + sizeof(dns_question_tail);
    *data_len = *data_len - bytes_consumed - sizeof(dns_question_tail);

    return 0;
}

static bool process_response_answer_c(char **data, uint16_t *data_len,
                                      const char *payload,
                                      uint16_t payload_len, fieldset_t *list) {
    log_trace("dnsc", "call to process_response_answer_c, data_len: %d",
              *data_len);
    // Payload is the start of the DNS packet, including header
    // data is handle to the start of this RR
    // data_len is a pointer to the how much total data we have to work
    // with. This is awful. I'm bad and should feel bad.
    uint16_t bytes_consumed = 0;
    char    *answer_name =
        get_name_c(*data, *data_len, payload, payload_len, &bytes_consumed);
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
    if (type > MAX_QTYPE || qtype_qtype_to_strid_c[type] == BAD_QTYPE_VAL) {
        fs_add_string(afs, "type_str", (char *) BAD_QTYPE_STR, 0);
    } else {
        // I've written worse things than this 3rd arg. But I want to be
        // fast.
        fs_add_string(afs, "type_str",
                      (char *) qtype_strs_c[qtype_qtype_to_strid_c[type]], 0);
    }
    fs_add_uint64(afs, "class", class);
    fs_add_uint64(afs, "ttl", ttl);
    fs_add_uint64(afs, "rdlength", rdlength);

    // XXX Fill this out for the other types we care about.
    if (type == DNS_QTYPE_NS || type == DNS_QTYPE_CNAME) {
        uint16_t rdata_bytes_consumed = 0;
        char    *rdata_name = get_name_c(rdata, rdlength, payload, payload_len,
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
            char *rdata_name = get_name_c(rdata + 2, rdlength - 2, payload,
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
            log_warn("dnsc", "TXT record with wrong TXT len. Not processing.");
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
            log_warn("dnsc", "A record with IP of length %d. Not processing.",
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
            log_warn("dnsc",
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
                "dnsc",
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
    } else {
        fs_add_uint64(afs, "rdata_is_parsed", 0);
        fs_add_binary(afs, "rdata", rdlength, rdata, 0);
    }
    // Now we're adding the new fs to the list.
    fs_add_fieldset(list, NULL, afs);
    // Now update the pointers.
    *data     = *data + bytes_consumed + sizeof(dns_answer_tail) + rdlength;
    *data_len = *data_len - bytes_consumed - sizeof(dns_answer_tail) - rdlength;
    log_trace("dnsc",
              "return success from process_response_answer_c, data_len: %d",
              *data_len);

    return 0;
}

static int load_question_from_str_c(const char *type_q_str) {
    char *probe_q_delimiter_p   = NULL;
    char *probe_arg_delimiter_p = NULL;
    while (1) {
        probe_q_delimiter_p   = strchr(type_q_str, ',');
        probe_arg_delimiter_p = strchr(type_q_str, ';');

        if (probe_q_delimiter_p == NULL) return EXIT_SUCCESS;

        if (probe_q_delimiter_p == type_q_str ||
            type_q_str + strlen(type_q_str) == (probe_q_delimiter_p + 1)) {
            log_error("dnsc", dnsc_usage_error);
            return EXIT_FAILURE;
        }

        if (index_questions_c >= num_questions_c) {
            log_error("dnsc", "less probes than questions configured. Add "
                              "additional questions.");
            return EXIT_FAILURE;
        }
