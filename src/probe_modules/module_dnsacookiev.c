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
