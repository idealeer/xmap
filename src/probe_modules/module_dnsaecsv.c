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
