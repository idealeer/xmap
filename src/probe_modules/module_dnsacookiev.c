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
