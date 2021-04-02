#ifndef XMAP_INCLUDES_H
#define XMAP_INCLUDES_H

#ifdef __APPLE__
#pragma GCC diagnostic ignored "-Wflexible-array-extensions"

#include <dnet.h>

#pragma GCC diagnostic warning "-Wflexible-array-extensions"
#endif

#ifndef __FAVOR_BSD
#define __FAVOR_BSD 2
#endif
#ifndef __USE_BSD
#define __USE_BSD
#endif

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/types.h>

#ifndef __APPLE__
#include <netinet/ip6.h>
#endif

#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#if defined(__NetBSD__)
#define ICMP_UNREACH_PRECEDENCE_CUTOFF ICMP_UNREACH_PREC_CUTOFF
#include <net/if_ether.h>
#else

#include <net/ethernet.h>

#endif

#include <arpa/inet.h>
#include <ifaddrs.h> // NOTE: net/if.h MUST be included BEFORE ifaddrs.h
#include <net/if.h>
#include <netdb.h>

#define MAC_ADDR_LEN ETHER_ADDR_LEN
#define UNUSED __attribute__((unused))

#endif // XMAP_INCLUDES_H
