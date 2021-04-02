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

#ifndef XMAP_GET_GATEWAY_BSD_H
#define XMAP_GET_GATEWAY_BSD_H

#ifdef XMAP_GET_GATEWAY_LINUX_H
#error "Don't include both get_gateway-bsd.h and get_gateway-linux.h"
#endif

#include <assert.h>
#include <errno.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) ||       \
    defined(__DragonFly__)
#if __GNUC__ < 4
#error "gcc version >= 4 is required"
#elif __GNUC_MINOR_ >= 6
#pragma GCC diagnostic ignored "-Wflexible-array-extensions"
#endif
#endif

#include "../lib/includes.h"
#include "../lib/logger.h"
#include "../lib/util.h"
#include "../lib/xalloc.h"

#define ROUNDUP(a)                                                             \
    ((a) > 0 ? (1 + (((a) -1) | (sizeof(int) - 1))) : sizeof(int))
#define UNUSED __attribute__((unused))
#define ZCPREFIX "zc:"
#define ZCPREFIX_LEN 3

// TODO: not support to get default gw's ipv6 address
static int _get_default_gw(uint8_t *gw_ip, char **iface) {
    char              buf[4096];
    struct rt_msghdr *rtm = (struct rt_msghdr *) &buf;
    memset(rtm, 0, sizeof(buf));
    int seq          = 0x00FF;
    rtm->rtm_msglen  = sizeof(buf);
    rtm->rtm_type    = RTM_GET;
    rtm->rtm_flags   = RTF_GATEWAY;
    rtm->rtm_version = RTM_VERSION;
    rtm->rtm_seq     = seq;
    rtm->rtm_addrs   = RTA_DST | RTA_IFP;
    rtm->rtm_pid     = getpid();

    int fd = socket(PF_ROUTE, SOCK_RAW, 0);
    assert(fd > 0);
    if (!write(fd, (char *) rtm, sizeof(buf))) {
        log_error("get_gateway-bsd", "unable to send route request");
        return EXIT_FAILURE;
    }

    size_t len;
    while (rtm->rtm_type == RTM_GET && (len = read(fd, rtm, sizeof(buf))) > 0) {
        if (len < (int) sizeof(*rtm)) {
            return (-1);
        }
        if (rtm->rtm_type == RTM_GET && rtm->rtm_pid == getpid() &&
            rtm->rtm_seq == seq) {
            if (rtm->rtm_errno) {
                errno = rtm->rtm_errno;
                return (-1);
            }
            break;
        }
    }

    struct sockaddr *sa = (struct sockaddr *) (rtm + 1);
    for (int i = 0; i < RTAX_MAX; i++) {
        if (rtm->rtm_addrs & (1 << i)) {
            if ((1 << i) == RTA_IFP) {
                struct sockaddr_dl *sdl = (struct sockaddr_dl *) sa;
                if (!sdl) {
                    log_error("get_gateway-bsd", "unable to retrieve gateway");
                    return EXIT_FAILURE;
                }
                char *_iface = xmalloc(sdl->sdl_nlen + 1);
                memcpy(_iface, sdl->sdl_data, sdl->sdl_nlen);
                _iface[sdl->sdl_nlen + 1] = 0;
                *iface                    = _iface;
            }
            if ((1 << i) == RTA_GATEWAY) {
                struct sockaddr_in *sin = (struct sockaddr_in *) sa;
                int                 j;
                for (j = 0; j < 4; j++)
                    gw_ip[j] = ((uint8_t *) &(sin->sin_addr.s_addr))[j];
            }
            // next element
            sa = (struct sockaddr *) (ROUNDUP(sa->sa_len) + (char *) sa);
        }
    }
    close(fd);

    return EXIT_SUCCESS;
}

char *get_default_iface(void) {
    uint8_t t[16];
    char *  retv = NULL;
    _get_default_gw(t, &retv);

    return retv;
}

int get_iface_ip(const char *iface_, uint8_t *ip, int ipv46_flag) {
    assert(iface_);

    const char *iface = iface_;
    if (!strncmp(iface_, ZCPREFIX, ZCPREFIX_LEN)) iface = iface_ + ZCPREFIX_LEN;

    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr)) {
        log_error(
            "get_gateway-linux",
            "unable able to retrieve IPv%d list of network interfaces %s: %s",
            ipv46_flag, iface, strerror(errno));
        return EXIT_FAILURE;
    }
    int af = 0;
    if (ipv46_flag == IPV4_FLAG)
        af = AF_INET;
    else if (ipv46_flag == IPV6_FLAG)
        af = AF_INET6;
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != af) {
            continue;
        }
        if (!strcmp(iface, ifa->ifa_name)) {
            switch (ipv46_flag) {
            case IPV4_FLAG: {
                struct sockaddr_in *sin = (struct sockaddr_in *) ifa->ifa_addr;
                int                 j;
                for (j = 0; j < 4; j++)
                    ip[j] = ((uint8_t *) &(sin->sin_addr.s_addr))[j];
                return EXIT_SUCCESS;
            }
            case IPV6_FLAG: {
                struct sockaddr_in6 *sin6 =
                    (struct sockaddr_in6 *) ifa->ifa_addr;
                uint8_t *ip6_addr = (uint8_t *) &(sin6->sin6_addr);
                if ((ip6_addr[0] >> 5u) != 0x01) continue; // global unicast
                int j;
                for (j = 0; j < 16; j++)
                    ip[j] = ip6_addr[j];
                return EXIT_SUCCESS;
            }
            default:
                break;
            }
        }
    }

    return EXIT_FAILURE;
}

int get_iface_hw_addr(const char *iface_, unsigned char *hw_mac) {
    const char *iface = iface_;
    if (!strncmp(iface_, ZCPREFIX, ZCPREFIX_LEN)) iface = iface_ + ZCPREFIX_LEN;

    eth_t *e = eth_open(iface);
    if (e) {
        eth_addr_t eth_addr;
        int        res = eth_get(e, &eth_addr);
        if (res == 0) {
            memcpy(hw_mac, eth_addr.data, ETHER_ADDR_LEN);
            return EXIT_SUCCESS;
        }
    }

    return EXIT_FAILURE;
}

// TODO: not support to get default gw's ipv6 address
int get_default_gw_ip(uint8_t *gw_ip, const char *iface) {
    char *_iface = NULL;
    _get_default_gw(gw_ip, &_iface);
    if (strcmp(iface, _iface) != 0) {
        log_error("get_gateway-bsd",
                  "interface specified (%s) does not match the interface of "
                  "the default gateway (%s). You will need to manually specify "
                  "the MAC address of your gateway.",
                  iface, _iface);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int get_hw_addr(const uint8_t *gw_ip_, UNUSED const char *iface,
                unsigned char *hw_mac) {
    struct in_addr * gw_ip = (struct in_addr *) gw_ip_;
    arp_t *          arp;
    struct arp_entry entry;

    if (!gw_ip || !hw_mac) {
        return EXIT_FAILURE;
    }

    if ((arp = arp_open()) == NULL) {
        log_error("get_gateway-bsd", "failed to open arp table");
        return EXIT_FAILURE;
    }

    // Convert gateway ip to dnet struct format
    memset(&entry, 0, sizeof(struct arp_entry));
    entry.arp_pa.addr_type = ADDR_TYPE_IP;
    entry.arp_pa.addr_bits = IP_ADDR_BITS;
    entry.arp_pa.addr_ip   = gw_ip->s_addr;

    if (arp_get(arp, &entry) < 0) {
        log_error("get_gateway-bsd", "failed to fetch arp entry");
        return EXIT_FAILURE;
    } else {
        memcpy(hw_mac, &entry.arp_ha.addr_eth, ETHER_ADDR_LEN);
    }
    arp_close(arp);

    return EXIT_SUCCESS;
}

#endif // XMAP_GET_GATEWAY_BSD_H
