XMap: The Internet Scanner
==========================
[![Build Status](https://travis-ci.com/idealeer/xmap.svg?token=Si5TyFph867jMev16gn1&branch=master)](https://travis-ci.com/idealeer/xmap)

XMap is a fast network scanner designed for performing Internet-wide IPv6 & IPv4 network research scanning.

XMap is reimplemented and improved thoroughly from ZMap and is fully compatible with ZMap, armed with the "5 minutes" probing speed and novel scanning techniques. XMap is capable of scanning the 32-bits address space in under 45 minutes. With a 10 gigE connection and [PF_RING](http://www.ntop.org/products/packet-capture/pf_ring/), XMap can scan the 32-bits address space in under 5 minutes. Moreover, leveraging the novel IPv6 scanning approach, XMap can discover the IPv6 Network Periphery fast. Furthermore, XMap can scan the network space randomly with any length and at any position, such as 2001:db8::/32-64 and 192.168.0.1/16-20. Besides, XMap can probe multiple ports simultaneously.

XMap operates on GNU/Linux, Mac OS, and BSD. XMap currently has implemented probe modules for ICMP Echo scans, TCP SYN scans, and [UDP probes](https://github.com/idealeer/xmap/blob/master/examples/udp-probes/README).

With banner grab and TLS handshake tool, [ZGrab2](https://github.com/zmap/zgrab2), more involved scans could be performed.

Installation
------------

The latest stable release of XMap is version 1.0.3 and supports Linux, macOS, and BSD. We recommend installing XMap from HEAD rather than using a distro package manager (not supported yet).

**Instructions on building XMap from source** can be found in [INSTALL](https://github.com/idealeer/xmap/blob/master/INSTALL.md).

Usage
-----

A guide to using XMap can be found in our [GitHub Wiki](https://github.com/idealeer/xmap/wiki).

Simple commands and options to using XMap can be found in [USAGE](https://github.com/idealeer/xmap/blob/master/src/xmap.1.ronn).

Watch the description video at [Pentester Academy TV](https://www.youtube.com/watch?v=wgdFham6P2Y).

## Paper

Fast IPv6 Network Periphery Discovery and Security Implications.

**Abstract.** Numerous measurement researches have been performed to discover the IPv4 network security issues by leveraging the fast Internet-wide scanning techniques. However, IPv6 brings the 128-bits address space and renders brute-force network scanning impractical. Although significant efforts have been dedicated to enumerating active IPv6 hosts, limited by technique efficiency and probing accuracy, large-scale empirical measurement studies under the increasing IPv6 networks are infeasible now. 

To fill this research gap, by leveraging the extensively adopted IPv6 address allocation strategy, we propose a novel IPv6 network periphery discovery approach. Specifically, *XMap*, a fast network scanner, is developed to find the periphery, such as a home router. We evaluate it on twelve prominent Internet service providers and harvest *52M* active peripheries. Grounded on these found devices, we explore IPv6 network risks of the unintended exposed security services and the flawed traffic routing strategies. First, we demonstrate the unintended exposed security services in IPv6 networks, such as DNS, and HTTP, have become emerging security risks by analyzing *4.7M* peripheries. Second, by inspecting the periphery’s packet routing strategies, we present the flawed implementations of IPv6 routing protocol affecting *5.8M* router devices. Attackers can exploit this common vulnerability to conduct effective routing loop attacks, inducing DoS to the ISP’s and home routers with an amplification factor of >*200*. We responsibly disclose those issues to all involved vendors and ASes and discuss mitigation solutions. Our research results indicate that the security community should revisit IPv6 network strategies immediately.

**Authors.** [Xiang Li](https://netsec.ccert.edu.cn/people/lx19), [Baojun Liu](https://netsec.ccert.edu.cn/people/lbj20/), Xiaofeng Zheng, [Haixin Duan](https://netsec.ccert.edu.cn/people/duanhx/), [Qi Li](https://netsec.ccert.edu.cn/people/qli/), Youjun Huang.

**Conference.** Proceedings of the 2021 IEEE/IFIP International Conference on Dependable Systems and Networks (DSN '21) 

**Paper.** [[PDF]](https://idealeer.github.io/publication/dsn21/dsn21-paper-li.pdf), [[Slides]](https://idealeer.github.io/publication/dsn21/dsn21-slides-li.pdf) and [[Video]](https://www.youtube.com/watch?v=aMlo_91-RlY).

**CNVD/CVE.** [[Lists]](https://idealeer.github.io/publication/dsn21/).

License and Copyright
---------------------

XMap Copyright 2021 Xiang Li from Network and Information Security Lab Tsinghua University

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License. You may obtain a copy of the
License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See LICENSE for the specific
language governing permissions and limitations under the License.
