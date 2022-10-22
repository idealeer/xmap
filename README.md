XMap: The Internet Scanner
==========================
[![Build Status](https://travis-ci.com/idealeer/xmap.svg?token=Si5TyFph867jMev16gn1&branch=master)](https://travis-ci.com/idealeer/xmap)

XMap is a fast network scanner designed for performing Internet-wide IPv6 & IPv4 network research scanning.

XMap is reimplemented and improved thoroughly from ZMap and is fully compatible with ZMap, armed with the "5 minutes" probing speed and novel scanning techniques. XMap is capable of scanning the 32-bits address space in under 45 minutes. With a 10 gigE connection and [PF_RING](http://www.ntop.org/products/packet-capture/pf_ring/), XMap can scan the 32-bits address space in under 5 minutes. Moreover, leveraging the novel IPv6 scanning approach, XMap can discover the IPv6 Network Periphery fast. Furthermore, XMap can scan the network space randomly with any length and at any position, such as 2001:db8::/32-64 and 192.168.0.1/16-20. Besides, XMap can probe multiple ports simultaneously.

XMap operates on GNU/Linux, Mac OS, and BSD. XMap currently has implemented probe modules for ICMP Echo scans, TCP SYN scans, [UDP probes](https://github.com/idealeer/xmap/blob/master/examples/udp-probes/README), and **DNS scans (stateless, stateful, or address-spoofing)**.

With banner grab and TLS handshake tool, [ZGrab2](https://github.com/zmap/zgrab2), more involved scans could be performed.

Installation
------------

The latest stable release of XMap is version 1.1.2 and supports Linux, macOS, and BSD. We recommend installing XMap from HEAD rather than using a distro package manager (not supported yet).

**Instructions on building XMap from source** can be found in [INSTALL](https://github.com/idealeer/xmap/blob/master/INSTALL.md).

Usage
-----

A guide to using XMap can be found in our [GitHub Wiki](https://github.com/idealeer/xmap/wiki).

Simple commands and options to using XMap can be found in [USAGE](https://github.com/idealeer/xmap/blob/master/src/xmap.1.ronn).

Watch the description video at [Pentester Academy TV](https://www.youtube.com/watch?v=wgdFham6P2Y).

## Paper

- **\[DSN '21\]** **[Xiang Li](https://netsec.ccert.edu.cn/people/lx19)**, [Baojun Liu](https://netsec.ccert.edu.cn/people/lbj20/), Xiaofeng Zheng, [Haixin Duan](https://netsec.ccert.edu.cn/people/duanhx/), [Qi Li](https://netsec.ccert.edu.cn/people/qli/), Youjun Huang. **[Fast IPv6 Network Periphery Discovery and Security Implications](https://lixiang521.com/publication/dsn21/).** In Proceedings of the 2021 IEEE/IFIP International Conference on Dependable Systems and Networks (**[DSN '21](http://dsn2021.ntu.edu.tw/)**). Taipei, Taiwan, June 21-24, 2021 (Virtually). [\[PDF\]](https://idealeer.github.io/publication/dsn21/dsn21-paper-li.pdf) [\[Slides\]](https://idealeer.github.io/publication/dsn21/dsn21-slides-li.pdf) [\[Video\]](https://www.youtube.com/watch?v=aMlo_91-RlY).

  ([Acceptance rate](https://dsn21.hotcrp.com/): 48/279=17.2%).

- **\[NDSS '23\]** **[Xiang Li](https://netsec.ccert.edu.cn/people/lx19)**, [Baojun Liu](https://netsec.ccert.edu.cn/people/lbj20), [Xuesong Bai](https://faculty.sites.uci.edu/zhouli/research/), [Mingming Zhang](https://netsec.ccert.edu.cn/people/zmm18), [Qifan Zhang](https://faculty.sites.uci.edu/zhouli/research/), [Zhou Li](https://faculty.sites.uci.edu/zhouli/), [Haixin Duan](https://netsec.ccert.edu.cn/people/duanhx/), and [Qi Li](https://netsec.ccert.edu.cn/people/qli/). **[Ghost Domain Reloaded: Vulnerable Links in Domain Name Delegation and Revocation](https://lixiang521.com/publication/ndss23/).** In Proceedings of the 30th Annual Network and Distributed System Security Symposium (**[NDSS '23](https://www.ndss-symposium.org/ndss2023/)**). San Diego, California, 27 February – 3 March, 2023. [\[PDF\]]() [\[Slides\]]() [\[Video\]]()

  (Acceptance rate: 101/581=17.4%, [Acceptance rate in summer](https://ndss23-summer.hotcrp.com/): 36/183=19.7%), [Acceptance rate in fall](https://ndss23-fall.hotcrp.com/): 65/398=16.3%)

- **\[USENIX Security '23\]** **[Xiang Li](https://netsec.ccert.edu.cn/people/lx19)**, [Chaoyi Lu](https://netsec.ccert.edu.cn/eng/people/lcy17), [Baojun Liu](https://netsec.ccert.edu.cn/people/lbj20), [Qifan Zhang](https://faculty.sites.uci.edu/zhouli/research/), [Zhou Li](https://faculty.sites.uci.edu/zhouli/), [Haixin Duan](https://netsec.ccert.edu.cn/people/duanhx/), and [Qi Li](https://netsec.ccert.edu.cn/people/qli/). **[The Maginot Line: Attacking the Boundary of DNS Caching Protection](https://lixiang521.com/publication/security23/).** In Proceedings of the 32nd USENIX Security Symposium (**[USENIX Security '23](https://www.usenix.org/conference/usenixsecurity23/)**). Anaheim, California, August 9–11, 2023. [\[PDF\]]() [\[Slides\]]() [\[Video\]]()

  (Acceptance rate: ??%, [Acceptance rate in summer](https://sec23summer.usenix.hotcrp.com/): 82/402=20.4%, [Acceptance rate in fall](https://sec23fall.usenix.hotcrp.com/): ??%), [Acceptance rate in winter](https://sec23winter.usenix.hotcrp.com/): ??%)

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
