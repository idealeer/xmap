XMap: The Internet Scanner
==========================
[![Build Status](https://travis-ci.com/idealeer/xmap.svg?token=Si5TyFph867jMev16gn1&branch=master)](https://travis-ci.com/idealeer/xmap)

XMap is a fast network scanner designed for performing Internet-wide IPv6 & IPv4 network research scanning.

XMap is reimplemented and improved thoroughly from ZMap and is fully compatible with ZMap, armed with the "5 minutes" probing speed and novel scanning techniques. XMap is capable of scanning the 32-bits address space in under 45 minutes. With a 10 gigE connection and [PF_RING](http://www.ntop.org/products/packet-capture/pf_ring/), XMap can scan the 32-bits address space in under 5 minutes. Moreover, leveraging the novel IPv6 scanning approach, XMap can discover the IPv6 Network Periphery fast. Furthermore, XMap can scan the network space randomly with any length and at any position, such as 2001:db8::/32-64 and 192.168.0.1/16-20. Besides, XMap can probe multiple ports simultaneously.

XMap operates on GNU/Linux, macOS, and BSD. XMap currently has implemented probe modules for ICMP Echo scans, TCP SYN scans, [UDP probes](https://github.com/idealeer/xmap/blob/master/examples/udp-probes/README), and **DNS scans (stateless, stateful, or address-spoofing)**.

With banner grab and TLS handshake tool, [ZGrab2](https://github.com/zmap/zgrab2), more involved scans could be performed.

Installation
------------

The latest stable release of XMap is version 2.0.1 and supports Linux, macOS, and BSD. We recommend installing XMap from HEAD rather than using a distro package manager (not supported yet).

**Instructions on building XMap from source** can be found in [INSTALL](https://github.com/idealeer/xmap/blob/master/INSTALL.md).

**Installing from [docker](https://hub.docker.com/r/liii/xmap)**: `docker pull liii/xmap:latest`

Usage
-----

A guide to using XMap can be found in our [GitHub Wiki](https://github.com/idealeer/xmap/wiki).

Simple commands and options to using XMap can be found in [USAGE](https://github.com/idealeer/xmap/blob/master/src/xmap.1.ronn).

Check how to use DNS probing modules in [Issue #11](https://github.com/idealeer/xmap/issues/11).

Watch the description video at [Pentester Academy TV](https://www.youtube.com/watch?v=wgdFham6P2Y).

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=idealeer/xmap&type=Date)](https://star-history.com/#idealeer/xmap&Date)

## Paper

- **\[DSN '21\]** **[Xiang Li](https://lixiang521.com/)**, [Baojun Liu](https://netsec.ccert.edu.cn/people/lbj20/), Xiaofeng Zheng, [Haixin Duan](https://netsec.ccert.edu.cn/people/duanhx/), [Qi Li](https://netsec.ccert.edu.cn/people/qli/), Youjun Huang. **[Fast IPv6 Network Periphery Discovery and Security Implications](https://lixiang521.com/publication/dsn21/).** In Proceedings of the 2021 IEEE/IFIP International Conference on Dependable Systems and Networks (**[DSN '21](http://dsn2021.ntu.edu.tw/)**). Taipei, Taiwan, June 21-24, 2021 (Virtually). [\[PDF\]](https://idealeer.github.io/publication/dsn21/dsn21-paper-li.pdf) [\[Slides\]](https://idealeer.github.io/publication/dsn21/dsn21-slides-li.pdf) [\[Video\]](https://www.youtube.com/watch?v=aMlo_91-RlY).

  ([Acceptance rate](https://dsn21.hotcrp.com/): 48/279=17.2%)

- **\[NDSS '23\]** **[Xiang Li](https://lixiang521.com/)**, [Baojun Liu](https://netsec.ccert.edu.cn/people/lbj20), [Xuesong Bai](https://faculty.sites.uci.edu/zhouli/research/), [Mingming Zhang](https://netsec.ccert.edu.cn/people/zmm18), [Qifan Zhang](https://faculty.sites.uci.edu/zhouli/research/), [Zhou Li](https://faculty.sites.uci.edu/zhouli/), [Haixin Duan](https://netsec.ccert.edu.cn/people/duanhx/), and [Qi Li](https://netsec.ccert.edu.cn/people/qli/). **[Ghost Domain Reloaded: Vulnerable Links in Domain Name Delegation and Revocation](https://lixiang521.com/publication/ndss23/).** In Proceedings of the 30th Annual Network and Distributed System Security Symposium (**[NDSS '23](https://www.ndss-symposium.org/ndss2023/)**). San Diego, California, 27 February – 3 March, 2023. [\[PDF\]](https://lixiang521.com/publication/ndss23/ndss23-li-phoenix.pdf) [\[Slides\]](https://lixiang521.com/publication/ndss23/ndss23-li-phoenix-slides.pdf) [\[Video\]]()

  (Acceptance rate: 94/581=16.2%, [**Acceptance rate in summer**](https://ndss23-summer.hotcrp.com/): 36/183=19.7%), [Acceptance rate in fall](https://ndss23-fall.hotcrp.com/): 58/398=14.6%)

  * Presented in [OARC 39](https://indico.dns-oarc.net/event/44/contributions/953/)
  * Presented in [ICANN DNS Symposium 2022](https://www.icann.org/ids-2022)
  * Presented in [Black Hat Asia 2023](https://www.blackhat.com/asia-23/briefings/schedule/index.html#phoenix-domain-attack-vulnerable-links-in-domain-name-delegation-and-revocation-31133)
  * Referenced by [RFC Draft: Delegation Revalidation by DNS Resolvers](https://datatracker.ietf.org/doc/draft-ietf-dnsop-ns-revalidation/)

- **\[USENIX Security '23\]** **[Xiang Li](https://lixiang521.com/)**, [Chaoyi Lu](https://netsec.ccert.edu.cn/eng/people/lcy17), [Baojun Liu](https://netsec.ccert.edu.cn/people/lbj20), [Qifan Zhang](https://faculty.sites.uci.edu/zhouli/research/), [Zhou Li](https://faculty.sites.uci.edu/zhouli/), [Haixin Duan](https://netsec.ccert.edu.cn/people/duanhx/), and [Qi Li](https://netsec.ccert.edu.cn/people/qli/). **[The Maginot Line: Attacking the Boundary of DNS Caching Protection](https://lixiang521.com/publication/security23/).** In Proceedings of the 32nd USENIX Security Symposium (**[USENIX Security '23](https://www.usenix.org/conference/usenixsecurity23/)**). Anaheim, California, August 9–11, 2023. [\[PDF\]](https://lixiang521.com/publication/security23/usenix23-li-maginot.pdf) [\[Slides\]](https://lixiang521.com/publication/security23/usenix23-li-slides.pdf) [\[Video\]]()

  (Acceptance rate: 422/1,444=29.2%, [**Acceptance rate in summer**](https://sec23summer.usenix.hotcrp.com/): 91/388=23.5%, [Acceptance rate in fall](https://sec23fall.usenix.hotcrp.com/): 155/531=29.2%), [Acceptance rate in winter](https://sec23winter.usenix.hotcrp.com/): 176/525=33.5%)

  * Presented in [Black Hat USA 2023](https://www.blackhat.com/us-23/briefings/schedule/index.html#maginotdns-attacking-the-boundary-of-dns-caching-protection-31901)
  * 60+ news coverage by media such as [BleepingComputer](https://www.bleepingcomputer.com/news/security/maginotdns-attacks-exploit-weak-checks-for-dns-cache-poisoning/) and [APNIC](https://blog.apnic.net/2023/09/26/maginotdns-attacking-the-boundary-of-dns-caching-protection/)
  * An Austria government [CERT daily report](https://www.govcert.gv.at/cert-tagesmeldungen.html?detail=entry-0)
  * A Sweden government [CERT weekly news](https://www.cert.se/2023/08/cert-se-s-veckobrev-v-33)
  * A Bournemouth University (BU) [CERT news](https://cert.bournemouth.ac.uk/maginotdns-attacks-exploit-weak-checks-for-dns-cache-poisoning/)
  * Presented in [SHUZIHUANYU Talk](https://cepoca.cn/lectureHall/lectureRoomDetail/?liveUid=af4d1df145b9e4defcfcef8c7c624c85)
  * Presented in [KANXUE 2023 SDC](https://zhuanlan.kanxue.com/article-24621.htm)
  * Presented in [Black Hat Webinar](https://www.blackhat.com/html/webcast/11022023.html)

- **\[CCS '23\]** [Wei Xu](https://netsec.ccert.edu.cn/people/xuw21)ⓘ, [**Xiang Li**](https://lixiang521.com/)ⓘ, [Chaoyi Lu](https://netsec.ccert.edu.cn/eng/people/lcy17), [Baojun Liu](https://netsec.ccert.edu.cn/people/baojun/), [Jia Zhang](https://netsec.ccert.edu.cn/people/jiazhang/), [Jianjun Chen](https://netsec.ccert.edu.cn/people/jianjun/), Tao Wan, and [Haixin Duan](https://netsec.ccert.edu.cn/people/duanhx/). [**TsuKing: Coordinating DNS Resolvers and Queries into Potent DoS Amplifiers**](https://lixiang521.com/publication/ccs23/). In Proceedings of the 2023 ACM SIGSAC Conference on Computer and Communications Security ([**CCS '23**](https://www.sigsac.org/ccs/CCS2023/)). Copenhagen, Denmark, November 26–30, 2023. [\[PDF\]](https://lixiang521.com/publication/ccs23/ccs23-xu-tsuking.pdf) [\[Slides\]]() [\[Video\]]()

  (Acceptance rate: ??%, **Acceptance rate in first round**: ??%, Acceptance rate in second round: ??%. ⓘ: Both authors contributed equally to the paper)

  * Presented in [OARC 41](https://indico.dns-oarc.net/event/47/contributions/1021/)
  * Presented in [Black Hat Europe 2023](https://www.blackhat.com/eu-23/briefings/schedule/index.html#tsuking-coordinating-dns-resolvers-and-queries-into-potent-dos-amplifiers-35441)

- **\[CCS '23\]** [Zhenrui Zhang](https://netsec.ccert.edu.cn/people/zzr21)ⓘ, Geng Hongⓘ, **[Xiang Li](https://lixiang521.com/)**, [Zhuoqun Fu](https://netsec.ccert.edu.cn/people/fzq20), [Jia Zhang](https://netsec.ccert.edu.cn/people/jiazhang/), [Mingxuan Liu](https://netsec.ccert.edu.cn/people/liumx18), [Chuhan Wang](https://netsec.ccert.edu.cn/people/wch), [Jianjun Chen](https://netsec.ccert.edu.cn/people/jianjun/), [Baojun Liu](https://netsec.ccert.edu.cn/people/baojun/), [Haixin Duan](https://netsec.ccert.edu.cn/people/duanhx/), [Chao Zhang](https://netsec.ccert.edu.cn/people/chaoz/), and Min Yang. **[Under the Dark: A Systematical Study of Stealthy Mining Pools (Ab)use in the Wild](https://lixiang521.com/publication/ccs23-2/)**. In Proceedings of the 2023 ACM SIGSAC Conference on Computer and Communications Security (**[CCS '23](https://www.sigsac.org/ccs/CCS2023/)**). Copenhagen, Denmark, November 26–30, 2023. [\[PDF\]](https://lixiang521.com/publication/ccs23/ccs23-zhang-under.pdf) [\[Slides\]]() [\[Video\]]()

  (Acceptance rate: ??%, **Acceptance rate in first round**: ??%, Acceptance rate in second round: ??%. ⓘ: Both authors contributed equally to the paper)

- **\[IMC '23\]** Fenglu Zhang, Yunyi Zhang, Baojun Liu, Eihal Alowaisheq, Lingyun Ying, **[Xiang Li](https://lixiang521.com/)**, Zaifeng Zhang, Ying Liu, Haixin Duan, Min Zhang. **[Wolf in Sheep's Clothing: Evaluating the Security Risks of the Undelegated Record on DNS Hosting Services](https://lixiang521.com/publication/imc23/)**. In Proceedings of ACM Internet Measurement Conference 2023 (**[IMC '23](https://conferences.sigcomm.org/imc/2023/)**). Montréal, Canada on October 24 - 26, 2023. [\[PDF\]]() [\[Slides\]]() [\[Video\]]()

  (Acceptance rate: 52/208=25.0%)

- **\[NDSS '24\]** Chuhan Wang, YASUHIRO KURANAGA, Yihang Wang, Mingming Zhang, Linkai Zheng, **[Xiang Li](https://lixiang521.com/)**, Jianjun Chen, Haixin Duan, Yanzhong Lin, Qingfeng Pan. **[BreakSPF: How Shared Infrastructures Magnify SPF Vulnerabilities Across the Internet](https://lixiang521.com/publication/ndss24/)**. In Proceedings of the 31st Annual Network and Distributed System Security Symposium (**[NDSS '24](https://www.ndss-symposium.org/ndss2024/)**). San Diego, California, 26 February – 1 March, 2024. [\[PDF\]]() [\[Slides\]]() [\[Video\]]()

  (Acceptance rate: 104/694=15.0%, **Acceptance rate in summer**: 41/211=19.4%, Acceptance rate in fall: 63/483=13.0%)

- **\[Oakland S&P '24\]** **[Xiang Li](https://lixiang521.com/)**, Wei Xu, Baojun Liu, Mingming Zhang, Zhou Li✉, Jia Zhang, Deliang Chang, Xiaofeng Zheng, Chuhan Wang, Jianjun Chen, Haixin Duan✉, and Qi Li✉. **[TuDoor Attack: Systematically Exploring and Exploiting Logic Vulnerabilities in DNS Response Pre-processing with Malformed Packets](https://lixiang521.com/publication/oakland24/)**. In Proceedings of 2024 IEEE Symposium on Security and Privacy (**[Oakland S&P '24](https://sp2024.ieee-security.org/cfpapers.html)**). San Francisco, California, May 20–23, 2024. [\[PDF\]](https://lixiang521.com/publication/oakland24/sp24spring-tudoor-li.pdf) [\[Slides\]](https://lixiang521.com/publication/oakland24/sp2024-tudoor-slides.pdf) [\[Poster\]](https://lixiang521.com/publication/oakland24/sp2024-tudoor-poster.pdf) [\[Video\]]()

  (Acceptance rate: ??%, **Acceptance rate in first circle**: ??%, Acceptance rate in second circle: ??%, Acceptance rate in third circle: ??%. ✉: Corresponding authors.)

  * Presented in [OARC 42](https://indico.dns-oarc.net/event/48/contributions/1039/)
  
  * Referenced by [RFC 9520: Negative Caching of DNS Resolution Failures](https://datatracker.ietf.org/doc/rfc9520/)

  * Presented in [GeekCon 2024 International](https://geekcon.top/)

  * Presented in [Black Hat USA 2024](https://www.blackhat.com/us-24/briefings/schedule/index.html#tudoor-attack-systematically-exploring-and-exploiting-logic-vulnerabilities-in-dns-response-pre-processing-with-malformed-packets-38986)

- **\[USENIX Security '24\]** [Qifan Zhang](https://faculty.sites.uci.edu/zhouli/research/), [Xuesong Bai](https://faculty.sites.uci.edu/zhouli/research/), **[Xiang Li](https://lixiang521.com/)**✉, [Haixin Duan](https://netsec.ccert.edu.cn/people/duanhx/), [Qi Li](https://netsec.ccert.edu.cn/people/qli/), and [Zhou Li](https://faculty.sites.uci.edu/zhouli/)✉. **[ResolverFuzz: Automated Discovery of DNS Resolver Vulnerabilities with Query-Response Fuzzing](https://lixiang521.com/publication/security24/).** In Proceedings of the 33rd USENIX Security Symposium (**[USENIX Security '24](https://www.usenix.org/conference/usenixsecurity24/)**). Philadelphia, Pennsylvania, August 14–16, 2024. [\[PDF\]](https://lixiang521.com/publication/security24/usenix24-zhang-resolverfuzz.pdf) [\[Slides\]]() [\[Video\]]()

  (Acceptance rate: ??%, [**Acceptance rate in summer**](https://sec24summer.usenix.hotcrp.com/): ??%, [Acceptance rate in fall](https://sec24fall.usenix.hotcrp.com/): ??%), [Acceptance rate in winter](https://sec24winter.usenix.hotcrp.com/): ??%. ✉: Both are corresponding authors.)

  * Presented in [SHUZIHUANYU Talk](https://cepoca.cn/lectureHall/lectureRoomDetail/?liveUid=af4d1df145b9e4defcfcef8c7c624c85)

- **\[NDSS '24\]** Mingxuan Liu, Yiming Zhang, **[Xiang Li](https://lixiang521.com/)**, Chaoyi Lu, Baojun Liu, Haixin Duan, Xiaofeng Zheng (2024). **[Understanding the Implementation and Security Implications of Protective DNS Services](http://lixiang521.com/publication/ndss24-1/)**. In Proceedings of the 31st Annual Network and Distributed System Security Symposium (**[NDSS '24](https://www.ndss-symposium.org/ndss2024/)**). San Diego, California, 26 February – 1 March, 2024. [\[PDF\]]() [\[Slides\]]() [\[Video\]]()

  (Acceptance rate: 104/694=15.0%, Acceptance rate in summer: 41/211=19.4%, **Acceptance rate in fall**: 63/483=13.0%)

- **\[Oakland S&P '24\]** **[Xiang Li](https://lixiang521.com/)**, Dashuai Wu, Haixin Duan, and Qi Li. **[DNSBomb: A New Practical-and-Powerful Pulsing DoS Attack Exploiting DNS Queries-and-Responses](https://lixiang521.com/publication/oakland24-2/)**. In Proceedings of 2024 IEEE Symposium on Security and Privacy (**[Oakland S&P '24](https://sp2024.ieee-security.org/cfpapers.html)**). San Francisco, California, May 20–23, 2024. [\[PDF\]](https://lixiang521.com/publication/oakland24-2/sp24summer-dnsbomb-li.pdf) [\[Slides\]](https://lixiang521.com/publication/oakland24-2/sp2024-dnsbomb-slides.pdf) [\[Poster\]](https://lixiang521.com/publication/oakland24-2/sp2024-dnsbomb-poster.pdf) [\[Video\]]()

  (Acceptance rate: ??%, Acceptance rate in first circle: ??%, **Acceptance rate in second circle**: ??%, Acceptance rate in third circle: ??%)

  * Presented in [GeekCon 2023](https://www.geekcon.top/2023/en/) (Second Prize)
  * 40+ news coverage by media, such as [The Hacker News](https://thehackernews.com/2024/05/researchers-warn-of-catddos-botnet-and.html), [Cyber Security News](https://cybersecuritynews.com/new-dos-attack-dnsbomb-exploiting/), and [dns-operation](https://www.mail-archive.com/dns-operations@lists.dns-oarc.net/msg08662.html)
  * Presented in [DNS OARC 43](https://indico.dns-oarc.net/event/51/)

- **\[NDSS '24\]** [Qifan Zhang](https://faculty.sites.uci.edu/zhouli/research/), [Xuesong Bai](https://faculty.sites.uci.edu/zhouli/research/), **[Xiang Li](https://lixiang521.com/)**✉, [Haixin Duan](https://netsec.ccert.edu.cn/people/duanhx/), [Qi Li](https://netsec.ccert.edu.cn/people/qli/), and [Zhou Li](https://faculty.sites.uci.edu/zhouli/)✉. **[Poster: ResolverFuzz: Automated Discovery of DNS Resolver Vulnerabilities with Query-Response Fuzzing](https://lixiang521.com/publication/ndss24-3/).** In Proceedings of the 31st Annual Network and Distributed System Security Symposium (**[NDSS '24](https://www.ndss-symposium.org/ndss2024/)**). San Diego, California, 26 February – 1 March, 2024. [\[PDF\]](https://lixiang521.com/publication/ndss24-3/ndss24-posters-30.pdf) [\[Slides\]]() [\[Video\]]()

  (Acceptance rate: 33/42=78.6%)

- **\[USENIX Security '24\]** Yunyi Zhang, Baojun Liu, Haixin Duan, Min Zhang, **[Xiang Li](https://lixiang521.com/)**, Fan Shi, Chengxi Xu, and Eihal Alowaisheq **[Rethinking the Security Threats of xxx DNS xxx](https://lixiang521.com/publication/security24-1/).** In Proceedings of the 33rd USENIX Security Symposium (**[USENIX Security '24](https://www.usenix.org/conference/usenixsecurity24/)**). Philadelphia, Pennsylvania, August 14–16, 2024. [\[PDF\]]() [\[Slides\]]() [\[Video\]]()

  (Acceptance rate: ??%, [Acceptance rate in summer](https://sec24summer.usenix.hotcrp.com/): ??%, [**Acceptance rate in fall**](https://sec24fall.usenix.hotcrp.com/): ??%), [Acceptance rate in winter](https://sec24winter.usenix.hotcrp.com/): ??%)

- [Other papers](https://scholar.google.com/scholar?oi=bibs&hl=en&cites=3737757293110831577) cite this tool or paper

License and Copyright
---------------------

XMap Copyright 2021-2024 Xiang Li from All-in-One Security and Privacy Lab (AOSP Lab) Nankai University

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License. You may obtain a copy of the
License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See LICENSE for the specific
language governing permissions and limitations under the License.
