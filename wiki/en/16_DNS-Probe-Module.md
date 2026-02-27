Unlike ZMap, in addition to providing ICMP, TCP SYN and UDP probe modules, we also offer a DNS scan module. This module is specifically designed to perform DNS-related queries and scans, enabling users to discover DNS servers, resolve domain names, and gather information about DNS configurations.
> Added in XMap v.2.0.0

* New feature:
  * new module `dnsx`                : enable DNS over IPv6
  * new module `dnsa`     (IPv4&IPv6): enable changing source port & TXID when sending multiple queries towards the same target <IP, port>
  * new module `dnsae`    (IPv4&IPv6): enable changing source port & TXID when sending multiple queries towards the same target <IP, port> with EDNS0=4096
  * new module `dnsan`    (IPv4&IPv6): enable fixed source port & TXID when sending multiple queries towards the same target <IP, port>
  * new module `dnsane`   (IPv4&IPv6): enable fixed source port & TXID when sending multiple queries towards the same target <IP, port> with EDNS0=4096
  * new module `dnsane16` (IPv4&IPv6): enable fixed source port & TXID when sending multiple queries towards the same target <IP, port> with EDNS0=65535
  * new module `dnsai`    (IPv4&IPv6): enable changing TXID when sending multiple queries towards the same target <IP, port>
  * new module `dnsaie`   (IPv4&IPv6): enable changing TXID when sending multiple queries towards the same target <IP, port> with EDNS0=4096
  * new module `dnsap`    (IPv4&IPv6): enable changing source port when sending multiple queries towards the same target <IP, port>
  * new module `dnsape`   (IPv4&IPv6): enable changing source port when sending multiple queries towards the same target <IP, port> with EDNS0=4096
  * new module `dnsaf`    (IPv4&IPv6): enable changing source port & TXID when sending multiple queries towards the same target <IP, port> with fake source IP
  * new module `dnsafe`   (IPv4&IPv6): enable changing source port & TXID when sending multiple queries towards the same target <IP, port> with EDNS0=4096 & source IP

Check how to use DNS probing modules in [Issue #11](https://github.com/idealeer/xmap/issues/11).