# 1.0.0 04/02/2021
* Initial public release

# 1.0.1 12/03/2021
* XMap 1.0.1 Minor Release
* Fix Bugs:
  * Fix the memory leakage issue
* New Features:
  * Increase the batch number

# 1.0.2 12/06/2021
* XMap 1.0.2 Minor Release.
* Fix Bugs:
    * Prevent multiple definitions of global variable IID when GCC >= 10 (thanks for @juergenhoetzel)

# 1.0.3 12/29/2021
* XMap 1.0.3 Minor Release.
* Fix Bugs:
  * Fix multiple port scanning modules, enabling `-p 0-65535`

# 1.1.0 09/10/2022
* XMap 1.1.0 Major Release.
* New Features:
  * DNS scan modules enabled (base module: `-M dnsx`, query for software version: `-M dnsv`, spoofing source address: `-M dnsf`, and so on)

# 1.1.1 09/22/2022
* XMap 1.1.1 Minor Release.
* Fix Bugs:
  * Fix the memory leakage issue

# 1.1.2 09/23/2022
* XMap 1.1.2 Minor Release.
* Fix Bugs:
  * Fix the print issue of DNS modules

# 1.1.3 04/08/2023
* XMap 1.1.3 Minor Release.
* Fix Bugs:
  * Fix the source port checking issue of DNS modules

# 1.1.4 06/28/2023
* XMap 1.1.4 Minor Release.
* New feature:
  * increase the field number to store results

# 2.0.0 06/28/2023
* XMap 2.0.0 New Version Release.
* New feature:
  * new module `dnsx`                : enable DNS over IPv6
  * new module `dnsa`     (IPv4&IPv6): enable changing source port & TxID when sending multiple queries towards the same target <IP, port>
  * new module `dnsae`    (IPv4&IPv6): enable changing source port & TxID when sending multiple queries towards the same target <IP, port> with EDNS0=4,096
  * new module `dnsan`    (IPv4&IPv6): enable fixed source port & TxID when sending multiple queries towards the same target <IP, port>
  * new module `dnsane`   (IPv4&IPv6): enable fixed source port & TxID when sending multiple queries towards the same target <IP, port> with EDNS0=4,096
  * new module `dnsane16` (IPv4&IPv6): enable fixed source port & TxID when sending multiple queries towards the same target <IP, port> with EDNS0=65,535
  * new module `dnsai`    (IPv4&IPv6): enable changing TxID when sending multiple queries towards the same target <IP, port>
  * new module `dnsaie`   (IPv4&IPv6): enable changing TxID when sending multiple queries towards the same target <IP, port> with EDNS0=4,096
  * new module `dnsap`    (IPv4&IPv6): enable changing source port when sending multiple queries towards the same target <IP, port>
  * new module `dnsape`   (IPv4&IPv6): enable changing source port when sending multiple queries towards the same target <IP, port> with EDNS0=4,096
  * new module `dnsaf`    (IPv4&IPv6): enable changing source port & TxID when sending multiple queries towards the same target <IP, port> with fake source IP
  * new module `dnsafe`   (IPv4&IPv6): enable changing source port & TxID when sending multiple queries towards the same target <IP, port> with EDNS0=4,096 & source IP

# 2.0.1 01/05/2024
* XMap 2.0.1 Minor Release.
* Fix Bugs:
  * Fix the compiling issuein Mac M1-M3

# 2.0.2 08/06/2024
* XMap 2.0.2 Minor Release.
* Fix Bugs:
  * Fix Bugs [#23](https://github.com/idealeer/xmap/issues/23) & [#24](https://github.com/idealeer/xmap/issues/23), thanks [@xiota](https://github.com/xiota)

# 2.0.3 03/14/2025
* XMap 2.0.3 Minor Release.
* New feature:
  * new module `dnsc`                   : enable using fake src IP addresses from the same sub network from the target IP address
  * new module `dnscse`                 : enable using fake src IP addresses from the same sub network from the target IP address with EDNS0=4,096
  * new module `dnsaecs`     (IPv4&IPv6): enable using EDNS0=4,096 and ECS with fixed src_ip/24/0
  * new module `dnsaecsv`    (IPv4&IPv6): enable using EDNS0=4,096 and ECS with variable src_ip/24/0
  * new module `dnsacookiev` (IPv4&IPv6): enable using EDNS0=4,096 with variable cookie

# 2.0.4 07/05/2025
* XMap 2.0.4 Minor Release.
* Fix Function:
  * Change the recv socket to non-promiscuous

# 2.0.5 08/12/2025
* XMap 2.0.5 Minor Release.
* Fix Bugs:
  * Crash when using EDNS0
