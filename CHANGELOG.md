# 1.0.0 2021-04-02
* Initial public release

# 1.0.1 2021-12-03
* XMap 1.0.1 Minor Release
* Fix Bugs:
  * Fix the memory leakage issue
* New Features:
  * Increase the batch number

# 1.0.2 2021-12-06
* XMap 1.0.2 Minor Release.
* Fix Bugs:
    * Prevent multiple definitions of global variable IID when GCC >= 10 (thanks for @juergenhoetzel)

# 1.0.3 2021-12-29
* XMap 1.0.3 Minor Release.
* Fix Bugs:
  * Fix multiple port scanning modules, enabling `-p 0-65535`

# 1.1.0 2022-09-10
* XMap 1.1.0 Major Release.
* New Features:
  * DNS scan modules enabled (base module: `-M dnsx`, query for software version: `-M dnsv`, spoofing source address: `-M dnsf`, and so on)

# 1.1.1 2022-09-22
* XMap 1.1.1 Minor Release.
* Fix Bugs:
  * Fix the memory leakage issue
