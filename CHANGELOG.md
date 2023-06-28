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
