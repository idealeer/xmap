Since XMap is fully compatible with ZMap, thanks to the [ZMap's Getting Started Guide](https://github.com/zmap/zmap/wiki/Getting-Started-Guide), you already have a reference for quickly getting started with XMap. However, XMap is reimplemented and improved thoroughly from ZMap, and its usage differs from ZMap in some aspects. Next, we will focus on **IPv6** and provide you with a new guide.

## Installation
XMap is available through many common package managers, or you can compile from source. Full instructions are available [here](https://github.com/idealeer/xmap/blob/master/INSTALL.md). To check that you've installed everything correctly, run with `xmap --version`. We recommend using version 2.0.2 currently.

## ⚠️ Warning on Scanning Rate

By default, XMap will scan as fast as your network card allows. Since XMap directly composes Ethernet frames, it doesn't have any concept of congestion control (as you'd get by default with TCP).
This has two potential pitfalls:

* _Target Network DoS:_ If you scan a small subnet (e.g., a single organization) at a very high rate, you can easily accidentally DOS the destination network. We recommend *not* running scans at 1Gbps or faster unless you're scanning the full Internet. You'll have more success running at a rate closer under 10Mbps if you're scanning a single network. 

* _Source Network overload:_ Regardless of how many hosts you are scanning, you also risk the possibility of overloading your _source_ network (i.e., the network you're using to scan the Internet). Many pieces of network equipment that advertise only _throughput_ numbers (e.g., 1Gbps) cannot handle that full speed using minimum sized packets (since this requires handling the theoretical maximum packet per second rate of the equipment.) 

To reduce the impact on destination networks, XMap scans in-scope IP addresses in a random order. This means the load in a given time period placed on a target subnet depends both on XMap's rate of scanning and the size of the target range.

⚠️**Note:** We equip XMap with address random generation and exclusion. The key module is the **address generation module**, providing an all address space random permutation. Unlike ZMap, which can only permute the rear segment of the 32-bit IPv4 address, XMap could **permute all the address space with any length and at any position**, such as the space between the 20th and 25th bit of `2001:db8::/20-25` and `192.168.0.0/20-25`. We leverage GMP to implement the address generation module.Nonetheless, GMP just provides a big integer library, and all the related data structures and functions should be **rewritten**, including the tree structure to present addresses, the blocklist structure to ignore addresses, the cyclic module to form a succeeding address, and the expression structure to filter specific fields. In addition, the IID generation module is created to fill up the left bits behind the prefix, and all related codes are improved to support IPv6.

## ⚠️ Warning on Threads
The xmap CLI offers the ability to set the number of sending threads with `-T (--sender-threads=num)`. A thread for receiving packets and for monitoring scan progress are also created, so the number of threads xmap requires is `2 + T` where T is the number of threads you set (1 by default). 

As a general rule, we recommend sticking to <= 8 sending threads, since the ZMap team have found performance plateaus after this point. Additionally, using very large thread counts (> 32) will *not* increase scan performance and could lead to you encountering packet sending issues or encountering packet drop leading to inaccurate scan results. 

To be clear, there is zero benefit in creating more threads than you have cores on your machine. The sending threads are all sending as fast as possible and increasing threads over core count will lead to core contention. 

> [!TIP]
> As with scanning rate, we recommend starting with less and increasing as needed to ensure your scans are accurate and you minimize host and network strain.

## Running Your First Scan

Let's start your first scan. We're going to send a `ICMP Echo` packet to all IP's in the subnet `2408:8459::/32/32-64` with a packet send rate of 128 packets per second. The last 64 bits (Interface Identifier, IID) of the IPv6 addresses will be randomly generated. If there's anything running on that IP address and it is reachable, we should get an `ICMP Echo Reply` packet in response. This indicates that the target host is active and responsive to ICMP requests.

Run the following command:
```shell
sudo xmap -x 64 -R 128 2408:8459::/32
```

Due to the vast number of IPv6 addresses, you will see the following output:
```shell

 0:05 0% (1 years left); send: 648 128 p/s 94.0 Kb/s (129 p/s 94.8 Kb/s avg); recv: 0 0 p/s (0 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.00%
 0:06 0% (1 years left); send: 776 128 p/s 94.0 Kb/s (128 p/s 94.6 Kb/s avg); recv: 0 0 p/s (0 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.00%
 0:07 0% (1 years left); send: 904 128 p/s 94.0 Kb/s (128 p/s 94.5 Kb/s avg); recv: 0 0 p/s (0 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.00%
 0:08 0% (1 years left); send: 1032 128 p/s 94.0 Kb/s (128 p/s 94.5 Kb/s avg); recv: 0 0 p/s (0 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.00%
 0:09 0% (1 years left); send: 1160 128 p/s 94.0 Kb/s (128 p/s 94.4 Kb/s avg); recv: 0 0 p/s (0 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.00%

```

You can solve this problem by increasing the number of packets sent per second:
```shell
sudo xmap -R 128000 --output-filter="(success = 0 || success = 1)" -x 64 2408:8459::/32
```
Besides, since there are relatively few packets with the `success` field value of 1 in ICMP Echo Reply, you also need to add `--output-filter="(success = 0 || success = 1)"` to quickly see the result output:
```shell

2408:8459:d0d0:a87c::1
2408:8459:3020:3338::1
2408:8459:5a50:4fba::1
2408:8459:6260:75ac::1
2408:8459:1660:a7::1
2408:8459:a40:5c4::1
2408:8459:5665:9e9::1
2408:8459:20:6c6c::1
2408:8459:5a54:f673::1
2408:8459:4665:d702::1
2408:8459:4a6b:130d::1
2408:8459:4262:a95c::1
2408:8459:3e5d:f238::1
2408:8459:4a61:dfe5::1
2408:8459:5e50:23d0::1
2408:8459:4253:7e85::1
 0:01 0%; send: 64295 64.3 Kp/s 46.10 Mb/s (62.5 Kp/s 44.83 Mb/s avg); recv: 343 343 p/s (333 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.53%

```

We can see 2 types of output here: 
1.  IP's that responded to our `ICMP Echo` packet
2.  Detailed scan status printed every second

We did say "output similar to" and that brings up a key point, your results may vary slightly. Internet-reachable hosts can go on/offline in-between scans and your hardware might be faster/slower than what we're running on.

> [!TIP]
> 
>	If you run the above command by remotely controlling the server, you are likely to get the same result as ours. However, if you are running XMap on a virtual machine, you may encounter issues with not receiving packets. To help you resolve this issue, please refer to the [Virtual Machine Configuration](https://github.com/Limerencece/xmap/wiki/Virtual-Machine-Configuration).

It's nice to have all output in one screen, but you might want to separate hits and status info.

### Output
The `-o` or `--output-file` flag allows us to specify where we'd like IP/Port pair hits to go. Try using the `-o` flag like this:
```shell
sudo xmap -R 128000 --output-filter="(success = 0 || success = 1)" -x 64 2408:8459::/32
 -o test.txt
```

You should get output similar to:
```shell
Mar 04 05:48:26.691 [INFO] xmap: probe network: ipv6
Mar 04 05:48:26.691 [INFO] xmap: probe module: icmp_echo
Mar 04 05:48:26.691 [INFO] xmap: output module: csv
Mar 04 05:48:26.691 [INFO] xmap: iid module: low
Mar 04 05:48:26.712 [INFO] recv: Data link layer Ethernet
 0:00 0%; send: 0 0 p/s 0 b/s (0 p/s 0 b/s avg); recv: 0 0 p/s (0 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.00%
 0:01 0%; send: 68758 68.7 Kp/s 49.30 Mb/s (67.3 Kp/s 48.26 Mb/s avg); recv: 14 14 p/s (13 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.02%
 0:02 0%; send: 170165 101 Kp/s 72.7 Mb/s (84.2 Kp/s 60.35 Mb/s avg); recv: 338 324 p/s (167 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.20%
 0:03 0%; send: 278408 108 Kp/s 77.6 Mb/s (92.1 Kp/s 66.1 Mb/s avg); recv: 731 393 p/s (241 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.26%
 0:04 0%; send: 378285 99.9 Kp/s 71.6 Mb/s (94.0 Kp/s 67.4 Mb/s avg); recv: 1129 398 p/s (280 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.30%
 0:05 0% (12h left); send: 486392 108 Kp/s 77.5 Mb/s (96.8 Kp/s 69.4 Mb/s avg); recv: 1530 401 p/s (304 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.31%

```
A new `test.txt` file (located in the folder from which you ran the scan) should now include all the hits and our `stdout` will only show us the status of the scan. You can run:

```shell
cat test.txt
```

You will see the following output:

```shell

saddr
2408:8459:5c5a:4ae4::1
2408:8459:5a5b:10d3::1
2408:8459:566c:8e17::1
2408:8459:425e:2b46::1
2408:8459:5a5f:ba6f::1
2408:8459:5656:9897::1
2408:8459:486a:887::1
2408:8459:5e62:d93::1
2408:8459:4260:4b03::1
2408:8459:5c6b:9762::1
2408:8459:4a60:b7ae::1
2408:8459:5a68:6388::1
2408:8459:4653:3477::1
2408:8459:445f:ebc1::1

```

⚠️**Note:** The default output format is `CSV`. You can also change the output format to `JSON` by using `-O json`. Note that XMap, by default, only outputs the `saddr` field. If you need multiple fields (e.g., `--output-fields="saddr,outersaddr,type,code"`), you must use the `JSON` format.

## Other Scans

### Get N Reachable Hosts
In our earlier example (`sudo xmap -R 128000 --output-filter="(success = 0 || success = 1)" -x 64 2408:8459::/32`) we did not limit the number of received packets. However, you might only want to target ten reachable hosts within the subnet. You can use `--max-results=10` or `-N 10`

```shell
sudo xmap -R 128000 --output-filter="(success = 0 || success = 1)" -x 64 2408:8459::/32 -N 10
```

You will see the following output:
```shell
Mar 05 02:51:51.955 [INFO] xmap: probe network: ipv6
Mar 05 02:51:51.955 [INFO] xmap: probe module: icmp_echo
Mar 05 02:51:51.955 [INFO] xmap: output module: csv
Mar 05 02:51:51.955 [INFO] xmap: iid module: low
Mar 05 02:51:51.955 [INFO] csv: no output file selected, will use stdout
saddr
Mar 05 02:51:51.976 [INFO] recv: Data link layer Ethernet
 0:00 0%; send: 25 1 p/s 752 b/s (1.17 Kp/s 857 Kb/s avg); recv: 0 0 p/s (0 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.00%
2408:8459:4261:5fb9::1
2408:8459:4261:e194::1
2408:8459:446e:1420::1
2408:8459:406c:7bac::1
2408:8459:4864:3014::1
2408:8459:3e63:c08d::1
2408:8459:5e64:2b22::1
2408:8459:4863:e366::1
2408:8459:4253:6905::1
2408:8459:4858:da51::1
 0:01 100%; send: 53968 done (49.2 Kp/s 35.32 Mb/s avg); recv: 10 10 p/s (9 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.02%
Mar 05 02:51:54.057 [INFO] xmap: completed
```

### Reproducibility and Random Search

Run the above command again...
```shell
sudo xmap -R 128000 --output-filter="(success = 0 || success = 1)" -x 64 2408:8459::/32 -N 10
```

You will see the following output:
```shell
Mar 05 02:53:36.585 [INFO] xmap: probe network: ipv6
Mar 05 02:53:36.585 [INFO] xmap: probe module: icmp_echo
Mar 05 02:53:36.585 [INFO] xmap: output module: csv
Mar 05 02:53:36.585 [INFO] xmap: iid module: low
Mar 05 02:53:36.585 [INFO] csv: no output file selected, will use stdout
saddr
Mar 05 02:53:36.608 [INFO] recv: Data link layer Ethernet
 0:00 0%; send: 0 0 p/s 0 b/s (0 p/s 0 b/s avg); recv: 0 0 p/s (0 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.00%
2408:8459:4653:aa89::1
2408:8459:3e63:10f2::1
2408:8459:626b:4514::1
2408:8459:4867:f0d::1
2408:8459:6060:20cf::1
2408:8459:5c6c:fd33::1
2408:8459:3e69:519a::1
2408:8459:4855:8eaf::1
2408:8459:565a:19af::1
2408:8459:4a58:f9ba::1
 0:01 17%; send: 66088 done (62.9 Kp/s 45.13 Mb/s avg); recv: 10 10 p/s (9 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.02%
Mar 05 02:53:38.642 [INFO] xmap: completed

```

That's interesting, we got an entirely different set of IPs! When you define a given search space, XMap scans it randomly, not linearly. This wasn't a big deal when we wanted to search the entire search space like with previous scans since we'd still end up with the same (unordered) result set. However, in this case XMap returns when it finds the first 10 hits in a given search space. XMap's random search pattern leads to this variance in output.

Why search randomly? Resource contention can happen on both the sending and receiving side. We want to spread out the load placed on a receiving subnet(s) as much as possible, so by randomly searching a search space, we spread out the load we're placing on a given network at a given time.Unlike ZMap, which can only permute the rear segment of the 32-bit IPv4 address, XMap could **permute all the address space with any length and at any position**, such as the space between the 20th and 25th bit of `2001:db8::/20-25` and `192.168.0.0/20-25`.

You may want to have reproducibility in your scan's order, so you can use the `--seed=n` to ensure subsequent runs use the same ordering.

### Multiple Ports

You can scan across multiple ports. In this case, XMap will send a `TCP SYN` packet to each IP/Port pair. 
```shell
sudo xmap -R 128000 --output-filter="(success = 0 || success = 1)" -x 64 2408:8459::/32 -N 10 -M tcp_syn -p 80,8080
```

```shell
Mar 05 05:11:23.646 [INFO] xmap: probe network: ipv6
Mar 05 05:11:23.646 [INFO] xmap: probe module: tcp_syn
Mar 05 05:11:23.646 [INFO] xmap: output module: csv
Mar 05 05:11:23.646 [INFO] xmap: iid module: low
Mar 05 05:11:23.646 [INFO] csv: no output file selected, will use stdout
saddr
Mar 05 05:11:23.668 [INFO] recv: Data link layer Ethernet
 0:00 0%; send: 1 1 p/s 784 b/s (45 p/s 34.58 Kb/s avg); recv: 0 0 p/s (0 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.00%
 0:01 0%; send: 49086 49.1 Kp/s 36.69 Mb/s (48.0 Kp/s 35.90 Mb/s avg); recv: 0 0 p/s (0 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.00%
 0:02 0%; send: 125490 76.4 Kp/s 57.11 Mb/s (62.0 Kp/s 46.39 Mb/s avg); recv: 0 0 p/s (0 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.00%
 0:03 0%; send: 211432 85.9 Kp/s 64.2 Mb/s (69.9 Kp/s 52.30 Mb/s avg); recv: 0 0 p/s (0 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.00%
 0:04 0%; send: 301744 90.3 Kp/s 67.5 Mb/s (75.0 Kp/s 56.08 Mb/s avg); recv: 0 0 p/s (0 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.00%
 0:05 0% (1d21h left); send: 391770 90.0 Kp/s 67.3 Mb/s (78.0 Kp/s 58.31 Mb/s avg); recv: 0 0 p/s (0 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.00%
2408:8459:e660:eda1::1
2408:8459:2e30:2016::1
 0:06 20% (25s left); send: 480253 88.5 Kp/s 66.1 Mb/s (79.7 Kp/s 59.61 Mb/s avg); recv: 2 2 p/s (0 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.00%
 0:07 20% (29s left); send: 568529 88.3 Kp/s 66.0 Mb/s (80.9 Kp/s 60.52 Mb/s avg); recv: 2 0 p/s (0 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.00%
 0:08 20% (33s left); send: 658157 89.6 Kp/s 67.0 Mb/s (82.0 Kp/s 61.33 Mb/s avg); recv: 2 0 p/s (0 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.00%
 0:09 20% (37s left); send: 742256 84.1 Kp/s 62.87 Mb/s (82.3 Kp/s 61.50 Mb/s avg); recv: 2 0 p/s (0 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.00%
2408:8459:3420:20e5::1
 0:10 30% (24s left); send: 830594 88.3 Kp/s 66.0 Mb/s (82.9 Kp/s 61.95 Mb/s avg); recv: 3 1 p/s (0 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.00%
 0:11 30% (26s left); send: 921119 90.5 Kp/s 67.7 Mb/s (83.6 Kp/s 62.47 Mb/s avg); recv: 3 0 p/s (0 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.00%

```

Since most IPv6 addresses are not actually allocated, the rate of receiving `SYN-ACK` packets will be relatively slow.

### Multiple Subnets

You can scan multiple subnets with the same scan as well.
```shell
sudo xmap -R 128000 --output-filter="(success = 0 || success = 1)" -x 64 2408:8459::/32 2409:8938::/32 -N 10 -M tcp_syn -p 80,8080
```
```shell
Mar 05 05:19:11.579 [INFO] xmap: probe network: ipv6
Mar 05 05:19:11.579 [INFO] xmap: probe module: tcp_syn
Mar 05 05:19:11.579 [INFO] xmap: output module: csv
Mar 05 05:19:11.579 [INFO] xmap: iid module: low
Mar 05 05:19:11.579 [INFO] csv: no output file selected, will use stdout
saddr
Mar 05 05:19:11.600 [INFO] recv: Data link layer Ethernet
 0:00 0%; send: 7 1 p/s 784 b/s (309 p/s 237.1 Kb/s avg); recv: 0 0 p/s (0 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.00%
 0:01 0%; send: 59051 59.0 Kp/s 44.14 Mb/s (57.7 Kp/s 43.17 Mb/s avg); recv: 0 0 p/s (0 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.00%
2409:8938:9232:3e::1
2409:8938:284f:2a23::1
2409:8938:48b9:55b2::1
2409:8938:4cbe:6134::1
2409:8938:68b6:bf37::1
2409:8938:746a:797::1
2409:8938:3655:6ffc::1
2409:8938:62ab:3dad::1
2409:8938:a825:182a::1
 0:02 90%; send: 156347 97.3 Kp/s 72.7 Mb/s (77.3 Kp/s 57.78 Mb/s avg); recv: 9 9 p/s (4 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.01%
2409:8938:4cbb:98c9::1
Mar 05 05:19:14.610 [INFO] xmap: completed
```

## XMap's Config Files

By default, XMap doesn't scan the *entire* IPv4 space. There are two files that include subnets that are not scanned by default. You can change these files to explicitly scan those ranges, however in each case there's a reason they're not scanned by default.

### `blacklist4.conf`

`blacklist4.conf` includes the subnets which have been defined by RFC's (e.g. multicast, [RFC 1918](https://tools.ietf.org/html/rfc1918) to be reserved/unallocated, these are not scanned by default. You can add to this file if you wish to not scan certain IPs/subnets. Due to the globally addressable (end-to-end) nature of IPv6, there is no need to restrict scanning of IPv6 subnets. As a result, there is no `blacklist6.conf` file.

### `xmap.conf`
If you find yourself specifying certain settings, such as your maximum bandwidth or blacklist file every time you run XMap, you can specify these in `/etc/xmap/xmap.conf` or use a custom configuration file.

### Finding the Config Files on your Installation

You can find these files in your installation *usually* at `/etc/xmap/...conf`.

If you installed XMap with a package manager, it may have installed the config files in it's own location.

If you're unable to locate the files, try running `sudo find . -name "blacklist4.conf"` from the root directory after installing XMap.

---
In addition, if you want to learn more about XMap's performance, such as how to decouple sending/receiving, how to increase send performance (related to threads), and how to improve scan accuracy, please refer to the [ZMap Getting Started Guide](https://github.com/zmap/zmap/wiki/Getting-Started-Guide). Once again, we thank the ZMap team for providing the framework and inspiration for writing the XMap wiki.