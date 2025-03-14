While XMap performs ICMP echo request scans by default, it also supports TCP SYN scans. When performing a TCP SYN scan, XMap requires a single target port (multiple ports/ranges can be supplied as well) and supports specifying a range of source ports from which the scan will originate:

* `-p, --target-port=port|range` TCP port(s) number to scan (e.g. `443` or `22,80,1000-2000`)
* `-s, --source-port=port|range` Source port(s) for scan packets (e.g. 40000-50000)

You need to explicitly specify the TCP SYN scan module:
```shell
xmap -M tcp_syn
```

*Warning!* Same as ZMap, XMap relies on the Linux kernel to respond to SYN/ACK packets with RST packets in order to close connections opened by the scanner. This occurs because XMap sends packets at the Ethernet layer in order to reduce overhead otherwise incurred in the kernel from tracking open TCP connections and performing route lookups. As such, if you have a firewall rule that tracks established connections such as a netfilter rule similar to `-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT`, this will block SYN/ACK packets from reaching the kernel.

This will not prevent XMap from recording responses, but it will prevent RST packets from being sent back, ultimately using up a connection on the scanned host until your connection times out. We strongly recommend that you select a set of unused ports on your scanning host which can be allowed access in your firewall and specifying this port range when executing XMap, with the -s flag (e.g. `-s '50000-60000'`).