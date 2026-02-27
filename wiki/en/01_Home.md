Welcome to the xmap wiki!
# XMap: A Fast IPv6 & IPv4 Network Scanner

XMap is a fast network scanner designed for performing Internet-wide IPv6 & IPv4 network research scanning.

XMap is reimplemented and improved thoroughly from ZMap and is fully compatible with ZMap, armed with the "5 minutes" probing speed and novel scanning techniques. XMap is capable of scanning the 32-bits address space in under 45 minutes. With a 10 gigE connection and [PF_RING](http://www.ntop.org/products/packet-capture/pf_ring/), XMap can scan the 32-bits address space in under 5 minutes. Moreover, leveraging the novel IPv6 scanning approach, XMap can discover the IPv6 Network Periphery fast. Furthermore, XMap can scan the network space randomly with any length and at any position, such as 2001:db8::/32-64 and 192.168.0.1/16-20. Besides, XMap can probe multiple ports simultaneously.

XMap operates on GNU/Linux, macOS, and BSD. XMap currently has implemented probe modules for ICMP Echo scans, TCP SYN scans, [UDP probes](https://github.com/idealeer/xmap/blob/master/examples/udp-probes/README), and **DNS scans (stateless, stateful, or address-spoofing)**.

With banner grab and TLS handshake tool, [ZGrab2](https://github.com/zmap/zgrab2), more involved scans could be performed.

By default, XMap will perform an ICMP Echo scan on the specified IPv6 or IPv4 address space at the maximum rate possible. A more conservative configuration that will scan 10,000 random addresses on port 80 at a maximum 10 Mbps can be run as follows:

    xmap --bandwidth=10M --target-port=80 --max-targets=10000 --output-file=results.csv

Or more concisely:

    xmap -B 10M -p 80 -n 10000 -o results.csv

Due to the default value of the parameter `-x(--max-len=len)` being `32`, the default scanning range of XMap is `::/0-32`.However, XMap can also scan specific subnets or CIDR blocks. For example, to perform an ICMP Echo scan only on the `2001:db8::/32`, you would run:

    xmap -x 128 2001:db8::/32

If you want to scan only `10.0.0.0/8`, you need to explicitly declare it with `-4`:

    xmap -4 10.0.0.0/8

In order to scan the network space randomly with any length and at any position, such as `2001:db8::/32-64` and `192.168.0.1/16-20`, you would run:

    xmap -x 64 2001:db8::/32
    xmap -4 -x 20 192.168.0.1/16

You can also perform a TCP SYN scan on the specified IPv6 or IPv4 address space on TCP/80 using `-M`:

    xmap -M tcp_syn -p 80

In addition, XMap can be used to scan multiple ports or ranges of ports. For example,

    xmap -M tcp_syn -p 80,443,445-447,500-502

If the scan started successfully, XMap will output real-time status updates:

    0:05 0% (2d09h left); send: 104117 20.9 Kp/s 14.97 Mb/s (20.7 Kp/s 14.87 Mb/s avg); recv: 156 35 p/s (31 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.15%
    0:06 0% (2d09h left); send: 125126 21.0 Kp/s 15.06 Mb/s (20.8 Kp/s 14.90 Mb/s avg); recv: 197 41 p/s (32 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.16%
    0:07 0% (2d09h left); send: 146065 20.9 Kp/s 15.01 Mb/s (20.8 Kp/s 14.92 Mb/s avg); recv: 243 46 p/s (34 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.17%
    0:08 0% (2d09h left); send: 166973 20.9 Kp/s 14.99 Mb/s (20.8 Kp/s 14.93 Mb/s avg); recv: 288 45 p/s (35 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.17%
    0:09 0% (2d09h left); send: 187892 20.9 Kp/s 15.00 Mb/s (20.8 Kp/s 14.93 Mb/s avg); recv: 337 49 p/s (37 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.18%
    0:10 0% (2d09h left); send: 208809 20.9 Kp/s 15.00 Mb/s (20.8 Kp/s 14.94 Mb/s avg); recv: 388 51 p/s (38 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.19%

These updates provide information about the current state of the scan and are of the following form: 

    <elapsed-time> <%-complete> (<est-time-remaining>); send: <packets-sent> <curr-send-rate> <curr-bandwidth> (<avg-send-rate> <avg-bandwidth>); recv: <packets-recv> <recv-rate> (<avg-recv-rate>); drops: <drop-rate> (<avg-drop-rate>); hitrate: <hit-rate>

⚠️ **Warning!** If you do not know the scan rate that your network can support, you should experiment with different scan rates or bandwidth limits to find the fastest rate that your network can support before you see decreased results.

By default, XMap will output the list of distinct IP addresses that responded successfully (e.g., with an ICMP Echo Reply or TCP SYN ACK packet) similar to the following (take IPv6 as an example). There are several additional formats (e.g., CSV and JSON) for outputting results. Additional output fields can be specified, and the results can be filtered using an output filter. [[more information](https://github.com/Limerencece/xmap/wiki/Output-Modules)]

    2001:db8::1
    240e:30e:3d23::55d
    2001:db8::2
    240e:30e:3d23::55e
    2001:db8::3

We strongly encourage you to use a blacklist file to exclude both reserved/unallocated IP space (e.g., multicast, [RFC 1918](https://tools.ietf.org/html/rfc1918)), as well as networks that request to be excluded from your scans. By default, XMap will utilize a simple blacklist file containing reserved and unallocated addresses located at `/etc/xmap/blacklist4.conf`. [[more information](https://github.com/Limerencece/xmap/wiki/Scan-Options)]

If you find yourself specifying certain settings, such as your maximum bandwidth or blacklist file every time you run XMap, you can specify these in `/etc/xmap/xmap.conf` or use a custom configuration file.

If you are attempting to troubleshoot scan-related issues, there are several options to help debug. First, it is possible to perform a dry run scan to see the packets that would be sent over the network by adding the `--dryrun` flag. Additionally, you can change the logging verbosity by setting the `--verbosity=num` flag.

---

**After reading the above content, I believe you now have a preliminary understanding of XMap. If a more detailed beginner's guide is needed, please check out the [Getting Started Guide](https://github.com/Limerencece/xmap/wiki/Getting-Started-Guide).**
