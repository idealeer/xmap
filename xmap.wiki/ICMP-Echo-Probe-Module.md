We equip XMap with various probe modules. Run the command `xmap --list-probe-modules`, and you will get the following output:
```shell
Probe-modules (IPv6):
udp
dnsx
dnsa
dnsae
dnsan
dnsane
dnsane16
dnsai
dnsaie
dnsap
dnsape
dnsaf
dnsafe
tcp_syn
icmp_echo
icmp_echo_gw
icmp_echo_tmxd
Probe-modules (IPv4):
udp
dns
dnsr
dnsx
dnsf
dnsz
dnss
dnsv
dnsa
dnsae
dnsan
dnsane
dnsane16
dnsai
dnsaie
dnsap
dnsape
dnsaf
dnsafe
tcp_scan
tcp_syn
icmp_echo
```

XMap performs ICMP Echo request scans by default (the default value for the `-M` option is `icmp_echo`), which an ICMP echo request packet is sent to each host and the type of ICMP response received in reply is denoted.

From the output above, it can be observed that the probing modules for IPv6 and IPv4 differ. Among the ICMP-related modules, IPv6 includes an additional module called `icmp_echo_gw`, which is not present in IPv4. As you may already know, **XMap** is a fast network scanner developed to discover the **IPv6 Network Periphery** (refers to the last-hop routed infrastructure devices that connect end-hosts or enable connectivity for themselves. Examples include Customer Premises Equipment like home routers and User Equipment like smartphones). If you want to discover the IPv6 Network Periphery or reproduce the results of our paper **[Fast IPv6 Network Periphery Discovery and Security Implications](https://lixiang521.com/publication/dsn21/)**, you need to select the `icmp_echo_gw` module.

For example, if you want to reproduce the scanning results of China Unicom's mobile network as presented in our paper, you can use the following command:

```shell
xmap -6 -B 15M -M icmp_echo_gw --iid-module=rand -o result/CN_M_Uni.txt -O json --output-fields="saddr,outersaddr,type,code" --output-filter="(success = 1 || success = 0) && (repeat = 0 || repeat = 1)" -x 64 2408:8459::/32
```

Here, `2408:8459::/32` is one of the prefixes allocated to China Unicom's mobile network. The `--output-fields` option specifies four fields from the ICMP Echo Reply packets, which are the most valuable fields for reproducing our paper.
