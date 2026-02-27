我们为 XMap 配备了多种探测模块。运行命令 `xmap --list-probe-modules`，您将看到以下输出：
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

XMap 默认执行 ICMP Echo 请求扫描（`-M` 选项的默认值为 `icmp_echo`），即向每个目标主机发送一个 ICMP 回显请求数据包，并标记收到的 ICMP 响应类型。

从上面的输出可以看出，IPv6 和 IPv4 的探测模块有所不同。在与 ICMP 相关的模块中，IPv6 比 IPv4 多了一个名为 `icmp_echo_gw` 的模块。您可能已经知道，**XMap** 是一个为发现 **IPv6 网络边缘**（指的是连接终端主机或为自身提供连接性的最后一跳路由基础设施设备，例如家庭路由器之类的用户驻地设备和智能手机之类的用户设备）而开发的快速网络扫描器。如果您想发现 IPv6 网络边缘，或复现我们论文 **[Fast IPv6 Network Periphery Discovery and Security Implications](https://lixiang521.com/publication/dsn21/)** 的结果，则需要选择 `icmp_echo_gw` 模块。

例如，如果您想复现我们论文中展示的中国联通移动网络的扫描结果，可以使用以下命令：

```shell
xmap -6 -B 15M -M icmp_echo_gw --iid-module=rand -o result/CN_M_Uni.txt -O json --output-fields="saddr,outersaddr,type,code" --output-filter="(success = 1 || success = 0) && (repeat = 0 || repeat = 1)" -x 64 2408:8459::/32
```

这里，`2408:8459::/32` 是分配给中国联通移动网络的前缀之一。`--output-fields` 选项指定了来自 ICMP Echo Reply 数据包的四个字段，这些字段对于复现我们的论文是最有价值的。