欢迎访问 xmap 维基！

# XMap：一个快速的 IPv6 和 IPv4 网络扫描器

XMap 是一个快速的网络扫描器，专为执行互联网范围的 IPv6 和 IPv4 网络研究扫描而设计。

XMap 是在 ZMap 的基础上重新实现并全面改进的，与 ZMap 完全兼容，拥有“5分钟”探测速度和新颖的扫描技术。XMap 能够在 45 分钟内扫描 32 位地址空间。借助 10 gigE 连接和 [PF_RING](http://www.ntop.org/products/packet-capture/pf_ring/)，XMap 可以在 5 分钟内扫描 32 位地址空间。此外，利用新颖的 IPv6 扫描方法，XMap 可以快速发现 IPv6 网络边缘。而且，XMap 可以以任意长度和在任意位置随机扫描网络空间，例如 `2001:db8::/32-64` 和 `192.168.0.1/16-20`。除此之外，XMap 还可以同时探测多个端口。

XMap 可在 GNU/Linux、macOS 和 BSD 上运行。XMap 目前已实现了针对 ICMP Echo 扫描、TCP SYN 扫描、[UDP 探测](https://github.com/idealeer/xmap/blob/master/examples/udp-probes/README)以及 **DNS 扫描（无状态、有状态或地址欺骗）**的探测模块。

结合用于抓取横幅和进行 TLS 握手的工具 [ZGrab2](https://github.com/zmap/zgrab2)，可以执行更深入的扫描。

默认情况下，XMap 将以最大可能速率在指定的 IPv6 或 IPv4 地址空间上执行 ICMP Echo 扫描。一个更保守的配置示例，即在最大 10 Mbps 速率下扫描端口 80 上的 10,000 个随机地址，可以如下运行：

    xmap --bandwidth=10M --target-port=80 --max-targets=10000 --output-file=results.csv

或者更简洁地：

    xmap -B 10M -p 80 -n 10000 -o results.csv

由于参数 `-x(--max-len=len)` 的默认值为 `32`，XMap 的默认扫描范围是 `::/0-32`。然而，XMap 也可以扫描特定的子网或 CIDR 块。例如，要仅在 `2001:db8::/32` 上执行 ICMP Echo 扫描，您可以运行：

    xmap -x 128 2001:db8::/32

如果您只想扫描 `10.0.0.0/8`，则需要使用 `-4` 明确声明：

    xmap -4 10.0.0.0/8

为了以任意长度和在任意位置随机扫描网络空间，例如 `2001:db8::/32-64` 和 `192.168.0.1/16-20`，您可以运行：

    xmap -x 64 2001:db8::/32
    xmap -4 -x 20 192.168.0.1/16

您也可以使用 `-M` 在指定的 IPv6 或 IPv4 地址空间的 TCP/80 端口上执行 TCP SYN 扫描：

    xmap -M tcp_syn -p 80

此外，XMap 可用于扫描多个端口或端口范围。例如，

    xmap -M tcp_syn -p 80,443,445-447,500-502

如果扫描成功启动，XMap 将输出实时状态更新：

    0:05 0% (2d09h left); send: 104117 20.9 Kp/s 14.97 Mb/s (20.7 Kp/s 14.87 Mb/s avg); recv: 156 35 p/s (31 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.15%
    0:06 0% (2d09h left); send: 125126 21.0 Kp/s 15.06 Mb/s (20.8 Kp/s 14.90 Mb/s avg); recv: 197 41 p/s (32 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.16%
    0:07 0% (2d09h left); send: 146065 20.9 Kp/s 15.01 Mb/s (20.8 Kp/s 14.92 Mb/s avg); recv: 243 46 p/s (34 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.17%
    0:08 0% (2d09h left); send: 166973 20.9 Kp/s 14.99 Mb/s (20.8 Kp/s 14.93 Mb/s avg); recv: 288 45 p/s (35 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.17%
    0:09 0% (2d09h left); send: 187892 20.9 Kp/s 15.00 Mb/s (20.8 Kp/s 14.93 Mb/s avg); recv: 337 49 p/s (37 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.18%
    0:10 0% (2d09h left); send: 208809 20.9 Kp/s 15.00 Mb/s (20.8 Kp/s 14.94 Mb/s avg); recv: 388 51 p/s (38 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.19%

这些更新提供了关于扫描当前状态的信息，格式如下：

    <已用时间> <完成百分比> (<预计剩余时间>); send: <已发送数据包> <当前发送速率> <当前带宽> (<平均发送速率> <平均带宽>); recv: <已接收数据包> <接收速率> (<平均接收速率>); drops: <丢弃速率> (<平均丢弃速率>); hitrate: <命中率>

⚠️ **警告！** 如果您不知道您的网络可以支持的扫描速率，您应该尝试不同的扫描速率或带宽限制，以找到在结果开始下降之前您的网络可以支持的最快速率。

默认情况下，XMap 将输出成功响应（例如，通过 ICMP Echo Reply 或 TCP SYN ACK 数据包）的不同 IP 地址列表，类似于以下内容（以 IPv6 为例）。还有几种其他格式（例如，CSV 和 JSON）可用于输出结果。可以指定额外的输出字段，并且可以使用输出过滤器对结果进行过滤。[[更多信息](https://github.com/Limerencece/xmap/wiki/Output-Modules)]

    2001:db8::1
    240e:30e:3d23::55d
    2001:db8::2
    240e:30e:3d23::55e
    2001:db8::3

我们强烈建议您使用黑名单文件来排除保留/未分配的 IP 空间（例如组播地址、[RFC 1918](https://tools.ietf.org/html/rfc1918)）以及请求从您的扫描中排除的网络。默认情况下，XMap 将使用一个位于 `/etc/xmap/blacklist4.conf` 的简单黑名单文件，其中包含保留和未分配的地址。[[更多信息](https://github.com/Limerencece/xmap/wiki/Scan-Options)]

如果您发现自己每次运行 XMap 时都需要指定某些设置，例如您的最大带宽或黑名单文件，您可以在 `/etc/xmap/xmap.conf` 中指定这些设置，或使用自定义的配置文件。

如果您正在尝试解决与扫描相关的问题，有几个选项可以帮助调试。首先，可以通过添加 `--dryrun` 标志来执行试运行扫描，以查看将通过网络发送的数据包。此外，您可以通过设置 `--verbosity=num` 标志来更改日志记录的详细程度。

---

**阅读完以上内容，相信您对 XMap 已经有了初步的了解。如果需要更详细的初学者指南，请查看[入门指南](https://github.com/Limerencece/xmap/wiki/Getting-Started-Guide)。**