由于 XMap 完全兼容 ZMap，得益于 [ZMap 的入门指南](https://github.com/zmap/zmap/wiki/Getting-Started-Guide)，您已经拥有了快速上手 XMap 的参考。然而，XMap 是在 ZMap 的基础上重新实现并全面改进的，其用法在某些方面与 ZMap 有所不同。接下来，我们将重点聚焦于 **IPv6**，为您提供一份全新的指南。

## 安装

XMap 可以通过许多常见的包管理器获取，或者您也可以从源代码编译。完整的安装说明请见[此处](https://github.com/idealeer/xmap/blob/master/INSTALL.md)。要检查是否已正确安装所有内容，请使用 `xmap --version` 命令运行。目前我们推荐使用 2.0.2 版本。

## ⚠️ 关于扫描速率的警告

默认情况下，XMap 会以您的网卡允许的最快速度进行扫描。由于 XMap 直接构造以太网帧，它不具备任何拥塞控制的概念（就像您默认通过 TCP 获得的那样）。
这有两个潜在的隐患：

* _目标网络 DoS：_ 如果您以非常高的速率扫描一个小型子网（例如，单个组织），您很容易意外地导致目标网络拒绝服务。我们建议*不要*以 1Gbps 或更快的速度运行扫描，除非您是在扫描整个互联网。如果您正在扫描单个网络，以接近 10Mbps 以下的速率运行会更容易成功。

* _源网络过载：_ 无论您扫描多少台主机，您也有可能使您的*源*网络（即您用来扫描互联网的网络）过载。许多网络设备虽然标榜有*吞吐量*数字（例如 1Gbps），但无法使用最小尺寸的数据包处理该全速（因为这需要处理设备的最大理论每秒数据包速率）。

为了减少对目标网络的影响，XMap 以随机顺序扫描范围内的 IP 地址。这意味着在给定时间段内，对目标子网造成的负载取决于 XMap 的扫描速率和目标范围的大小。

⚠️**注意：** 我们为 XMap 配备了地址随机生成和排除功能。关键模块是**地址生成模块**，它提供了全地址空间的随机排列。与 ZMap 仅能排列 32 位 IPv4 地址的后段不同，XMap 可以**以任意长度和在任意位置排列整个地址空间**，例如 `2001:db8::/20-25` 和 `192.168.0.0/20-25` 中第 20 位到第 25 位之间的空间。我们利用 GMP 来实现地址生成模块。尽管如此，GMP 仅提供了一个大整数库，所有相关的数据结构和函数都需要**重写**，包括表示地址的树结构、忽略地址的黑名单结构、形成后续地址的循环模块以及过滤特定字段的表达式结构。此外，还创建了 IID 生成模块来填充前缀之后的剩余位，并且改进了所有相关代码以支持 IPv6。

## ⚠️ 关于线程的警告

xmap 命令行界面提供了使用 `-T (--sender-threads=num)` 设置发送线程数的功能。同时还会创建一个用于接收数据包的线程和一个用于监控扫描进度的线程，因此 xmap 所需的线程数为 `2 + T`，其中 T 是您设置的发送线程数（默认为 1）。

一般规则是，我们建议坚持使用 <= 8 个发送线程，因为 ZMap 团队发现在超过此数量后性能会出现平台期。此外，使用非常大的线程数（> 32）*不会*提高扫描性能，反而可能导致您遇到数据包发送问题，或因遭遇数据包丢弃而导致扫描结果不准确。

需要明确的是，创建的线程数超过您机器上的核心数没有任何好处。发送线程都在尽可能地快速发送，增加线程数超过核心数会导致核心争用。

> [!TIP]
> 与扫描速率一样，我们建议从较少的线程数开始，然后根据需要增加，以确保您的扫描准确，并最大限度地减少主机和网络的压力。

## 运行您的第一次扫描

让我们开始您的第一次扫描。我们将向 `2408:8459::/32/32-64` 子网中的所有 IP 发送一个 `ICMP Echo` 数据包，数据包发送速率为每秒 128 个数据包。IPv6 地址的最后 64 位（接口标识符，IID）将被随机生成。如果该 IP 地址上有任何东西在运行并且可达，我们应该会收到一个 `ICMP Echo Reply` 数据包作为响应。这表明目标主机处于活动状态并且对 ICMP 请求有响应。

运行以下命令：
```shell
sudo xmap -x 64 -R 128 2408:8459::/32
```

由于 IPv6 地址数量巨大，您将看到如下输出：
```shell

 0:05 0% (1 years left); send: 648 128 p/s 94.0 Kb/s (129 p/s 94.8 Kb/s avg); recv: 0 0 p/s (0 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.00%
 0:06 0% (1 years left); send: 776 128 p/s 94.0 Kb/s (128 p/s 94.6 Kb/s avg); recv: 0 0 p/s (0 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.00%
 0:07 0% (1 years left); send: 904 128 p/s 94.0 Kb/s (128 p/s 94.5 Kb/s avg); recv: 0 0 p/s (0 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.00%
 0:08 0% (1 years left); send: 1032 128 p/s 94.0 Kb/s (128 p/s 94.5 Kb/s avg); recv: 0 0 p/s (0 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.00%
 0:09 0% (1 years left); send: 1160 128 p/s 94.0 Kb/s (128 p/s 94.4 Kb/s avg); recv: 0 0 p/s (0 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.00%

```

您可以通过增加每秒发送的数据包数量来解决这个问题：
```shell
sudo xmap -R 128000 --output-filter="(success = 0 || success = 1)" -x 64 2408:8459::/32
```
此外，由于在 ICMP Echo Reply 中，`success` 字段值为 1 的数据包相对较少，您还需要添加 `--output-filter="(success = 0 || success = 1)"` 来快速查看结果输出：
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

这里我们可以看到 2 种输出类型：
1.  对我们 `ICMP Echo` 数据包做出响应的 IP
2.  每秒打印一次的详细扫描状态

我们确实说了“类似于上述的输出”，这引出了一个关键点，您的结果可能会略有不同。互联网上可达的主机在两次扫描之间可能会上线/下线，而且您的硬件可能比我们运行的硬件更快或更慢。

> [!TIP]
>
> 	如果您通过远程控制服务器运行上述命令，您很可能会得到与我们相同的结果。但是，如果您在虚拟机上运行 XMap，您可能会遇到无法接收数据包的问题。为了帮助您解决此问题，请参考[虚拟机配置](https://github.com/Limerencece/xmap/wiki/Virtual-Machine-Configuration)。

将所有输出放在一个屏幕上固然不错，但您可能希望将命中结果和状态信息分开。

### 输出

`-o` 或 `--output-file` 标志允许我们指定希望将 IP/端口对命中结果写入的位置。尝试像这样使用 `-o` 标志：
```shell
sudo xmap -R 128000 --output-filter="(success = 0 || success = 1)" -x 64 2408:8459::/32 -o test.txt
```

您应该会得到类似于以下的输出：
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
一个新的 `test.txt` 文件（位于您运行扫描的文件夹中）现在应该包含所有命中结果，而我们的 `stdout` 将只显示扫描的状态。您可以运行：

```shell
cat test.txt
```

您将看到以下输出：

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

⚠️**注意：** 默认输出格式为 `CSV`。您也可以使用 `-O json` 将输出格式更改为 `JSON`。请注意，XMap 默认只输出 `saddr` 字段。如果您需要多个字段（例如，`--output-fields="saddr,outersaddr,type,code"`），则必须使用 `JSON` 格式。

## 其他扫描

### 获取 N 个可达主机

在我们之前的例子（`sudo xmap -R 128000 --output-filter="(success = 0 || success = 1)" -x 64 2408:8459::/32`）中，我们没有限制接收数据包的数量。但是，您可能只想针对子网内的十个可达主机。您可以使用 `--max-results=10` 或 `-N 10`。

```shell
sudo xmap -R 128000 --output-filter="(success = 0 || success = 1)" -x 64 2408:8459::/32 -N 10
```

您将看到以下输出：
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

### 可重复性与随机搜索

再次运行上面的命令...
```shell
sudo xmap -R 128000 --output-filter="(success = 0 || success = 1)" -x 64 2408:8459::/32 -N 10
```

您将看到以下输出：
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

这很有意思，我们得到了一组完全不同的 IP！当您定义一个给定的搜索空间时，XMap 是随机扫描的，而不是线性扫描。这对于我们之前希望搜索整个搜索空间的扫描来说问题不大，因为我们最终仍会得到相同的（无序）结果集。但是，在这种情况下，XMap 在给定搜索空间中找到前 10 个命中结果时就返回了。XMap 的随机搜索模式导致了输出的这种差异。

为什么要随机搜索？发送端和接收端都可能发生资源争用。我们希望尽可能分散目标子网所承受的负载，因此通过随机搜索搜索空间，我们可以分散在给定时间对特定网络造成的负载。与 ZMap 仅能排列 32 位 IPv4 地址的后段不同，XMap 可以**以任意长度和在任意位置排列整个地址空间**，例如 `2001:db8::/20-25` 和 `192.168.0.0/20-25` 中第 20 位到第 25 位之间的空间。

您可能希望扫描的顺序具有可重复性，因此您可以使用 `--seed=n` 来确保后续运行使用相同的顺序。

### 多端口扫描

您可以跨多个端口进行扫描。在这种情况下，XMap 将向每个 IP/端口对发送一个 `TCP SYN` 数据包。
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

由于大多数 IPv6 地址实际上并未分配，因此接收 `SYN-ACK` 数据包的速率会相对较慢。

### 多子网扫描

您也可以在同一个扫描中扫描多个子网。
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

## XMap 的配置文件

默认情况下，XMap 不会扫描*整个* IPv4 空间。有两个文件包含了默认不扫描的子网。您可以更改这些文件以明确扫描这些范围，但在每种情况下，默认不扫描都是有原因的。

### `blacklist4.conf`

`blacklist4.conf` 包含了由 RFC（例如组播地址、[RFC 1918](https://tools.ietf.org/html/rfc1918)）定义为保留/未分配的子网，这些子网默认不会被扫描。如果您希望不扫描某些 IP/子网，可以将它们添加到此文件中。由于 IPv6 具有全球可寻址（端到端）的特性，因此没有必要限制对 IPv6 子网的扫描。因此，没有 `blacklist6.conf` 文件。

### `xmap.conf`
如果您发现自己每次运行 XMap 时都需要指定某些设置，例如您的最大带宽或黑名单文件，您可以在 `/etc/xmap/xmap.conf` 中指定这些设置，或使用自定义的配置文件。

### 在您的安装中找到配置文件

您通常可以在您的安装目录下的 `/etc/xmap/...conf` 找到这些文件。

如果您通过包管理器安装了 XMap，它可能将配置文件安装在其自己的位置。

如果您找不到这些文件，请在安装 XMap 后尝试从根目录运行 `sudo find . -name "blacklist4.conf"`。

---
此外，如果您想了解有关 XMap 性能的更多信息，例如如何解耦发送/接收、如何提高发送性能（与线程相关）以及如何提高扫描准确性，请参阅 [ZMap 入门指南](https://github.com/zmap/zmap/wiki/Getting-Started-Guide)。我们再次感谢 ZMap 团队为编写 XMap wiki 提供的框架和灵感。