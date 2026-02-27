虽然 XMap 默认执行 ICMP 回显请求扫描，但它也支持 TCP SYN 扫描。执行 TCP SYN 扫描时，XMap 需要一个目标端口（也可以提供多个端口或范围），并支持指定扫描发起的源端口范围：

* `-p, --target-port=port|range` 要扫描的 TCP 端口号（例如 `443` 或 `22,80,1000-2000`）
* `-s, --source-port=port|range` 扫描数据包的源端口（例如 40000-50000）

您需要明确指定 TCP SYN 扫描模块：
```shell
xmap -M tcp_syn
```

*警告！* 与 ZMap 相同，XMap 依赖 Linux 内核使用 RST 数据包响应 SYN/ACK 数据包，以关闭由扫描器打开的连接。之所以如此，是因为 XMap 在以太网层发送数据包，以减少内核中因跟踪打开的 TCP 连接和执行路由查找而产生的开销。因此，如果您有一条跟踪已建立连接的防火墙规则，例如类似于 `-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT` 的 netfilter 规则，这将阻止 SYN/ACK 数据包到达内核。

这不会阻止 XMap 记录响应，但会阻止 RST 数据包被发送回去，最终会消耗被扫描主机上的一个连接，直到您的连接超时。我们强烈建议您在扫描主机上选择一组未使用的端口，在您的防火墙中允许访问这些端口，并在执行 XMap 时使用 `-s` 标志指定此端口范围（例如 `-s '50000-60000'`）。
