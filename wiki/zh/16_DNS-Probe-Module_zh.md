与 ZMap 不同，除了提供 ICMP、TCP SYN 和 UDP 探测模块外，我们还提供了一个 DNS 扫描模块。该模块专门设计用于执行与 DNS 相关的查询和扫描，使用户能够发现 DNS 服务器、解析域名，并收集有关 DNS 配置的信息。

> 添加于 XMap v.2.0.0

- 新特性：
  -  `dnsx` : 启用基于 IPv6 的 DNS
  -  `dnsa` (IPv4&IPv6): 在向同一目标 <IP, port> 发送多个查询时，允许更改源端口和 TXID
  -  `dnsae` (IPv4&IPv6): 在向同一目标 <IP, port> 发送多个查询时，允许更改源端口和 TXID，并使用 EDNS0=4096
  -  `dnsan` (IPv4&IPv6): 在向同一目标 <IP, port> 发送多个查询时，使用固定源端口和 TXID
  -  `dnsane` (IPv4&IPv6): 在向同一目标 <IP, port> 发送多个查询时，使用固定源端口和 TXID，并使用 EDNS0=4096
  -  `dnsane16` (IPv4&IPv6): 在向同一目标 <IP, port> 发送多个查询时，使用固定源端口和 TXID，并使用 EDNS0=65535
  -  `dnsai` (IPv4&IPv6): 在向同一目标 <IP, port> 发送多个查询时，允许更改 TXID
  -  `dnsaie` (IPv4&IPv6): 在向同一目标 <IP, port> 发送多个查询时，允许更改 TXID，并使用 EDNS0=4096
  -  `dnsap` (IPv4&IPv6): 在向同一目标 <IP, port> 发送多个查询时，允许更改源端口
  -  `dnsape` (IPv4&IPv6): 在向同一目标 <IP, port> 发送多个查询时，允许更改源端口，并使用 EDNS0=4096
  -  `dnsaf` (IPv4&IPv6): 在向同一目标 <IP, port> 发送多个查询时，允许更改源端口和 TXID，并使用伪造源 IP
  -  `dnsafe` (IPv4&IPv6): 在向同一目标 <IP, port> 发送多个查询时，允许更改源端口和 TXID，并使用 EDNS0=4096 和伪造源 IP

有关如何使用 DNS 探测模块，请查看 [Issue #11](https://github.com/idealeer/xmap/issues/11)。