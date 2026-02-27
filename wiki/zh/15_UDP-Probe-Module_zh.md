XMap 额外支持 UDP 探测，它会向每个目标主机发送一个任意的 UDP 数据报，并接收 UDP 或 ICMP 不可达响应。XMap 通过命令行选项 `--probe-args` 支持四种设置 UDP 负载的方法。分别是：用于 ASCII 可打印负载的 `"text"`，用于在命令行设置十六进制负载的 `"hex"`，用于包含在外部文件中的负载的 `"file"`，以及用于需要动态字段生成的负载的 `"template"`。为了获取 UDP 响应，请确保您使用 `--output-fields=fields` 选项将 `data` 指定为要报告的字段之一。

下面的示例将向 UDP 端口 5632 发送两个字节 `"ST"`，这是一个 PCAnywhere `"status"` 请求：

```shell
sudo xmap -M udp -p 5632 -N 100 -R 300000 -O json --probe-args=text:ST --output-fields="saddr,data" --output-filter="(success = 1 || success = 0) && (repeat = 0 || repeat = 1)"
```
您将看到如下输出：
```shell
Mar 05 13:03:52.231 [INFO] xmap: probe network: ipv6
Mar 05 13:03:52.231 [INFO] xmap: probe module: udp
Mar 05 13:03:52.232 [INFO] xmap: output module: json
Mar 05 13:03:52.232 [INFO] xmap: iid module: low
Mar 05 13:03:52.252 [INFO] recv: Data link layer Ethernet
 0:00 0%; send: 0 0 p/s 0 b/s (0 p/s 0 b/s avg); recv: 0 0 p/s (0 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.00%
 0:01 0%; send: 61211 61.2 Kp/s 41.09 Mb/s (60.0 Kp/s 40.28 Mb/s avg); recv: 0 0 p/s (0 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.00%
 0:02 0%; send: 143690 82.5 Kp/s 55.36 Mb/s (71.1 Kp/s 47.74 Mb/s avg); recv: 0 0 p/s (0 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.00%
 0:03 0%; send: 228244 84.5 Kp/s 56.76 Mb/s (75.6 Kp/s 50.73 Mb/s avg); recv: 0 0 p/s (0 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.00%
{ "saddr": "2a04:6d04::1", "data": null }
 0:04 1%; send: 322152 93.9 Kp/s 63.03 Mb/s (80.1 Kp/s 53.79 Mb/s avg); recv: 1 1 p/s (0 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.00%
{ "saddr": "2403:99f9::1", "data": null }
{ "saddr": "2602:ffb5::1", "data": null }

```

下面的示例将向 UDP 端口 1434 发送字节 `"0x02"`，这是一个 SQL Server `"client broadcast"` 请求：

```shell
sudo xmap -M udp -p 1434 -N 100 -R 300000 -O json --probe-args=hex:02 --output-fields="saddr,data"  --output-filter="(success = 1 || success = 0) && (repeat = 0 || repeat = 1)"
```

下面的示例将向 UDP 端口 137 发送一个 NetBIOS 状态请求。这使用了 XMap 发行版中包含的一个负载文件：

```shell
sudo xmap -M udp -p 137 -N 100 -R 300000 -O json --probe-args=file:/your/path/to/netbios_137.pkt --output-fields="saddr,data" --output-filter="(success = 1 || success = 0) && (repeat = 0 || repeat = 1)"
```

下面的示例将向 UDP 端口 5060 发送一个 SIP `"OPTIONS"` 请求。这使用了 XMap 发行版中包含的一个模板文件：

```shell
sudo xmap -M udp -p 5060 -N 100 -R 300000 -O json --probe-args=template:/your/path/to/sip_options.tpl --output-fields="saddr,data" --output-filter="(success = 1 || success = 0) && (repeat = 0 || repeat = 1)"
```

有关 UDP 探测模块的更多信息，请参阅 [ZMap 的 UDP 探测模块](https://github.com/zmap/zmap/wiki/UDP-Probe-Module)。
