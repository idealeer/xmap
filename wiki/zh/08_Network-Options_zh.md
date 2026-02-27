XMap 提供了多种网络选项，允许用户微调其扫描的行为。您可以通过 `xmap --help` 查看关于网络选项的简要介绍：

```bash
Network options:
  -s, --source-port=port|range  Source port(s) for scan packets, use `-'
  -S, --source-ip=ip|range      Source address(es) for scan packets, use `,'
                                  and `-' (max=`1024')
  -G, --gateway-mac=mac         Specify gateway MAC address, e.g.,
                                  12:34:56:78:90:ab
      --source-mac=mac          Specify source MAC address, e.g.,
                                  12:34:56:78:90:ab
  -i, --interface=name          Specify network interface to use
  -X, --iplayer                 Sends IP packets instead of Ethernet (for VPNs)
```

通常情况下，XMap 会自动检测并设置这些参数。但是，如果您的安装路径不正确或者您有个性化需求，您可以自行设置这些参数。

- `-s`, `--source-port=port|range`：扫描数据包的源端口，此端口是在发送扫描数据包时使用的端口。您可以指定单个端口（例如 `-s 12345`）或端口范围（例如 `-s 10000-20000`）。如果您想使用 `,` 来设置源端口，请记住不要在 `,` 后加空格（例如 `-s 12345,12346`）。

- `-S`, `--source-ip=ip|range`：扫描数据包的源地址，使用 `,` 和 `-`（最大=`1024`）。您可以指定单个 IP 地址（例如 `-S 192.168.1.1`）或 IP 地址范围（例如 `-S 192.168.1.1-192.168.1.10`）。当您想要构造一个源地址设置为指定目标地址的数据包时，这很有帮助。

- `-G`, `--gateway-mac=mac`：指定网关 MAC 地址，例如 12:34:56:78:90:ab。网关 MAC 地址是向目标网络发送数据包时使用的下一跳 MAC 地址。

- `--source-mac=mac`：指定源 MAC 地址，例如 12:34:56:78:90:ab。源 MAC 地址是发送扫描数据包时使用的 MAC 地址。

- `-i`, `--interface=name`：指定要使用的网络接口（例如 `xmap -i eth0`）。

- `-X`, `--iplayer`：发送 IP 层数据包而不是以太网帧（用于 VPN）。默认情况下，XMap 发送以太网帧。当使用 VPN 时，您可能需要发送 IP 层数据包。

如果 XMap 无法自动检测到这些参数的值，您可以在您的计算机上检查这些参数以自行设置。以下是一些方法（在 Linux 中）。

1. **检查您的 IP 地址**

   使用 `ifconfig` 查看您的 IP 地址。您可能会看到类似于以下的输出：

   ```bash
   eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
           inet 10.10.10.00  netmask 255.255.128.0  broadcast 10.10.10.10
           inet6 2001:abcd:abcd:abcd:abcd:abcd:abcd:abcd  prefixlen 64  scopeid 0x0<global>
           inet6 fe80::5b7f:665:196c:abcd  prefixlen 64  scopeid 0x20<link>
           ...
           TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
   ```

   - 如果您想扫描 IPv6 地址空间，请记住使用带有 global 标签的 IPv6 地址。

2. **检查您的 MAC 地址**

   使用 `ifconfig` 查看您的 MAC 地址。例如：

   ```bash
   eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
           ether 00:1a:2b:3c:4d:5e  txqueuelen 1000  (Ethernet)
           ...
   ```

   - `ether` 字段（例如 `00:1a:2b:3c:4d:5e`）就是您的 MAC 地址。

3. **检查您的 ARP 表**

   使用 `ip neigh` 命令查看 ARP 表，该表将 IP 地址映射到 MAC 地址。例如：

   ```bash
   $ ip neigh
   10.10.10.1 dev eth0 lladdr 00:1a:2b:3c:4d:5f REACHABLE
   10.10.10.100 dev eth0 lladdr 00:1a:2b:3c:4d:60 STALE
   ```

   - 每个条目显示一个 IP 地址及其对应的 MAC 地址。
