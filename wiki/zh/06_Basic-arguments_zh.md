使用命令 `xmap --help`（或更简洁地使用 `xmap -h`），可以看到基本参数的简要介绍如下：

```
Basic arguments:
  -6, --ipv6                    扫描 IPv6 网络（默认）
  -4, --ipv4                    扫描 IPv4 网络
  -x, --max-len=len             要扫描的最大 IP 位长度  (default=`32')
  -p, --target-port=port|range  要扫描的端口号（用于 TCP 和 UDP 扫描），
                                  使用 `,' 和 `-'，使用该选项时，一个目标
                                  表示为 <ip/x, port>
  -P, --target-index=num        要扫描的 payload 编号，使用该选项时，一个
                                  目标表示为 <ip/x, (port), index>
                                  (default=`0')
  -o, --output-file=name        输出文件，使用 `-' 表示 stdout
  -b, --blacklist-file=path     要排除的子网文件，使用 CIDR 表示法，
                                  例如：2001::/64, 192.168.0.0/16,
                                  www.qq.com/32（域名最大长度：256）
  -w, --whitelist-file=path     要包含的子网文件，使用 CIDR 表示法，
                                  例如：2001::/64, 192.168.0.0/16,
                                  www.qq.com/32（域名最大长度：256）
  -I, --list-of-ips-file=path   要扫描的单个地址列表文件，按随机顺序扫描，
                                  例如：2001:db8::1, 192.168.0.1
```

## 网络类型选择

- `-6`, `--ipv6`: 扫描 IPv6 网络（默认启用）。
- `-4`, `--ipv4`: 扫描 IPv4 网络。

**Note**: 默认情况下，XMap 扫描 IPv6 网络。如果需要扫描 IPv4 网络，必须显式使用 `xmap -4` 指定。`-6` 和 `-4` 是互斥的，这意味着不能同时扫描 IPv4 和 IPv6 网络。

## 扫描范围配置

- `-x`, `--max-len=len`: 设置要扫描的最大 IP 位长度（默认 = 32）。
- `ip|domain|range`: 指定要扫描的 IP 地址、DNS 主机名或 IP 范围（支持 CIDR 块表示法）。示例：
  - `2001::1`（IPv6 地址）
  - `192.168.0.1`（IPv4 地址）
  - `2001::/64`（IPv6 CIDR 块）
  - `192.168.0.1/16`（IPv4 CIDR 块）
  - `www.qq.com`（域名）
  - 默认值：`::/0`（IPv6）和 `0.0.0.0/0`（IPv4）。

### 示例

1. 扫描 IPv6 地址空间（`::/0-32`）：

   ```bash
   xmap
   ```

2. 扫描整个 IPv4 地址空间（`0.0.0.0/0-32`），如下：

   ```bash
   xmap -4
   ```

3. 扫描 `2001::/8` 和 `2002::/16` 子网的地址空间（`2001::/8-32` 和 `2002::/16-32`）：

   ```bash
   xmap 2001::/8 2002::/16
   ```

4. 扫描 2001::/32-64 地址空间：

   ```bash
   xmap -x 64 2001::/32
   ```

## 目标端口配置

- `-p`, `--target-port=port|range`: 指定要扫描的 TCP 或 UDP 端口（用于 SYN 扫描和基础 UDP 扫描）。支持使用 `,` 和 `-` 指定端口范围。<br>示例：
  - `80,443`
  - `8080-8081`
  - `80,8080-8081`
- `-P`, `--target-index=num`: 指定要扫描的 payload 编号。

**Note**: `-P` 在 DNS 模块中特别有用。在 DNS 扫描中，它通常用于匹配 `--probe-args` 中指定的问题数量。当与 `--target-port` 结合使用时，一个目标定义为 `<ip/x, port, index>`。例如，如果 `--probe-args` 包含多个 DNS 查询，如 `"A,example.com;AAAA,www.example.com"`，则应使用 `-P 2` 和 `-p 53`：

```
xmap -p 53 -P 2 --probe-args="A,example.com;AAAA,www.example.com"
```

## 输出配置

- `-o`, `--output-file=name`: 将扫描结果写入文件。使用 `-` 表示 stdout（标准输出）。

### 支持的格式

XMap 支持多种输出格式，包括：

1. **CSV**：逗号分隔值，适用于电子表格应用程序。
2. **JSON**：结构化数据格式，适用于程序化处理。

有关输出选项的更多详细信息，包括自定义字段和格式，请参阅 [Output Modules](https://github.com/Limerencece/xmap/wiki/Output-Modules)。

## 子网过滤

- `-b`, `--blacklist-file=path`: 要排除的子网文件，接受 DNS 主机名，使用 CIDR 表示法，每行一个。建议使用此选项排除 RFC 1918 地址、多播地址、IANA 保留空间以及其他 IANA 特殊用途地址。为此提供了一个示例黑名单文件 `blacklist4.conf`。
- `-w`, `--whitelist-file=path`: 要包含的子网文件，接受 DNS 主机名，使用 CIDR 表示法，每行一个。指定白名单文件等价于直接在命令行界面指定范围，但允许指定大量子网。为此提供了一个示例白名单文件 `whitelist6.conf`。
- `-I`, `--list-of-ips-file=path`: 要扫描的单个 IP 地址文件，每行一个。此功能允许扫描大量不相关的地址。如果只有少量 IP，直接在命令行或使用 `--whitelist-file` 指定会更快。

**Note**:

1. `--list-of-ips-file` 仅应在扫描超过 100 万个地址时使用。
2. 如果同时使用 `--whitelist-file` 和 `--list-of-ips-file`，则只会扫描两个集合交集中的主机。
3. 在 `--list-of-ips-file` 中指定但同时包含在 `--blacklist-file` 中的主机将被排除。