使用命令 `xmap --help`（或更简洁地使用 `xmap -h`），可以看到附加选项的简要介绍如下：

```
Additional options:
  -T, --sender-threads=num      用于发送数据包的线程数  (default=`1')
  -C, --config=filename         读取配置文件，该文件可以指定
                                  这些选项中的任意一个
                                  (default=`/etc/xmap/xmap.conf')
  -d, --dryrun                  不实际发送数据包，仅显示
      --max-sendto-failures=num 在扫描中止前允许的最大 NIC sendto 失败次数
                                  (default=`-1')
      --min-hitrate=rate        在扫描中止前允许的最小命中率
                                  (default=`0.0')
      --cores=STRING            要绑定的 CPU 核心的逗号分隔列表
      --ignore-blacklist-error  忽略 `--whitelist-file/blacklist-file`
                                  中的无效条目
      --ignore-filelist-error   忽略 `--list-of-ips-file` 中的无效条目
  -h, --help                    打印帮助信息并退出
  -V, --version                 打印版本信息并退出
```

## 附加选项

- `-T`, `--sender-threads=num`: 用于发送数据包的线程数。XMap 将尝试根据处理器核心数检测最优的发送线程数。
- `-C`, `--config=filename`: 读取配置文件，该文件可以指定任意其他选项。
- `-d`, `--dryrun`: 将每个数据包打印到 stdout，而不是发送它（用于调试）。
- `--max-sendto-failures=num`: 在扫描中止前允许的最大 NIC sendto 失败次数。
- `--min-hitrate=rate`: 在扫描中止前允许的最小命中率。
- `--cores`: 要绑定的 CPU 核心的逗号分隔列表。
- `--ignore-blacklist-error`: 忽略 `--whitelist-file` 和 `--blacklist-file` 中无效、格式错误或无法解析的条目。
- `--ignore-filelist-error`: 忽略 `--list-of-ips-file` 中无效、格式错误或无法解析的条目。
- `-h`, `--help`: 打印帮助信息并退出。
- `-V`, `--version`: 打印版本信息并退出。

### 获取基本 XMap 信息

- `-h, --help` – 列出所有支持的 XMap 命令行选项，使用户可以快速参考命令用法。
- `-V, --version` – 打印当前 XMap 版本并退出。这可用于验证已安装的版本，以确保与其他工具或脚本的兼容性。

### 运行时配置

- `-T num, --sender-threads=num` – 指定用于发送数据包的线程数。XMap 会根据 CPU 核心数自动调整，但对于大规模扫描建议手动调优。
- `--cores` – 将 XMap 绑定到指定 CPU 核心，以增强性能和控制能力。
- `-C filename, --config=filename` – 从配置文件加载扫描参数，适用于批量管理复杂扫描任务。

### 扫描终止条件

- `--max-sendto-failures=num` – 设置 XMap 在终止之前允许的最大数据包发送失败次数。
- `--min-hitrate=rate` – 定义扫描继续所需的最小命中率。如果命中率低于该阈值，XMap 将终止扫描。
- **Notes:**
  `--max-sendto-failures=num`: 如果网络不稳定，将该值设置得过低可能导致扫描过早终止，因此需要谨慎调整。
  `--min-hitrate=rate`: 该参数有助于消除低效扫描，但设置过高可能导致提前终止。
- **Example:**

```bash
xmap -6 2409:8000::/32 --max-sendto-failures=100
```

如果 `sendto` 失败次数超过 **100 次**，则中止扫描。

```bash
xmap -6 2409:8000::/32 --min-hitrate=0.05
```

如果命中率在 5 秒内低于 0，则中止扫描。

### 过滤和容错

这两个参数的目的是提高容错能力，使程序在面对文件格式问题时仍能继续运行，通过尽可能忽略错误并继续处理有效条目。

- `--ignore-blacklist-error`: 忽略 `--whitelist-file` 和 `--blacklist-file` 中无效、格式错误或无法解析的条目。当你有黑名单文件但不希望由于文件中的某些错误导致整个操作失败时，该选项特别有用。
- `--ignore-filelist-error`: 忽略 `--list-of-ips-file` 中无效、格式错误或无法解析的条目。同样地，它确保即使 IP 列表文件包含错误条目，程序也不会因此停止。

### 调试和测试

仅打印 ping 请求（ICMPv6 Echo Request）数据包，而不实际发送它们。这对于检查 IPv6 网络连通性以及验证目标主机是否存活非常有用。当与 `-v` 选项结合使用时，它会提供详细输出。

**Example:**

```bash
xmap -6 -d 2409:8000::/32
Ethernet
	Destination(6B)		: 4a:c5:70:77:4e:1d
	Source(6B)		: 00:0c:29:f2:02:9f
	Type(2B)		: 0x86dd
IPv6
	Version(4b)		: 6
	Traffic Class(8b)	: 0x00
	Flow Label(20b)		: 0x00000
	Payload Length(2B)	: 16
	Next Header(1B)		: 58
	Hop Limit(1B)		: 255
	Source(16B)		: 2408:8411:6029:15a3:3074:725b:bf34:97d4
	Destination(16B)	: 2001:4860:370f:d232:a6f3:d69a:8750:d6a
ICMPv6
	Type(1B)		: 128
	Code(1B)		: 0
	Checksum(2B)		: 0x194c
	Identifier(2B)		: n:30438 (0x76e6) h:58998 (0xe676)
	Sequence number(2B)	: n:31153 (0x79b1) h:45433 (0xb179)
```