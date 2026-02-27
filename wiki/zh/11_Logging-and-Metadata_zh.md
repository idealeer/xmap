使用命令 `xmap --help`（或更简洁地，`xmap -h`），您可以看到关于日志和元数据的简要介绍如下：

    Logging and Metadata:
      -q, --quiet                   Do not print status updates
      -v, --verbosity=num           Level of log detail (0-5)  (default=`3')
      -l, --log-file=name           Write log entries to file
      -L, --log-directory=path      Write log entries to a timestamped file in this
                                      directory
      -m, --metadata-file=name      Output file for scan metadata (JSON)
      -u, --status-updates-file=name
                                    Write scan progress updates to CSV file
          --disable-syslog          Disables logging messages to syslog
          --notes=notes             Inject user-specified notes into scan metadata
          --user-metadata=json      Inject user-specified JSON metadata into scan
                                      metadata


​    

## 日志和元数据选项

- `-q`, `--quiet`：不每秒打印一次状态更新。
  
- `-v`, `--verbosity=n`：日志详细级别（0-5，默认 = `3`）。
  
- `-l`, `--log-file=filename`：日志消息的输出文件。默认输出到 `stderr`。
  
- `-L`, `--log-directory=path`：将日志条目写入此目录中一个带有时间戳的文件中。
  
- `-m`, `--metadata-file=filename`：扫描元数据的输出文件（JSON 格式）。
  
- `-u`, `--status-updates-file`：将扫描进度更新写入 CSV 文件。
  
- `--disable-syslog`：禁止将日志消息发送到系统日志（syslog）。
  
- `--notes=notes`：将用户指定的注释注入扫描元数据中。
  
- `--user-metadata=json`：将用户指定的 JSON 元数据注入扫描元数据中。

XMap 会产生几种类型的屏幕输出。默认情况下，XMap 会每隔 1 秒打印一次类似如下的基本进度信息。这可以通过设置 `-q` 标志来禁用。
```bash
0:02 41%; send: 1 done (12 p/s 9.42 Kb/s avg); recv: 1 1 p/s (0 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 100.00%
```
### 日志

XMap 在扫描器配置期间还会打印如下所示的信息性消息，这些消息可以通过 `-v` 参数来控制。
```bash
Mar 02 07:26:37.595 [INFO] xmap: probe network: ipv6
Mar 02 07:26:37.595 [INFO] xmap: probe module: icmp_echo
Mar 02 07:26:37.595 [INFO] xmap: output module: json
Mar 02 07:26:37.595 [INFO] xmap: iid module: low
Mar 02 07:26:37.645 [INFO] recv: Data link layer Ethernet
```
- **`-l`, `--log-file=filename`**：将所有日志消息发送到指定的文件，而不是默认的标准错误输出（stderr）。
  
- **`-L`, `--log-directory=path`**：将其日志条目写入指定目录内的一个文件中。日志文件会自动使用时间戳命名，确保每次扫描会话的日志都分开存储。
  
- **`--disable-syslog`**：不将其日志消息发送到系统日志设施（syslog）。
	
- **`-u`, `--status-updates-file`**：将扫描进度更新记录到 CSV 文件。每次更新都记录诸如已发送的探测包数量、已接收的响应数量或扫描的当前状态等信息。

### 元数据

XMap 也支持提供其元数据。元数据封装了关于扫描配置、环境和性能的全面详细信息。它包括有关主机身份、网络设置（IP 和 MAC 地址）、探测特性、扫描时间、性能指标、模块使用情况和过滤条件的信息。

- **`-m`, `--metadata-file=filename`**：将扫描元数据以 JSON 格式保存到指定的文件中。元数据通常包含有关扫描的详细信息，例如扫描参数、结果摘要和时间戳。

- **`--notes=notes`**：此选项允许您向扫描元数据中添加自定义的文本注释。这些注释可能包括关于扫描目的的信息、有关目标的上下文或任何其他用户特定的细节。这些注释成为元数据输出的一部分，有助于记录保存和后续分析。

- **`--user-metadata=json`**：将结构化的 JSON 数据注入到扫描元数据中。通过以 JSON 格式提供额外的字段，您可以包含自定义的元数据，例如项目标识符、部门名称或特定于扫描的标识符。
