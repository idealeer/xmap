XMap 提供了多种扫描选项来定制扫描过程，允许用户控制速率、带宽和其他参数，以针对不同的网络环境和需求优化扫描。以下是对 XMap 中可用扫描选项的详细介绍。当您使用 `xmap --help` 命令时，可以看到扫描选项的简要介绍：

```bash
Scan options:
  -R, --rate=pps                Set send rate in pkts/sec
  -B, --bandwidth=bps           Set send rate in bits/sec (supports suffixes
                                  G/g, M/m, and K/k)
      --batch=num               Number of continuous targets probed before
                                  sleeping  (default=`1')
      --probes=num              Number of probes to send to each target
                                  (default=`1')
      --retries=num             Max number of times to try to send packets if
                                  send fails  (default=`1')
  -n, --max-targets=num         Capture number of targets to probe (default: no
                                  limit)
  -k, --max-packets=num         Capture number of packets to send (default: no
                                  limit)
  -t, --max-runtime=secs        Capture length of time for sending packets
                                  (default: no limit)
  -N, --max-results=num         Capture number of results to return (default:
                                  no limit)
  -E, --est-elements=num        Estimated number of results for unique, adapt
                                  to your memory capacity
                                  (default=`500000000')
  -c, --cooldown-secs=secs      How long to continue receiving after sending
                                  last probe  (default=`5')
  -e, --seed=num                Seed used to select address permutation and
                                  generate random probe validation msg
      --shards=num              Set the total number of shards  (default=`1')
      --shard=num               Set which shard this scan is (0 indexed)
                                  (default=`0')
```

## 速率和带宽控制

与 ZMap 类似，XMap 将以您的网络适配器支持的最快速率进行扫描。然而，在实际场景中，您可能需要根据您的网络环境和特定需求调整扫描速率。

- `-R`, ` --rate=pps`：以每秒数据包数（pps）设置发送速率。此选项允许您控制 XMap 每秒发送多少个数据包。调整速率有助于避免压垮网络或目标主机。
- `-B`, `--bandwidth=bps`：以每秒比特数（bps）设置发送速率。当您想限制扫描的带宽使用时，此选项很有用。

在实际使用中，以 15M/s 的速率扫描一个 32 位的 IPv6 空间大约需要 **2 天 15 小时**，相当于每秒约 250,000 个数据包。

### 示例

1. **以 15M/s 的速率扫描 IPv6 地址空间（`2409:8000::/32-64`）：**

   ```bash
   xmap -6 -x 64 -B 15M 2409:8000::/32
   ```

2. **以每秒 250,000 个数据包的速率扫描 IPv6 地址空间（`2409:8000::/32-64`）：**

   ```bash
   xmap -6 -x 64 -R 250000 2409:8000::/32
   ```

### 发送多个探测包

XMap 支持向每个目标主机发送多个探测包。探测包是直接作为以太网帧发送的，因此在不可靠的网络中无法保证送达。增加探测包数量可以提高到达更多主机的机会，但也会**增加扫描时间**。经验表明，扫描时间的增加（**每增加一个探测包，时间增加约 100%**）可能并不会大幅增加到达的主机数量。不过，您可以根据您的网络条件调整这些设置，以确保测量的可靠性。

- `--batch=num`：指定在调用系统调用发送之前，批量处理的数据包数量。此参数用于利用 Linux 的 `sendmmsg` 系统调用，该调用允许在单个系统调用中发送多个数据包，从而提高发送效率。默认值为 `1`。**增加此值可以显著提高扫描性能**，尤其是在支持批量发送机制的 Linux 系统上。
- `--probes=num`：发送到每个目标的探测包数量（默认=`1`）。增加此数字可以提高扫描结果的可靠性，尤其是在有损耗的网络环境中。但是，这将显著增加检测时间，即使您将此参数设置为 2。
- `--retries=num`：如果发送失败，尝试重新发送数据包的最大次数（默认=`1`）。此选项在传输过程中可能丢包的不可靠网络中很有用。

### 个性化扫描

- `-n`, `--max-targets=num`：要探测的目标数量上限（默认：无限制）。当您想对地址空间进行随机抽样时，此选项很有用。
- `-k`, `--max-packets=num`：要发送的数据包数量上限（默认：无限制）。此选项可用于控制扫描期间发送的数据包总数。
- `-t`, `--max-runtimes=secs`：发送数据包的时间长度上限（默认：无限制）。如果您只是想粗略了解一个地址空间，此选项会很有帮助。
- `-N`, `--max-results=num`：要返回的结果数量上限（默认：无限制）。此选项可用于在收集到一定数量的阳性结果后停止扫描。

### 内存和资源管理

- `-E`, `--est-elements=num`：预期唯一结果的数量，根据您的内存容量进行调整（默认=`500000000`）。此选项通过根据预期结果数量预先分配资源，帮助 XMap 管理内存使用。
- `-c`, `--cooldown-secs=secs`：指定在发送最后一个探测包后，XMap 应继续接收响应的时间。默认值为 `5` 秒。此选项确保 XMap 在结束扫描前捕获延迟的响应。

### 分片选项

- `-e`, `--seed=num`：用于选择地址排列和生成随机探测验证消息的种子。
- `--shards=num`：设置总分片数（默认=`1`）。
- `--shard=num`：设置此扫描是哪个分片（从 0 开始索引）（默认=`0`）。

这些选项帮助 XMap 实现在多台机器之间分片扫描。例如，要将扫描分片到四台机器上，让每台机器运行**以下命令之一**：

```bash
xmap --shards 4 --shard 0 --seed 1234
xmap --shards 4 --shard 1 --seed 1234
xmap --shards 4 --shard 2 --seed 1234
xmap --shards 4 --shard 3 --seed 1234
```
