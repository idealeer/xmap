使用命令 `xmap --help`（或更简洁地，`xmap -h`），您可以看到关于输出模块的简要介绍如下：

    Output Modules:
      -O, --output-module=name      Select output module (default=`csv')
                                      (default=`default')
          --output-args=args        Arguments to pass to output module
      -f, --output-fields=fields    Fields that should be output in result set, use
                                      `,' and `*'
      -F, --output-filter=filter    Specify a filter over the response fields to
                                      limit what responses get sent to the output
                                      module
          --list-output-modules     List available output modules
          --list-output-fields      List all fields that can be output by selected
                                      probe module


## 输出选项

XMap 允许用户指定并编写自己的输出模块以供 XMap 使用。输出模块负责处理探测模块返回的字段集，并将其输出给用户。用户可以指定输出字段，并对输出字段编写过滤器。

- `--list-output-modules`：列出可用的输出模块（例如，csv）。
- `-O`, `--output-module=name`：选择输出模块（默认 = `csv`）。
- `--output-args=args`：传递给输出模块的参数。
- `-f`, `--output-fields=fields`：要输出的字段列表，以逗号分隔。接受使用 `,` 和 `*` 的字段。
- `--output-filter`：在探测模块定义的字段上指定一个输出过滤器。更多细节请参见输出过滤器部分。

## 输出字段

除了 IP 地址之外，XMap 还可以输出多种字段。对于给定的探测模块，可以通过运行带有 `--list-output-fields` 标志的命令来查看这些字段。

```
xmap --list-output-fields
IPv6 icmp_echo:
saddr           string: source IPv6 address of response
daddr           string: destination IPv6 address of response
hlim               int: hop-limit of response packet
success            int: did probe module classify response as success
clas            string: packet classification(type str):
						`e.g., echoreply', `other'
						use `--probe-args=icmp-type-code-str' to list
desc            string: ICMPv6 message detail(code str):
						use `--probe-args=icmp-type-code-str' to list
type               int: ICMPv6 message type
code               int: ICMPv6 message sub type code
icmp_id            int: ICMPv6 id number
seq                int: ICMPv6 sequence number
outersaddr      string: outer src address of ICMPv6 reply packet
data            binary: ICMPv6 payload
repeat            bool: is response <ip, port> a repeat response from host
cooldown          bool: was response received during the cooldown period
timestamp_str   string: timestamp of when response arrived in ISO8601 format.
timestamp_ts       int: timestamp of when response arrived in seconds since Epoch
timestamp_us       int: microsecond part of timestamp (e.g. microseconds since 
						'timestamp-ts')
```

#### 输出特定字段

此命令扫描端口 80，捕获特定字段（`saddr, daddr, seq, timestamp_str`），并将结果保存在 `output.csv` 中。

```bash
xmap -p 80 -f "saddr,daddr,seq,timestamp_str" -o output.csv
```
#### 输出所有字段

```bash
xmap -p 443 -f "*" -o all_results.csv
```
注意：`*` 表示**输出所有可用字段**，无需手动列出。

## 输出模块

* `--list-output-modules`：列出 `xmap` 支持的所有可用**输出模块**（例如，`csv`、`json`）。
* `-O`/ `--output-module=name`：指定**输出模块**，默认是 `csv`。
* `--output-args=args`：`--output-args` 选项用于向输出模块传递特定参数，以控制输出的格式和内容。这些参数的确切含义和可用选项取决于所选的输出模块。

## 过滤输出

XMap 可以在输出之前过滤探测结果。过滤条件使用 **`--output-filter`** 选项设置，其语法类似于 SQL。
表达式格式为： **`<字段名> <操作符> <值>`**
您可以定义过滤条件，例如：

- 仅输出成功的结果： **`success = 1`**
- 排除重复数据： **`repeat != 1`**
多个条件可以组合，例如：

```bash
--output-filter="success = 1 && repeat = 0"
```
这意味着仅选择成功且不重复的结果。

如果您不确定哪些字段可用于过滤，请运行：

```bash
xmap --list-output-fields
```
此命令将显示所有可用的可过滤字段。

### 示例

- **过滤结果，仅包含来自 `2001:db8::1` 的响应。**

```
--output-filter="saddr='2001:db8::1'"
```
- **保留成功响应和 ICMP 错误消息，但排除重复结果。**

```
--output-filter="((success=1) || (type>=130)) && (repeat=0)"
```
