在 XMap 中，IID（接口标识符）模块用于生成 IPv6 地址的低 64 位，即接口标识符部分。高 64 位通常是网络前缀。IID 模块允许您控制接口标识符的生成方式。以下是关于 IID 模块的简要介绍，信息来自 `xmap --help`。

```bash
IID Modules:
  -U, --iid-module=name         Select iid module (default=`low')
                                  (default=`default')
      --iid-args=args           Arguments to pass to iid module
      --iid-num=num             Number of iid for one IP prefix  (default=`1')
      --list-iid-modules        List available iid modules
```

### 选项

- `-U`, `--iid-module=name`：此选项允许您选择用于生成接口标识符的 IID 模块。默认模块是 `low`。
- `--iid-args=args`：传递给 IID 模块的参数。`set` 模块需要用户提供一个特定的 IPv6 地址，XMap 将提取该地址的最后 64 位作为 IID。
- `--iid-num=num`：每个 IP 前缀的 IID 数量。默认值为 `1`，这意味着每个前缀只会生成一个 IID。不同的探测模块可能会为此选项设置不同的数值。您也可以自行设置该值。

### IID 模块

XMap 提供了几种 IID 模块，每种模块都有不同的生成接口标识符的策略。您可以使用 `-U` 或 `--iid-module` 选项来选择 IID 模块。可以使用 `--list-iid-modules` 选项列出可用的 IID 模块：

```bash
xmap --list-iid-modules
```

输出将显示可用的 IID 模块：

```bash
IID-modules:
full
low
low_fill
rand
set
zero
```

#### full

- **功能**：生成一个所有位都设置为 1 的 IID。
- **示例**：`2001:db8:1234:5678:FFFF:FFFF:FFFF:FFFF`

#### low

- **功能**：生成一个低位 IID，其中最后一位设置为 1，其余位设置为 0。
- **示例**：`2001:db8:1234:5678::1`

#### low_fill

- **功能**：生成一个低位填充 IID，其中最后几位设置为 1。
- **示例**：`2001:db8:1234:5678::FFFF`

#### rand

- **功能**：生成一个随机的 IID。
- **示例**：`2001:db8:1234:5678:1783:ab42:9247:cb38`

#### set

- **功能**：基于用户提供的 IPv6 地址生成 IID。
- **示例**：`2001:db8:1234:5678::1`
- **用例**：此模式要求用户通过 `--iid-args` 参数指定一个 IPv6 地址的后缀。XMap 将提取所提供地址的最后 64 位作为 IID。当您有特定的地址或地址范围需要扫描时，这很有用。

#### zero

- **功能**：生成一个所有位都设置为 0 的 IID。
- **示例**：`2001:db8:1234:5678::`

### 示例

**使用 `set` IID 模块并指定一组 IID 进行扫描：**

   ```bash
   xmap -U set --iid-args 2001:db8::1 2001:db8::/32
   ```
