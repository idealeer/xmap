In XMap, IID (Interface Identifier) modules are used to generate the lower 64 bits of an IPv6 address, which is the interface identifier part. The upper 64 bits are typically the network prefix. The IID modules allow you to control how the interface identifier is generated. Here is a brief introduction about the IID Modules with `xmap --help`.

```bash
IID Modules:
  -U, --iid-module=name         Select iid module (default=`low')
                                  (default=`default')
      --iid-args=args           Arguments to pass to iid module
      --iid-num=num             Number of iid for one IP prefix  (default=`1')
      --list-iid-modules        List available iid modules
```

### Options

- `-U`, `--iid-module=name`: This option allows you to select the IID module to use for generating the interface identifier. The default module is `low`.
- `--iid-args=args`: Arguments to pass to IID module. The `set` module requires the user to provide a specific IPv6 address, and XMap will extract the last 64 bits of that address as the IID.
- `--iid-num=num`: Number of IID for one IP prefix. The default value is `1`  which means that only one IID will be generated pre prefix. Different probe modules may set different numbers for this option. You can also set the value by yourself.

### IID Modules

XMap provides several IID modules, each with different strategies for generating the interface identifier. You can select an IID module using the `-U` or `--iid-module` option. The available IID modules can be listed using the `--list-iid-modules` option:

```bash
xmap --list-iid-modules
```

The output will show the available IID modules:

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

- **Functionality**: Generates an IID with all bits set to 1.
- **Example**: `2001:db8:1234:5678:FFFF:FFFF:FFFF:FFFF`

#### low

- **Functionality**: Generates a low IID, where the last bit is set to 1 and the rest are set to 0.
- **Example**: `2001:db8:1234:5678::1`

#### low_fill

- **Functionality**: Generates a low-fill IID, where the last few bits are set to 1.
- **Example**: `2001:db8:1234:5678::FFFF`

#### rand

- **Functionality**: Generates a random IID.
- **Example**: `2001:db8:1234:5678:1783:ab42:9247:cb38`

#### set

- **Functionality**: Generates an IID based on a user-provided IPv6 address.
- **Example**: `2001:db8:1234:5678::1`
- **Use Case**: This mode requires the user to specify an IPv6 address' suffix through the `--iid-args` parameter. XMap will extract the last 64 bits of the provided address as the IID. This is useful when you have a specific address or range of addresses to scan.

#### zero

- **Functionality**: Generates an IID with all bits set to zero.
- **Example**: `2001:db8:1234:5678::`

### Example

**Scan with the `set` IID module and specify a set of IIDs:**

   ```bash
   xmap -U set --iid-args 2001:db8::1 2001:db8::/32
   ```

   