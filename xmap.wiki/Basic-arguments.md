Using the command `xmap --help` (or more concisely, `xmap -h` ), you can see a brief introduction to the basic arguments as follows:
    
    Basic arguments:
      -6, --ipv6                    Scanning the IPv6 networks (default)
      -4, --ipv4                    Scanning the IPv4 networks
      -x, --max-len=len             Max IP bit length to scan  (default=`32')
      -p, --target-port=port|range  Port(s) number to scan (for TCP and UDP scans),
                                      use `,' and `-', with this option, one target
                                      is a <ip/x, port>
      -P, --target-index=num        Payload number to scan, with this option, one
                                      target is a <ip/x, (port), index>
                                      (default=`0')
      -o, --output-file=name        Output file, use `-' for stdout
      -b, --blacklist-file=path     File of subnets to exclude, in CIDR notation,
                                      e.g., 2001::/64, 192.168.0.0/16,
                                      www.qq.com/32 (max len of domain: 256)
      -w, --whitelist-file=path     File of subnets to include, in CIDR notation,
                                      e.g., 2001::/64, 192.168.0.0/16,
                                      www.qq.com/32 (max len of domain: 256)
      -I, --list-of-ips-file=path   List of individual addresses to scan in random
                                      order, e.g., 2001:db8::1, 192.168.0.1
    

## Network Type Selection

- `-6`, `--ipv6`: Scan IPv6 networks (enabled by default).
- `-4`, `--ipv4`: Scan IPv4 networks.

**Note**: By default, XMap scans the IPv6 networks. If you need to scan IPv4 networks, you must explicitly specify it using `xmap -4`. `-6` and `-4` are mutually exclusive, which means scanning IPv4 and IPv6 networks cannot be performed simultaneously. 


## Scan Range Configuration

- `-x`, `--max-len=len`: Set the maximum IP bit length to scan (default = 32).
- `ip|domain|range`: Specify the IP addresses, DNS hostnames, or IP ranges to scan (supports CIDR block notation).<br>Examples:
  - `2001::1` (IPv6 address)
  - `192.168.0.1` (IPv4 address)
  - `2001::/64` (IPv6 CIDR block)
  - `192.168.0.1/16` (IPv4 CIDR block)
  - `www.qq.com` (domain name)
  - Default values: `::/0` (IPv6) and `0.0.0.0/0` (IPv4).

### Examples

1. Scan the IPv6 address space (`::/0-32`) :

   ```bash
   xmap
   ```
2. Scan the entire IPv4 address space (`0.0.0.0/0-32`) as follows:
    
   ```bash
   xmap -4
   ```
   
3. Scan both `2001::/8` and `2002::/16` subnets for their respective address spaces (`2001::/8-32` and `2002::/16-32`) :

   ```bash
   xmap 2001::/8 2002::/16
   ```
4. Scan the 2001::/32-64 address space : 

   ```bash
   xmap -x 64 2001::/32
   ```

## Target Port Configuration

- `-p`, `--target-port=port|range`: Specify the TCP or UDP port(s) to scan (for SYN scans and basic UDP scans). Supports port ranges using `,` and `-`.<br>Examples:
  - `80,443`
  - `8080-8081`
  - `80,8080-8081`
- `-P`, `--target-index=num`: Specify the payload number to scan.

**Note**: `-P` is particularly useful in DNS modules. In DNS scanning, it is often used to match the number of questions specified in `--probe-args`. When combined with `--target-port`, a target is defined as `<ip/x, port, index>`. For example, if `--probe-args` contains multiple DNS queries like `"A,example.com;AAAA,www.example.com"`, you would use `-P 2` and `-p 53` : 

   ```
   xmap -p 53 -P 2 --probe-args="A,example.com;AAAA,www.example.com"
   ```

## Output Configuration

- `-o`, `--output-file=name`: Write scan results to a file. Use `-` for stdout (standard output).

### Supported Formats
XMap supports multiple output formats, including:
1. **CSV**: Comma-separated values, suitable for spreadsheet applications.
2. **JSON**: Structured data format, ideal for programmatic processing.

For more detailed information on output options, including customizing fields and formatting, please refer to [Output Modules](https://github.com/Limerencece/xmap/wiki/Output-Modules).

## Subnet Filtering

- `-b`, `--blacklist-file=path`: File of subnets to exclude, accept DNS hostnames, in CIDR notation, one-per line. It is recommended you use this to exclude RFC 1918 addresses, multicast, IANA reserved space, and other IANA special-purpose addresses. An example blacklist file `blacklist4.conf` for this purpose.
- `-w`, `--whitelist-file=path`: File of subnets to include, accept DNS hostnames, in CIDR notation, one-per line. Specifying a whitelist file is equivalent to specifying to ranges directly on the command line interface, but allows specifying a large number of subnets. An example whitelist file `whitelist6.conf` for this purpose.
- `-I`, `--list-of-ips-file=path`: File of individual IP addresses to scan, one-per line. This feature allows you to scan a large number of unrelated addresses. If you have a small number of IPs, it is faster to specify these on the command line or by using `--whitelist-file`. 

**Note**: 
1. `--list-of-ips-file` should only be used when scanning more than 1 million addresses. 
2. If both `--whitelist-file` and `--list-of-ips-file` are used, only hosts in the intersection of both sets will be scanned.
3. Hosts specified in `--list-of-ips-file` but included in `--blacklist-file` will be excluded.