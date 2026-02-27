Using the command `xmap --help` (or more concisely, `xmap -h` ), you can see a brief introduction to the additional options as follows:
    
    Additional options:
      -T, --sender-threads=num      Threads used to send packets  (default=`1')
      -C, --config=filename         Read a configuration file, which can specify
                                      any of these options
                                      (default=`/etc/xmap/xmap.conf')
      -d, --dryrun                  Do not actually send packets, just show
          --max-sendto-failures=num Maximum NIC sendto failures before scan is
                                      aborted  (default=`-1')
          --min-hitrate=rate        Minimum hitrate that scan can hit before scan
                                      is aborted  (default=`0.0')
          --cores=STRING            Comma-separated list of cores to pin to
          --ignore-blacklist-error  Ignore invalid entries in
                                      `--whitelist-file/blacklist-file'
          --ignore-filelist-error   Ignore invalid entries in `--list-of-ips-file'
      -h, --help                    Print help and exit
      -V, --version                 Print version and exit
 

## ADDITIONAL OPTIONS

- `-T`, `--sender-threads=num`: Threads used to send packets. XMap will attempt to detect the optimal number of send threads based on the number of processor cores.
    
- `-C`, `--config=filename`: Read a configuration file, which can specify any other options.
    
- `-d`, `--dryrun`: Print out each packet to stdout instead of sending it (useful for debugging).
    
- `--max-sendto-failures=num`: Maximum NIC sendto failures before scan is aborted.
    
- `--min-hitrate=rate`: Minimum hitrate that scan can hit before scan is aborted.
    
- `--cores`: Comma-separated list of cores to pin to.
    
- `--ignore-blacklist-error`: Ignore invalid, malformed, or unresolvable entries in `--whitelist-file` and `--blacklist-file`.
    
- `--ignore-filelist-error`: Ignore invalid, malformed, or unresolvable entries in `--list-of-ips-file`.
    
- `-h`, `--help`: Print help and exit.
    
- `-V`, `--version`: Print version and exit.

### Retrieving Basic XMap Information

- `-h, --help` – Lists all supported XMap command-line options, making it easy to quickly reference command usage.
- `-V, --version` – Prints the current XMap version and exits. This can be used to verify the installed version to ensure compatibility with other tools or scripts.

###  Runtime Configuration

- `-T num, --sender-threads=num` – Specifies the number of threads for sending packets. XMap automatically adjusts based on the number of CPU cores, but manual tuning is recommended for large-scale scans.
- `--cores` – Binds XMap to specific CPU cores to enhance performance and control.
- `-C filename, --config=filename` – Loads scan parameters from a configuration file, useful for managing complex scanning tasks in bulk.

### Scan Termination Conditions

- `--max-sendto-failures=num` – Sets the maximum number of packet send failures allowed before XMap terminates.  
- `--min-hitrate=rate` – Defines the minimum hit rate required for the scan to continue. If the hit rate falls below this threshold, XMap will terminate.  
- **Notes:**
  `--max-sendto-failures=num`: If the network is unstable, setting this value too low may cause premature scan termination, so careful adjustment is needed.
  `--min-hitrate=rate`: This helps eliminate inefficient scans, but setting it too high may cause early termination.
- **Example:**

```bash
xmap -6 2409:8000::/32 --max-sendto-failures=100
```
   If `sendto` fails more than **100 times**,  abort the scan.

``` bash
xmap -6 2409:8000::/32 --min-hitrate=0.05
```
   If the hit rate falls below 0 for 5 seconds, abort the scan.

### Filtering and Fault Tolerance

The purpose of these two parameters is to improve fault tolerance, allowing the program to continue running even when faced with file format issues, by ignoring errors as much as possible and continuing to process valid entries.

- `--ignore-blacklist-error`: Ignore invalid, malformed, or unresolvable entries in `--whitelist-file` and `--blacklist-file`. It is mainly useful when you have a blacklist file but do not want the entire operation to fail due to some errors in the file. 
- `--ignore-filelist-error`: Ignore invalid, malformed, or unresolvable entries in `--list-of-ips-file`.Similarly, It ensures that even if the IP list file contains erroneous entries, the program will not stop because of these issues.
### Debugging and Testing

Only prints ping request( ICMPv6 Echo Request) packets without actually sending them. This is useful for checking IPv6 network connectivity and verifying whether a target host is alive. When combined with the `-v` option, it provides detailed output.

**Example:**

```bash
xmap -6 -d 2409:8000::/32
```

```
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