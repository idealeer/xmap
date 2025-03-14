Using the command `xmap --help` (or more concisely, `xmap -h` ), you can see a brief introduction to the output modules as follows:
    
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
    

## OUTPUT OPTIONS

XMap allows users to specify and write their own output modules for use with XMap. Output modules are responsible for processing the fieldsets returned by the probe module, and outputting them to the user. Users can specify output fields, and write filters over the output fields.
- `--list-output-modules`: List available output modules (e.g., csv).
- `-O`, `--output-module=name`: Select output module (default = `csv`).
- `--output-args=args`: Arguments to pass to output module.
- `-f`, `--output-fields=fields`: Comma-separated list of fields to output. Accept fields with `,` and `*`.
- `--output-filter`: Specify an output filter over the fields defined by the probe module. See the output filter section for more details.

## Output Fields

XMap has a variety of fields it can output beyond IP address. These fields can be viewed for a given probe module by running with the `--list-output-fields` flag.

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

####  Output Specific Fields

This command scans port 80, captures specific fields (`saddr, daddr, seq, timestamp_str`), and saves the results in `output.csv`.

```bash
xmap -p 80 -f "saddr,daddr,seq,timestamp_str" -o output.csv
```
#### Output All Fields

```bash
xmap -p 443 -f "*" -o all_results.csv
```
Note: `*` means **output all available fields**, without manually listing them.

## Output Modules

* `--list-output-modules`: Lists all available **output modules** supported by `xmap` (e.g., `csv`, `json`).
* `-O`/ `--output-module=name`: Specifies the **output module**, with `csv` as the default.
* `--output-args=args`: The `--output-args` option is used to pass specific arguments to the output module, controlling the format and content of the output.The exact meaning and available options for these arguments depend on the selected output module.

## Filtering Output

XMap can filter probe results before outputting them. Filtering conditions are set using the **`--output-filter`** option, with a syntax similar to SQL.
The expression format is:  **`<fieldname> <operator> <value>`**
You can define filtering conditions, such as:

- Only successful results: **`success = 1`**
- Exclude duplicate data: **`repeat != 1`**
Multiple conditions can be combined, for example:  

```bash
--output-filter="success = 1 && repeat = 0"
```
This means selecting only successful and non-duplicate results.

If you're unsure which fields can be used for filtering, run:

```bash
xmap --list-output-fields
```
This command will display all available filterable fields.

### Examples

- **Filters results to only include responses from `2001:db8::1`.**

```
--output-filter="saddr='2001:db8::1'"
```
- **Keeps successful responses and ICMP error messages, but excludes repeated results.**

```
--output-filter="((success=1) || (type>=130)) && (repeat=0)"
```
