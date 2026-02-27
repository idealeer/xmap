Using the command `xmap --help` (or more concisely, `xmap -h` ), you can see a brief introduction to the logging and metadata as follows:
    
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

    

## LOGGING AND METADATA OPTIONS

- `-q`, `--quiet`: Do not print status updates once per second.
    
- `-v`, `--verbosity=n`: Level of log detail (0-5, default = `3`).
    
- `-l`, `--log-file=filename`: Output file for log messages. By default, `stderr`.
    
- `-L`, `--log-directory=path`: Write log entries to a timestamped file in this directory.
    
- `-m`, `--metadata-file=filename`: Output file for scan metadata (JSON).
    
- `-u`, `--status-updates-file`: Write scan progress updates to CSV file.
    
- `--disable-syslog`: Disables logging messages to syslog.
    
- `--notes=notes`: Inject user-specified notes into scan metadata.
    
- `--user-metadata=json`: Inject user-specified JSON metadata into scan metadata.

There are several types of on-screen output that XMap produces. By default, XMap will print out basic progress information similar to the following every 1 second. This can be disabled by setting the `-q` flag.
```bash
0:02 41%; send: 1 done (12 p/s 9.42 Kb/s avg); recv: 1 1 p/s (0 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 100.00%
```
### Log

XMap also prints out informational messages during scanner configuration such as the following, which can be controlled with the `-v` argument.
```bash
Mar 02 07:26:37.595 [INFO] xmap: probe network: ipv6
Mar 02 07:26:37.595 [INFO] xmap: probe module: icmp_echo
Mar 02 07:26:37.595 [INFO] xmap: output module: json
Mar 02 07:26:37.595 [INFO] xmap: iid module: low
Mar 02 07:26:37.645 [INFO] recv: Data link layer Ethernet
```
- **`-l`, `--log-file=filename`**: Send all log messages to the specified file instead of the default output, which is the standard error (stderr). 
    
- **`-L`, `--log-directory=path`**: Write its log entries into a file within the provided directory. The log file is automatically named with a timestamp, ensuring that each scanning session's logs are stored separately. 
    
- **`--disable-syslog`** : Do not send its log messages to the system logging facility (syslog).
	
- **`-u`, `--status-updates-file`**: Log the scan progress updates to a CSV file. Each update records information such as the number of probes sent, responses received, or the current status of the scan.

### Metadata

XMap also supports providing its metadata.The metadata encapsulates comprehensive details about the scan’s configuration, environment, and performance. It includes information on host identity, network settings (both IP and MAC addresses), probe characteristics, scan timing, performance metrics, module usage, and filtering criteria.

- **`-m`, `--metadata-file=filename`**: Save the scan metadata in JSON format to a specified file. The metadata typically includes details about the scan such as the scan parameters, results summary, and timestamps.

- **`--notes=notes`**:  This option allows you to add custom textual notes to the scan metadata. Such notes might include information about the purpose of the scan, context about the target, or any other user-specific details. These notes become part of the metadata output, aiding in record-keeping and later analysis.

- **`--user-metadata=json`**: Inject structured JSON data into the scan metadata. By providing additional fields in JSON format, you can include custom metadata such as project identifiers, department names, or scan-specific identifiers. 
