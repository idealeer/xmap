XMap additionally supports UDP probes, where it will send out an arbitrary UDP datagram to each host, and receive either UDP or ICMP Unreachable responses. XMap supports four different methods of setting the UDP payload through the --probe-args command-line option. These are `"text"` for ASCII-printable payloads, `"hex"` for hexadecimal payloads set on the command-line, `"file"` for payloads contained in an external file, and `"template"` for payloads that require dynamic field generation. In order to obtain the UDP response, make sure that you specify `data` as one of the fields to report with the `--output-fields=fields` option.

The example below will send the two bytes `"ST"`, a PCAnywhere `"status"` request, to UDP port 5632:

```shell
sudo xmap -M udp -p 5632 -N 100 -R 300000 -O json --probe-args=text:ST --output-fields="saddr,data" --output-filter="(success = 1 || success = 0) && (repeat = 0 || repeat = 1)"
```
You will see the output as follows:
```shell
Mar 05 13:03:52.231 [INFO] xmap: probe network: ipv6
Mar 05 13:03:52.231 [INFO] xmap: probe module: udp
Mar 05 13:03:52.232 [INFO] xmap: output module: json
Mar 05 13:03:52.232 [INFO] xmap: iid module: low
Mar 05 13:03:52.252 [INFO] recv: Data link layer Ethernet
 0:00 0%; send: 0 0 p/s 0 b/s (0 p/s 0 b/s avg); recv: 0 0 p/s (0 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.00%
 0:01 0%; send: 61211 61.2 Kp/s 41.09 Mb/s (60.0 Kp/s 40.28 Mb/s avg); recv: 0 0 p/s (0 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.00%
 0:02 0%; send: 143690 82.5 Kp/s 55.36 Mb/s (71.1 Kp/s 47.74 Mb/s avg); recv: 0 0 p/s (0 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.00%
 0:03 0%; send: 228244 84.5 Kp/s 56.76 Mb/s (75.6 Kp/s 50.73 Mb/s avg); recv: 0 0 p/s (0 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.00%
{ "saddr": "2a04:6d04::1", "data": null }
 0:04 1%; send: 322152 93.9 Kp/s 63.03 Mb/s (80.1 Kp/s 53.79 Mb/s avg); recv: 1 1 p/s (0 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.00%
{ "saddr": "2403:99f9::1", "data": null }
{ "saddr": "2602:ffb5::1", "data": null }

```

The example below will send the byte `"0x02"`, a SQL Server `"client broadcast"` request, to UDP port 1434:

```shell
sudo xmap -M udp -p 1434 -N 100 -R 300000 -O json --probe-args=hex:02 --output-fields="saddr,data"  --output-filter="(success = 1 || success = 0) && (repeat = 0 || repeat = 1)"
```

The example below will send a NetBIOS status request to UDP port 137. This uses a payload file that is included with the XMap distribution:

```shell
sudo xmap -M udp -p 137 -N 100 -R 300000 -O json --probe-args=file:/your/path/to/netbios_137.pkt --output-fields="saddr,data" --output-filter="(success = 1 || success = 0) && (repeat = 0 || repeat = 1)"
```

The example below will send a SIP `"OPTIONS"` request to UDP port 5060. This uses a template file that is included with the XMap distribution:

```shell
sudo xmap -M udp -p 5060 -N 100 -R 300000 -O json --probe-args=template:/your/path/to/sip_options.tpl --output-fields="saddr,data" --output-filter="(success = 1 || success = 0) && (repeat = 0 || repeat = 1)"
```

For more information about the UDP Probe Module, please refer to [ZMap's UDP Probe Module](https://github.com/zmap/zmap/wiki/UDP-Probe-Module).
