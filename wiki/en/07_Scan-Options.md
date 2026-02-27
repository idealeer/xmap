XMap provides a variety of scan options to customize the scanning process, allowing users to control the rate, bandwidth, and other parameters to optimize the scan for different network environments and requirements. Below is a detailed introduction to the scan options available in XMap. When you use the `xmap --help` command, you can see a brief introduction to the scanning options:

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

## Rate and Bandwidth Control

Similar to ZMap, XMap will scan at the fastest rate supported by your network adapter. However, in real-world scenarios, you may need to adjust the scanning rate based on your network environment and specific requirements.

- `-R`, ` --rate=pps`: Set the send rate in packets per second (pps). This option allows you to control how many packets XMap sends per second. Adjusting the rate can help avoid overwhelming the network or the target hosts.
- `-B`, `--bandwidth=bps`: Set the send rate in bits per second (bps). This option is useful when you want to limit the bandwidth usage of the scan.

In practical use, setting the rate to 15M/s for scanning a 32-bit IPv6 space takes approximately **2 days and 15 hours**, which translates to around 250,000 packets per second.

### Examples

1. **Scan at a rate of 15M/s for the IPv6 address space (`2409:8000::/32-64`):**

   ```bash
   xmap -6 -x 64 -B 15M 2409:8000::/32	
   ```

2. **Scan at a rate of 250,000 packets per second for the IPv6 address space (`2409:8000::/32-64`):**

   ```bash
   xmap -6 -x 64 -R 250000 2409:8000::/32
   ```

### Sending Multiple Probes

XMap supports sending multiple probes to each host. Probes are sent as Ethernet frames directly, so there is no guarantee of delivery in unreliable networks. Increasing the number of probes increases the chance of reaching more hosts, but it also **increases the scan time**.  In experience, the increase in scan time (**~100% per additional probe**) might not greatly increase in hosts reached. However, you can adjust these settings based on your network conditions to ensure more reliable measurements.

- `--batch=num`: Specifies the number of packets to batch together before invoking the system call to send them. This parameter is used to take advantage of Linux's `sendmmsg` syscall, which allows sending multiple packets in a single system call, thereby improving sending efficiency. The default value is `1`. **Increasing this value can significantly enhance scan performance**, especially on Linux systems that support batch sending mechanisms.
- `--probes=num`: Number of probes to send to each target (default=`1`). Increasing this number can improve the reliability of the scan results, especially in lossy network environments. However, this will significantly increase the detection time, even if you set this parameter to 2.
- `--retries=num`: Max number of times to try to send packets if send fails  (default=`1`). This option is useful in unreliable networks where packets may be lost during transmission.

### Personalized scanning

- `-n`, `--max-targets=num`: Capture number of targets to probe (default: no limit).This option is useful when you want to perform a random sampling of the address space.
- `-k`, `--max-packets=num`: Capture number of packets to send (default: no limit).This option can be used to control the total number of packets sent during the scan.
- `-t`, `--max-runtimes=secs`: Capture length of time for sending packets (default: no limit).This option can be helpful if you just want to have a rough understanding of an address space.
- `-N`, `--max-results=num`: Capture number of results to return (default: no limit). This option can be used to stop the scan once a certain number of positive results have been collected.

### Memory and Resource Management

- `-E`, `--est-elements=num`: Estimated number of results for unique, adapt to your memory capacity (default=`500000000`). This option helps XMap manage memory usage by pre-allocating resources based on the expected number of results.
- `-c`, `--cooldown-secs=secs` : Specify how long XMap should continue receiving responses after sending the last probe. The default is `5` seconds. This option ensures that XMap captures late responses before ending the scan.

### Sharding options

- `-e`, `--seed=num`: Seed used to select address permutation and generate random probe validation message.
- `--shards=num` : Set the total number of shards  (default=`1`)
- `--shard=num` : Set which shard this scan is (0 indexed)(default=`0`)

These options help XMap allow for sharding a scan across multiple machines. For example, to split a scan across four machines, have each machine run **one** of the following commands:

```bash
xmap --shards 4 --shard 0 --seed 1234
xmap --shards 4 --shard 1 --seed 1234
xmap --shards 4 --shard 2 --seed 1234
xmap --shards 4 --shard 3 --seed 1234
```