XMap provides a variety of network options that allow users to fine-tune the behavior of their scans. You can see a brief introduction about the network options with `xmap --help`:

```bash
Network options:
  -s, --source-port=port|range  Source port(s) for scan packets, use `-'
  -S, --source-ip=ip|range      Source address(es) for scan packets, use `,'
                                  and `-' (max=`1024')
  -G, --gateway-mac=mac         Specify gateway MAC address, e.g.,
                                  12:34:56:78:90:ab
      --source-mac=mac          Specify source MAC address, e.g.,
                                  12:34:56:78:90:ab
  -i, --interface=name          Specify network interface to use
  -X, --iplayer                 Sends IP packets instead of Ethernet (for VPNs)
```

Normally, XMap automatically detects these parameters and sets them. However, if your installation path is not correct or you have personalized needs, you can set these parameters yourself. 

-  `-s`, `--source-port=port|range`: Source port(s) for scan packets, this(these) port(s) is the port used when sending scan packets. You can specify a single port (e.g., `-s 12345`) or a range of ports (e.g., `-s 10000-20000`). If you want to use `,` to set the source port, remember not to include a space after the `,` (e.g., `-s 12345,12346`).

-  `-S`, `--source-ip=ip|range`: Source address(es) for scan packets, use `,`and `-` (max=`1024`). You can specify a single IP address (e.g., `-S 192.168.1.1`) or a range of IP addresses (e.g., `-S 192.168.1.1-192.168.1.10`).  This is helpful when you want to construct a packet with the source address set to the specified destination address.
-  `-G`, `--gateway-mac=mac`: Specify gateway MAC address, e.g.,12:34:56:78:90:ab. The gateway MAC address is the next-hop MAC address used when sending packets to the target network. 
-  `--source-mac=mac`: Specify source MAC address, e.g.,12:34:56:78:90:ab. The source MAC address is the MAC address used when sending scan packets.
-  `-i`, `--interface=name`: Specify network interface to use. (e.g., `xmap -i eth0`).
- `-X`, `--iplayer`: Sends IP packets instead of Ethernet (for VPNs). By default, XMap sends Ethernet packets. When using a VPN, you may need to send IP-layer packets instead.

If XMap can't  automatically detect your values for these parameters, You can check these parameters on your computer to set them yourself. Here are some ways.(In Linux)

1. **Check Your IP Address**

   use `ifconfig` to see your IP address. You might see output similar to the following:

   ```bash
   eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
           inet 10.10.10.00  netmask 255.255.128.0  broadcast 10.10.10.10
           inet6 2001:abcd:abcd:abcd:abcd:abcd:abcd:abcd  prefixlen 64  scopeid 0x0<global>
           inet6 fe80::5b7f:665:196c:abcd  prefixlen 64  scopeid 0x20<link>
           ...
           TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
   ```

   - Remember use the IPv6 address with the global label if you want to scan the IPv6 place.

2. **Check Your MAC Address**

   Use `ifconfig` to see your MAC address. For example:

   ```bash
   eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
           ether 00:1a:2b:3c:4d:5e  txqueuelen 1000  (Ethernet)
           ...
   ```

   - The `ether` field (e.g., `00:1a:2b:3c:4d:5e`) is your MAC address.

3. **Check Your ARP Table**

   Use the `ip neigh` command to view the ARP table, which maps IP addresses to MAC addresses. For example:

   ```bash
   $ ip neigh
   10.10.10.1 dev eth0 lladdr 00:1a:2b:3c:4d:5f REACHABLE
   10.10.10.100 dev eth0 lladdr 00:1a:2b:3c:4d:60 STALE
   ```

   - Each entry shows an IP address and its corresponding MAC address.

 