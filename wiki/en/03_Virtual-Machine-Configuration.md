To ensure smooth usage of XMap for IPv6 scanning on a virtual machine, follow the configuration steps below:


## 1. Set the Virtual Machine to Bridged Mode
When using virtualization software like VMware, the default network mode is **NAT**. For IPv6 networks, NAT configurations are more complex compared to **bridged mode**. Even if NAT is successfully configured (and packets are received), certain fields in the received packets may not be as expected (e.g., the `outersaddr` field in `ICMP Echo Reply` packets). Therefore, it is strongly recommended to use **bridged mode**.

## 2. Ensure Your Computer Supports IPv6
Although IPv6 has been around for years and addresses IPv4 address exhaustion, its deployment is still ongoing. There is a chance your computer does not support IPv6, especially on broadband networks. If your broadband does not support IPv6, try using a **mobile hotspot**. Note that in China, using XMap on **campus networks** may cause issues, so even if the campus network supports IPv6, we recommend using a mobile hotspot.

After configuration, on a **Windows** system, run the command `ipconfig` (or `ifconfig` on **Linux**). You will see output similar to the following:

```shell
Wireless LAN adapter WLAN:

Connection-specific DNS Suffix . :
IPv6 Address . . . . . . . . . . : xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx
Temporary IPv6 Address. . . . . . : xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx
Link-local IPv6 Address . . . . . : fe80::xxxx:xxxx:xxxx:xxxx %8
IPv4 Address. . . . . . . . . . . : x.x.x.x
Subnet Mask . . . . . . . . . . . : 255.255.128.0
Default Gateway . . . . . . . . . : fe80::xxxx:xxxx:xxxx:xxxx %8
                                    x.x.x.x
```

Bridged mode can be understood as the virtual machine and the host obtaining IP addresses through the same router. If the host has already obtained a globally addressable IPv6 address, the virtual machine should theoretically have one as well. Run the `ifconfig` command in the virtual machine terminal, and you will see output similar to:

```shell
ens34: flags=4163<UP,BROADCAST,RUNNING,MULTICAST> mtu 1500
        inet x.x.x.x netmask 255.255.255.0 broadcast x.x.x.x
        inet6 fe80::xxxx:xxxx:xxxx:xxxx prefixlen 64 scopeid 0x20<link>
        inet6 xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx prefixlen 64 scopeid 0x0<global>
        inet6 xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx prefixlen 64 scopeid 0x0<global>
        ether xx:xx:xx:xx:xx:xx txqueuelen 1000 (Ethernet)
        RX packets xxxxxxxxx bytes xxxxxxxxx (xxx.x GB)
        RX errors 0 dropped xxxxx overruns 0 frame 0
        TX packets xxxxxxxxx bytes xxxxxxxxx (xxx.x TB)
        TX errors 0 dropped 0 overruns 0 carrier 0 collisions 0
```

The `<global>` address is your globally addressable IPv6 address.


## 3. Add Required Options to the XMap Command
After configuring the network, add the following three options to the XMap command provided in our guide:

- `-S`: Your source address (the globally addressable IPv6 address).
- `-G`: Specify the gateway MAC address.
- `-i`: Specify the network interface.

To obtain the gateway MAC address, run the `ip -6 neigh` command:
```shell
fe80::xxxx:xxxx:xxxx:xxxx dev ens34 lladdr xx:xx:xx:xx:xx:xx router REACHABLE
```

Here, `xx:xx:xx:xx:xx:xx` is the gateway MAC address. The full command will look like this:
```shell
sudo xmap -R 128000 --output-filter="(success = 0 || success = 1)" -x 64 xxxx:xxxx::/32 -S xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx -G xx:xx:xx:xx:xx:xx -i ens34
```

## 4. Verify Packet Reception
At this point, you should be able to receive packets successfully. Congratulations!