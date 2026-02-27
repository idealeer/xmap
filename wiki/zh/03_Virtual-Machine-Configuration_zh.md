为了确保在虚拟机上顺利使用 XMap 进行 IPv6 扫描，请遵循以下配置步骤：


## 1. 将虚拟机设置为桥接模式

在使用 VMware 等虚拟化软件时，默认的网络模式是 **NAT**。对于 IPv6 网络，NAT 的配置比**桥接模式**更复杂。即使 NAT 配置成功（并且能接收到数据包），接收到的数据包中的某些字段也可能不符合预期（例如 `ICMP Echo Reply` 数据包中的 `outersaddr` 字段）。因此，强烈建议使用**桥接模式**。

## 2. 确保您的电脑支持 IPv6

尽管 IPv6 已经存在多年并解决了 IPv4 地址枯竭的问题，但其部署仍在进行中。您的电脑有可能不支持 IPv6，尤其是在宽带网络上。如果您的宽带不支持 IPv6，请尝试使用**移动热点**。请注意，在中国，在**校园网**上使用 XMap 可能会出现问题，因此即使校园网支持 IPv6，我们也建议使用移动热点。

配置完成后，在 **Windows** 系统上运行命令 `ipconfig`（在 **Linux** 上运行 `ifconfig`）。您将看到类似于以下的输出：

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

桥接模式可以理解为虚拟机和宿主机通过同一个路由器获取 IP 地址。如果宿主机已经获取了全球可路由的 IPv6 地址，理论上虚拟机也应该有。在虚拟机终端中运行 `ifconfig` 命令，您将看到类似于以下的输出：

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

`<global>` 地址就是您的全球可路由 IPv6 地址。


## 3. 向 XMap 命令添加所需选项

配置好网络后，请向我们指南中提供的 XMap 命令添加以下三个选项：

- `-S`：您的源地址（全球可路由的 IPv6 地址）。
- `-G`：指定网关 MAC 地址。
- `-i`：指定网络接口。

要获取网关 MAC 地址，请运行 `ip -6 neigh` 命令：
```shell
fe80::xxxx:xxxx:xxxx:xxxx dev ens34 lladdr xx:xx:xx:xx:xx:xx router REACHABLE
```

这里，`xx:xx:xx:xx:xx:xx` 就是网关 MAC 地址。完整的命令将如下所示：
```shell
sudo xmap -R 128000 --output-filter="(success = 0 || success = 1)" -x 64 xxxx:xxxx::/32 -S xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx -G xx:xx:xx:xx:xx:xx -i ens34
```

## 4. 验证数据包接收情况

至此，您应该能够成功接收数据包了。恭喜！
