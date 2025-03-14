Large-scale network scanning may induce several ethical concerns, as it may inadvertently affect systems and create additional work for network operators. To address these concerns, the XMap development team adheres to the ethical conventions for network measurement studies. These conventions ensure that our scanning activities are conducted responsibly and with minimal impact on the broader Internet ecosystem.

## Our Actions

To ensure compliance with the ethical conventions, our actions are as follows:

1. **Signal Intent**: We set up web pages on the source probing IPv6 addresses, signal the benign intent of the network scans, and show our contact details. This allows network operators to understand the purpose of our scans and reach out to us if necessary.

2. **Minimize Impact**: We limit the probing rate and lighten the probing to minimize negative impacts on the scanned networks. This ensures that our scans do not overwhelm the target systems or cause unnecessary disruption.

3. **Compliance with Standards**: We restrict ourselves to regular TCP/UDP/ICMP connection attempts followed by RFC-compliant protocols. We never undertake to exploit any vulnerabilities, ensuring that our scans are non-invasive and ethical.

4. **Responsible Disclosure**: In the end, we avoid releasing the discovered periphery addresses for privacy concerns. We also disclose all found weaknesses or vulnerabilities to involved device vendors and network administrators, helping to improve the overall security of the Internet.

## Call to Action

We encourage all users of XMap to follow these best practices when conducting network scans. By doing so, you can help ensure that your scanning activities are ethical, responsible, and minimally disruptive. Together, we can contribute to a safer and more secure Internet while advancing the field of network measurement research.

For more information on how to responsibly conduct network scans, you can refer to the [ZMap Scanning Best Practices](https://github.com/zmap/zmap/wiki/Scanning-Best-Practices).

## Run in Parallel?

We do not recommend running multiple commands that may put significant pressure on the network simultaneously, as everyone's resources are limited. Based on our practical experience, running three or more commands like the following on a server at a certain university is highly likely to cause commands to terminate abnormally (due to reasons such as out of memory, etc.), which may result in incomplete results:

```shell
sudo xmap -6 -B 15M -M icmp_echo_gw --iid-module=rand -o result/test.txt -O json --output-fields="saddr,outersaddr,type,code" --output-filter="(success = 1 || success = 0) && (repeat = 0 || repeat = 1)" -x 64 xxxx:xxxx::/32
```

We recommend setting the packet rate (`-R` or `-B`) to the maximum value your network can handle and running the commands one by one.