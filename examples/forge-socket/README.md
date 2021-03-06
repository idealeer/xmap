Forge-socket banner grab
======

This utility, in combination with a kernel module
(https://github.com/ewust/forge_socket/) will complete the half-open connection
created by XMap during a TCP-scan, optionally send a small message, and wait
for the hosts response. The response is then printed along with their IP
address on stdout. Periodic status messages appear on stderr.

This utility is functionally equivalent to banner-grab-tcp, however, instead of
having the kernel send a RST packet for the server's SYN+ACK, and
banner-grab-tcp attempting to start a fresh TCP connection with the host,
forge-socket will take the parameters of the SYN+ACK packet, and use a kernel
module to add it as an ESTABLISHED TCP connection socket. Then, the
forge-socket user-space program can use this socket to send() and recv() as
normal, and completes the banner-grab process (optionally send a small message,
and receive the server's response).



USING:
-----
# Install forge-socket to the XMap root directory:
cd ./xmap/
git clone git@github.com:ewust/forge_socket.git
cd forge_socket
make
sudo insmod forge_socket.ko

# Don't send RST packets (forge-socket will complete these connections instead)
sudo iptables -A OUTPUT -p tcp -m tcp --tcp-flags RST,RST RST,RST -j DROP

# Use XMap + forge-socket simultaneously:
make
#echo -e -n "GET / HTTP/1.1\r\nHost: %s\r\n\r\n" > http-req
sudo su
ulimit -SHn 1000000 && ulimit -SSn 1000000
xmap -4 -p 80 -B 50M -N 1000 -O extended_file -o - | ./forge-socket -c 8000 -d http-req > http-banners.out


The options are similar to banner-grab-tcp, except there is no connection timeout :)

OPTIONS:
-----
-c, --concurent         Number of connections that can be going on at once.
                        This, combined with timeouts, will decide the maximum
                        rate at which banners are grabbed. If this value
                        is set higher than 1000, you should use 
                        `ulimit -SSn 1000000` and `ulimit -SHn 1000000` to
                        avoid running out of file descriptors (typically capped
                        at 1024).

-r, --read-timeout      Read timeout (seconds). Give up on a host if after
                        connecting (and optionally sending data), it does
                        not send any response by this time. Default: 4 seconds.

-v, --verbosity         Set status verbosity. Status/error messages are outputed
                        on stderr. This value can be 0-5, with 5 being the most
                        verbose (LOG_TRACE). Default: 3 (LOG_INFO)

-f, --format            Format to output banner responses. One of 'hex', 'ascii',
                        or 'base64'. 
                        'hex' outputs ascii hex characters, e.g. 48656c6c6f.  
                        'ascii' outputs ascii, without separators, e.g. Hello
                        'base64' outputs base64 encoding, e.g. SGVsbG8=
                        Default is base64.

-d, --data              Optional data file. This data will be sent to each host
                        upon successful connection. Currently, this file does 
                        not allow null characters, but supports up to 4
                        occurances of the current host's IP address, by replacing
                        %s with the string (inet_ntoa) of that host's IP address.   

