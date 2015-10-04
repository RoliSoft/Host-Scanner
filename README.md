# Host Scanner

The purpose of this project is to discover hosts on a network and then port scan them.

## Implemented features

* TCP scanner
  * A high-performance TCP scanner which initiates the three-way handshake by multiplexing non-blocking sockets and grabs the service banner.

* UDP scanner
  * Uses a list of known port numbers and sends a specifically crafted payload in order to try and get an answer from the server, if there are any listening.

## Planned features

* Network mapping
  * LAN
    * ARP requests for IPv4
    * Neighbor Solicitation for IPv6
  * WAN
    * Try host discovery methods for the whole range

* Host discovery
  * Send standard ICMP ping
  * Send TCP SYN to port 80, if ACK or RST received, host is alive
  * Send UDP packet to port 53, if response or ICMP "port unreachable", host is alive
  * _Otherwise assume host is offline or heavily firewalled_

* <strike>Port scanning</strike> &#x2713;
  * <strike>Send TCP SYN to all or popular ports, get service banner on ACK</strike> &#x2713;
  * <strike>Send crafted UDP packets to known ports</strike> &#x2713;

* External tools
  * Integrate with external tools for failover/preference
    * nmap, msfscan

* Reporting
  * Results will be forwarded to agent for further processing

## How to run

To compile and run the project, you must first install the dependencies, which on Debian (and on its derivatives) can be done with:

    apt-get install build-essential cmake libboost-dev

After the dependencies have been installed, you can check out the repository and compile it with the following commands:

    git clone https://github.com/RoliSoft/Host-Scanner.git
    cd Host-Scanner
    cmake .
    make

If the compilation was successful, you can run it with the `./HostScanner` command.

Tested on:

 * Windows 10 / Visual Studio 2015
 * Debian Sid / gcc 5.2.1, clang 3.5.0
 * Kali Linux 2 / gcc 4.9.2, clang 3.5.0

Other platforms are not supported at this time.

## Known issues

* Neither the `TcpScanner` nor the `UdpScanner` classes receive the `WSAECONNREFUSED` (`ECONNREFUSED` on Linux) error on Windows. There is little documentation on non-blocking sockets and this particular error. The [783052b](https://github.com/RoliSoft/Host-Scanner/commit/783052b49d39c3f2833e93c9bc183088eaec8797) commit tried using native `WSA*()` calls, as the documentation says `WSAECONNREFUSED` would be signalled on `FD_CONNECT`, but that is not happening, `WSAWaitForMultipleEvents()` returns either `WSA_WAIT_EVENT_0` or the undocumented `258` value, while `WSAGetLastError()` either returns `0` or `WSAEWOULDBLOCK`. The result of this issue is that on Windows, connections to non-listening ports will only be marked as dead after the timeout period has elapsed, while on Linux, the scan returns as soon as the ICMP packet is received.