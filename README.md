# Host Scanner

The purpose of this project is to discover hosts on a network and then port scan them.

## Implemented features

* TCP scanner
  * A high-performance TCP scanner which initiates the three-way handshake by multiplexing non-blocking sockets and grabs the service banner.

* UDP scanner
  * Uses a list of known port numbers and sends a specifically crafted payload in order to try and get an answer from the server, if there are any listening.

* ICMP pinger
  * Support for ICMP Echo Request packets (also known as "standard ping") to determine if a host is alive.

* ARP pinger
  * Support for ARP Request packets to map alive hosts on a local network.

* External scanners
  * Ability to use external tools for all the scanning needs, instead of the built-in scanners. Currently Nmap support is implemented, more to follow if needed.

* Unit tests
  * All features are covered by unit tests which are run on three platforms in order to ensure utmost stability and portability.

* Portability
  * Features are implemented (when a standardized API is not available) using raw sockets on Linux, WinPcap on Windows, and Berkeley Packet Filter on BSD / OS X.

## Planned features

* Network mapping
  * ~~ARP requests for IPv4~~ ✓
  * Neighbor Solicitation for IPv6

* Host discovery
  * Send standard ICMP ping
  * Send TCP SYN to port 80, if ACK or RST received, host is alive
  * Send UDP packet to port 53, if response or ICMP "port unreachable", host is alive
  * _Otherwise assume host is offline or heavily firewalled_

* ~~Port scanning~~ ✓
  * ~~Send TCP SYN to all or popular ports, get service banner on ACK~~ ✓
  * ~~Send crafted UDP packets to known ports~~ ✓

* ~~External tools~~ ✓
  * ~~Integrate with external tools for failover/preference~~ ✓
    * ~~nmap~~ ✓

* Reporting
  * Results will be forwarded to agent for further processing

## How to run

To compile and run the project, you must first install the dependencies, which on Debian (and on its derivatives) can be done with:

    apt-get install build-essential cmake libboost-dev libboost-test-dev libboost-program-options-dev

After the dependencies have been installed, you can check out the repository and compile it with the following commands:

    git clone https://github.com/RoliSoft/Host-Scanner.git
    cd Host-Scanner/build
    cmake ..
    make

If the compilation was successful, you can run it with the `./HostScanner` command. Tests are also available, you may run them through `make test` or directly, by executing `./TestScanner`.

Tested on:

 * Windows 10 / Visual Studio 2015
 * Debian Sid / gcc 5.2.1, clang 3.8.0
 * Kali Linux 2 / gcc 4.9.2, clang 3.5.0
 * FreeBSD 11 / clang 3.7.0
 * OS X 10.11 / AppleClang 7.0.0

Other platforms are not supported at this time.

## Known issues

* Neither the `TcpScanner` nor the `UdpScanner` classes receive the `WSAECONNREFUSED` (`ECONNREFUSED` on Linux) error on Windows. There is little documentation on non-blocking sockets and this particular error. The [783052b](https://github.com/RoliSoft/Host-Scanner/commit/783052b49d39c3f2833e93c9bc183088eaec8797) commit tried using native `WSA*()` calls, as the documentation says `WSAECONNREFUSED` would be signalled on `FD_CONNECT`, but that is not happening, `WSAWaitForMultipleEvents()` returns either `WSA_WAIT_EVENT_0` or the undocumented `258` value, while `WSAGetLastError()` either returns `0` or `WSAEWOULDBLOCK`. The result of this issue is that on Windows, connections to non-listening ports will only be marked as dead after the timeout period has elapsed, while on Linux, the scan returns as soon as the ICMP packet is received.