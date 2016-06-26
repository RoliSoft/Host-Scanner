# Host Scanner

The purpose of this project is to implement a network scanner with both active and passive data acquisition components, which can then autonomously identify services using the latest CPE dictionary from NIST and discover the vulnerabilities of those by querying the CVE database.

## Features

* TCP Scanner
  * High-performance TCP scanner which initiates the three-way handshake (also called "TCP connect scan") by multiplexing non-blocking sockets and grabbing their service banners.

* UDP Scanner
  * Makes use of a database of specifically crafted payloads mapped to port numbers in order to try and get an answer from the UDP services, if there are any listening.

* ICMP Pinger
  * Support for the use of ICMP Echo Request packets (also known as "standard ping") in order to determine if a host is alive.

* ARP Pinger
  * Support for the use of ARP Who-Has Request packets in order to map online hosts on a local network. Useful when ICMP packets are filtered on a network.

* External Scanners
  * Ability to use external tools for all the active or passive scanning needs, instead of the built-in scanners:
    * Launch new scans with or process earlier XML outputs from Nmap.

* Online Sources
  * Support for passive reconnaissance by fetching data already available from relevant services intended for security researchers:
    * Shodan
    * Censys
    * Mr Looquer

* Service Identification
  * Autonomous Identification:
    * Latest CPE dictionary from NIST is used to map service banners to their CPE names.
  * Pattern-based Identification:
    * Database of regular expressions can be used as a redundancy to map service banners to their CPE names.

* Vulnerabilitiy Assessment
  * Based on the CVE database, the resolved CPE names (which also include version numbers) are matched against the affected software list of each CVE entry to discover service vulnerabilities.

* Package Lookup
  * Resolve CPE names to actual operating system packages and get a simple command to update only the vulnerable versions for:
    * Debian (oldstable to unstable), Ubuntu (all current and lts versions)
    * Red Hat (5-7), CentOS (5-7), Fedora (all current and rawhide)

* Vulnerability Validation
  * Use the package manager, security or bug tracker of the identified distribution to check whether a package is vulnerable, whether a vendor patch is available, and whether it is installed or not.

* Estimate System Upgrade Date
  * Using the changelog of the discovered packages with version numbers and security patch information, estimate the date range of the last system upgrade of the host.

* Reporting
  * Generate a L<sup>A</sup>T<sub>E</sub>X report of the scanned network, which includes open ports, identified services, discovered vulnerabilities and mitigation recommendations.

* Unit Tests
  * All features are covered by unit tests which are run on three platforms in order to ensure utmost stability and portability.

* Portability
  * Features are implemented (when a standardized API is not available) using raw sockets on Linux, WinPcap on Windows, and Berkeley Packet Filter on BSD / OS X.

## Usage

	usage: HostScanner [args] targets
	arguments:

	  -t [ --target ] arg     List of targets to scan:
	                            Each can be a hostname, IP address, IP range or CIDR.
	                            E.g. `192.168.1.1/24` is equivalent to `192.168.1.0-192.168.1.255`.

	  -p [ --port ] arg       TCP ports to scan:
	                            Can be a single port (80), a list (22,80) or a range (1-1024).
	                            Range can be unbounded from either sides, simultaneously.
	                            E.g. `1024-` will scan ports 1024-65535. `-` will scan all ports.
	                            Specifying `top` or `t` will scan the top 100 most popular ports.

	  -u [ --udp-port ] arg   UDP ports to scan:
	                            Supports the same values as --port, with the difference that
	                            specifying `top` will scan all of the ports with known payloads.

	  -s [ --scanner ] arg    Scanner instance to use:
	                            internal - Uses the built-in scanner. (active)
	                            nmap     - Uses 3rd-party application Nmap. (active)
	                            shodan   - Uses data from Shodan. (passive; requires API key)
	                            censys   - Uses data from Censys. (passive; requires API key)
	                            looquer  - Uses data from Mr Looquer. (passive; requires API key)
	                            shosys   - Uses data from Shodan, Censys and Mr Looquer. (passive)

	  --shodan-key arg        Specifies an API key for Shodan.
	  --shodan-uri arg        Overrides the API endpoint used for Shodan. You may specify an URI
	                          starting with file:// pointing to a directory containing previously
	                          downloaded JSON responses.
	                            Default: https://api.shodan.io/shodan

	  --censys-key arg        Specifies an API key for Censys in the `uid:secret` format.
	  --censys-uri arg        Overrides the API endpoint used for Censys. You may specify an URI
	                          starting with file:// pointing to a directory containing previously
	                          downloaded JSON responses.
	                            Default: https://censys.io/api/v1

	  --looquer-key arg       Specifies an API key for Mr Looquer.
	  --looquer-uri arg       Overrides the API endpoint used for Mr Looquer. You may specify an URI
	                          starting with file:// pointing to a directory containing previously
	                          downloaded JSON responses.
	                            Default: https://mrlooquer.com/api/v1

	  -f [ --input-file ] arg Process an input file with the selected scanner.
	                            E.g. the nmap scanner can parse XML reports.

	  -d [ --delay ] arg      Delay between packets sent to the same host. Default is 3 for 100ms.
	                          Possible values are 0..6, which have the same effect as nmap's -T:
	                            0 - 5m, 1 - 15s, 2 - 400ms, 3 - 100ms, 4 - 10ms, 5 - 5ms, 6 - no delay

	  -r [ --resolve ]        Resolves vulnerable CPE names to their actual package names depending on
	                          the automatically detected operating system of the host.

	  -w [ --validate ]       Validate all vulnerabilities with the package manager of the distribution.

	  -e [ --estimate ]       Estimate date range of the last system upgrade based on the installed
	                          package versions and security patches.

	  -o [ --output-latex ] arg Exports the scan results into a LaTeX file, with all the available
	                            information gathered during the scan.

	  -x [ --passive ]        Globally disables active reconnaissance. Functionality using active
	                          scanning will break, but ensures no accidental active scans will be
	                          initiated, which might get construed as hostile.

	  -l [ --logging ] arg    Logging level to use:
	                            i, int - All messages.
	                            d, dbg - All debug messages and up.
	                            v, vrb - Enable verbosity, but don't overdo it.
	                            m, msg - Print only regular messages. (default)
	                            e, err - Print only error messages to stderr.

	  -q [ --no-logo ]        Suppresses the ASCII logo.
	  -v [ --version ]        Display version information.
	  -h [ --help ]           Displays this message.

### Examples

Scan a network for vulnerabilities on the top 100 TCP ports and known UDP ports using the internal scanners:

	./HostScanner -p t -u t 192.168.1.0/24

Scan an IP address or netblock for vulnerabilities passively, with data from Shodan, Censys and Mr Looquer:

	./HostScanner -x 178.62.192.0/18

Perform service identification and vulnerability analysis on an earlier XML output of nmap through `nmap -oX report.xml …`:

	./HostScanner -s nmap -f report.xml

Get list of vulnerable packages and command to upgrade it on the host:

	./HostScanner -r 192.168.1.66 192.168.1.71

The above will scan the TCP ports of the specified addresses, perform operating system and service detection followed by vulnerability analysis, and lookup the packages needed to be updated for the discovered CVEs to be mitigated:

	[*] 192.168.1.66 is running cpe:/o:debian:debian_linux:8
	[*] 192.168.1.71 is running cpe:/o:redhat:enterprise_linux:7
	    ...
	[*] 192.168.1.66 -> sudo apt-get install --only-upgrade apache2 php5 python2.7
	[*] 192.168.1.71 -> sudo yum update httpd php python27-python

Generate a L<sup>A</sup>T<sub>E</sub>X report with all the information gathered during the scan, including open ports, identified services, discovered vulnerabilities and mitigation recommendations:

	./HostScanner -o report.tex -r 192.168.1.66 192.168.1.71

### Persistent Options

The application supports reading configuration files which allow for settings to persist.

On Linux, the following paths will be probed, and the first file found will be read, in this order:

	%AppPath%/HostScanner.ini
	~/.HostScanner.conf
	/etc/HostScanner/HostScanner.conf

On Windows:

	%AppPath%\HostScanner.ini
	%AppData%\RoliSoft\Host Scanner\HostScanner.ini

As an example, this feature can be used to persist Shodan/Censys API keys:

	shodan-key=abcdefghijklmnopqrstuvwxyz012345
    censys-key=abcdefgh-ijkl-mnop-qrst-uvwxyz012345:abcdefghijklmnopqrstuvwxyz012345
    looquer-key=abcdefghijklmnopqrstuvwxyz012345

Similarly, the `-x` option can be stored, in order to globally disallow any active scanner usage as a fail-safe:

	passive

This option cannot be disabled through the command line. To use an active scanner again, this line needs to be removed from the configuration file. Otherwise, only analysis of Shodan/Censys/Looquer data and nmap reports are allowed.

## Building

To compile and run the application, you must first install the dependencies, which can be done with:

 * Debian/Ubuntu/Kali:

        apt install build-essential cmake libcurl4-openssl-dev libsqlite3-dev libboost-all-dev libz-dev

 * RHEL/CentOS/Fedora:

        yum install gcc-c++ make cmake libcurl-devel sqlite-devel boost-devel-static zlib-devel

 * FreeBSD:

        pkg install cmake curl sqlite3 boost-libs

 * Mac OS X: (with [Homebrew](http://brew.sh/))

        xcode-select --install && brew install cmake curl sqlite boost

 * Windows _or_ any of the above platforms if problems arise with the vendor packages: (with [Conan](https://conan.io/))

        conan install --build=missing

   When executed in the project root, downloads and/or builds all required dependencies for the project and generates a `conanbuildinfo.cmake` file, which when exists, will be used by `CMakeLists.txt` to configure include directories and link targets.

After the dependencies have been installed, you can check out the repository and compile it with the following commands:

    git clone https://github.com/RoliSoft/Host-Scanner.git
    cd Host-Scanner/build
    cmake ..
    make

If the compilation was successful, you can run it with the `./HostScanner` command. Tests are also available, you may run them through `make test` or directly, by executing `./TestScanner`.

## Distribution

The `distrib` folder contains the `Dockerfile` and scripts to pull, compile and package the latest revision. The `.deb` package is generated with the current Debian Stable (`debian:latest` in Docker Hub) while the `.rpm` package is generated with the current Fedora version. (`fedora:latest`)

Since Boost is statically linked during compilation, the dynamic dependencies for now are `libcurl`, `libsqlite3` and `zlib` for both distributions.

The files will be generated by CMake's packaging component, CPack, whose configuration can be found in `CPackConfig.cmake`.

In order to set up these build environments, you must first compile the container:

    cd distrib/deb
    docker build -t debbuild .

After this, the `debbuild` container will be available for any compilations needs. To bake a fresh `.deb`, just run:

    docker run -it debbuild

This will pull a fresh copy of the repository _inside_ the container, therefore any changes to the repository on your host machine will not be reflected. If you wish to compile you own fork or a different branch, you'll have to modify the `compile.sh` file next to the preferred `Dockerfile` and rebuild the container.

## Portability

You'll need a fairly new compiler, as C++14 features are used in the code. As for platforms, the application is compiled and unit-tested periodically on the following:

 * Windows
   * Windows 10 / Visual Studio 2015

 * Linux
   * Debian stable, unstable / gcc, clang
   * Fedora latest, rawhide / gcc, clang

The project was developed with support in mind for the following platforms, however continuous integration is not available for these platforms, therefore builds might break until tested or otherwise observed:

 * BSD/Darwin
   * FreeBSD 11 / clang 3.7.0
   * OS X 10.11 / AppleClang 7.0.0

Other platforms are not supported at this time.

## Permissions

Some features of the application require elevated privileges in order to run:

* `IcmpPinger` uses raw sockets in order to send and receive ICMP packets.
  * *Windows*: Administrator privileges are required.
  * *Linux*: root user _or_ `CAP_NET_RAW` capability is required.
  * *BSD / OS X*: root user is required.

* `ArpPinger` crafts, sends and listens for raw Ethernet frames.
  * *Windows*: [WinPcap](http://www.winpcap.org/install/default.htm) driver is required.
  * *Linux*: root user _or_ `CAP_NET_RAW` capability is required.
  * *BSD / OS X*: root user _or_ read-write access to `/dev/bpf*` is required.

### Granting access

On Unix and Unix-like operating systems, if you wish to allow users without root privileges to run the application, you can do so by running:

    chmod +s HostScanner
    chown root:root HostScanner

This will activate the `SUID` bit, which will allow the application to escalate to root when run by an unprivileged user.

If you do not wish to run the application as root, but wish to use the features that require it, on Linux, you have the option of using the capabilities system:

    setcap cap_net_raw+eip HostScanner

This will specifically allow the use of raw sockets for this application when run by unprivileged users.

## Known issues

* Neither the `TcpScanner` nor the `UdpScanner` classes receive the `WSAECONNREFUSED` (`ECONNREFUSED` on Linux) error on Windows. There is little documentation on non-blocking sockets and this particular error. The [783052b](https://github.com/RoliSoft/Host-Scanner/commit/783052b49d39c3f2833e93c9bc183088eaec8797) commit tried using native `WSA*()` calls, as the documentation says `WSAECONNREFUSED` would be signalled on `FD_CONNECT`, but that is not happening, `WSAWaitForMultipleEvents()` returns either `WSA_WAIT_EVENT_0` or the undocumented `258` value, while `WSAGetLastError()` either returns `0` or `WSAEWOULDBLOCK`. The result of this issue is that on Windows, connections to non-listening ports will only be marked as dead after the timeout period has elapsed, while on Linux, the scan returns as soon as the ICMP packet is received.

## Licensing

Copyright (c) `2016` `RoliSoft <root@rolisoft.net>`

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version. This program is distributed in the hope that it will be useful, but without any warranty; without even the implied warranty of merchantability or fitness for a particular purpose.

For more information regarding the terms and conditions of this software, please read the full legal text of the GNU General Public License version 3, a copy of which is available in the [LICENSE.md](LICENSE.md) file. Otherwise, see &lt;<http://www.gnu.org/licenses/>&gt;.

Dual-licensing may be available upon request, depending on your purpose. For any inquiries, feel free to contact me at the email address listed above.