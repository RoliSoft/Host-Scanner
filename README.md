# Host Scanner

The purpose of this project is to discover hosts on a network and then port scan them.

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

* Port scanning
  * Send TCP SYN to all or popular ports, get service banner on ACK
  * Send crafted UDP packets to known ports

* External tools
  * Integrate with external tools for failover/preference
    * nmap, msfscan

* Reporting
  * Results will be forwarded to agent for further processing