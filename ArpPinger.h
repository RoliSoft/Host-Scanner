#pragma once
#include "Stdafx.h"
#include "HostScanner.h"
#include <vector>
#include <unordered_set>
#include <unordered_map>

#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY   2

/*!
* Structure of an Ethernet packet.
*/
struct EthHeader
{
	
	/*!
	 * Destination MAC address.
	 */
	unsigned char dst[6];

	/*!
	 * Source MAC address.
	 */
	unsigned char src[6];

	/*!
	 * Protocol type. (e.g. IP)
	 */
	unsigned short typ;

};

/*!
 * Structure of an ARP packet.
 */
struct ArpHeader
{

	/*!
	 * Hardware type. (e.g. Ethernet)
	 */
	unsigned short htype;

	/*!
	 * Protocol type. (e.g. IP)
	 */
	unsigned short ptype;

	/*!
	 * Hardware size.
	 */
	unsigned char hlen;

	/*!
	 * Protocol size.
	 */
	unsigned char plen;

	/*!
	 * Packet type. (request or reply)
	 */
	unsigned short opcode;

	/*!
	 * Sender MAC address.
	 */
	unsigned char srcmac[6];

	/*!
	 * Sender IP address.
	 */
	unsigned char srcip[4];

	/*!
	 * Target MAC address.
	 */
	unsigned char dstmac[6];

	/*!
	 * Target IP address.
	 */
	unsigned char dstip[4];

};

/*!
 * Structure for holding interface information.
 */
struct Interface
{

	/*!
	 * Identifier of the interface.
	 */
	std::string adapter;

#if Unix

	/*!
	 * Interface number.
	 */
	int ifnum;

#endif
	
	/*!
	 * Human-friendly description of the interface.
	 */
	std::string description;
	
	/*!
	 * MAC address of the adapter.
	 */
	unsigned char macaddr[6];

	/*!
	 * Registered IPv4 address.
	 */
	unsigned int ipaddr;
	
	/*!
	 * IPv4 network mask.
	 */
	unsigned int ipmask;
	
	/*!
	 * IPv4 gateway.
	 */
	unsigned int ipgate;

};

/*!
 * Represents internal scan data for the ARP scanner.
 */
struct ArpScanData
{

	/*!
	 * IPv4 address in decimal format.
	 */
	unsigned int ipaddr;

	/*!
	 * Interface information.
	 */
	struct Interface* iface;

};

/*!
 * Implements a scanner which sends ARP pings using raw sockets.
 */
class ArpPinger : public HostScanner
{
public:

	/*!
	 * Creates a new instance of this type.
	 */
	ArpPinger();

	/*!
	 * Gets the currently set value for the option key.
	 *
	 * \param option Option index, see `OPT_*` macros.
	 * \param value Pointer to the value to set.
	 *
	 * \return true if it succeeds, false if it fails.
	 */
	bool GetOption(int option, void* value);

	/*!
	 * Sets a specified value for the option key.
	 *
	 * \param option Option index, see `OPT_*` macros.
	 * \param value Pointer to the value to set.
	 *
	 * \return true if it succeeds, false if it fails.
	 */
	bool SetOption(int option, void* value);

	/*!
	 * Value indicating whether this instance is a passive scanner.
	 * 
	 * A passive scanner does not actively send packets towards the
	 * scanned target, it instead uses miscellaneous data sources to
	 * gather information regarding the target.
	 * 
	 * \return true if passive, false if not.
	 */
	bool IsPassive() override;

	/*!
	 * Scans a host to determine aliveness.
	 *
	 * \param host Host.
	 */
	void Scan(Host* host) override;

	/*!
	 * Scans a list of hosts to determine aliveness.
	 *
	 * \param hosts List of hosts.
	 */
	void Scan(Hosts* hosts) override;

	/*!
	 * Frees up the resources allocated during the lifetime of this instance.
	 */
	~ArpPinger() override;

private:
	
	/*!
	 * Number of milliseconds to wait for a reply packet.
	 */
	unsigned long timeout = 3000;

	/*!
	 * List of available interfaces and their properties.
	 */
	std::vector<Interface*> interfaces;

	/*!
	 * Makes the required preparations in order to determine whether this
	 * host is eligible for this type of scanning or not.
	 *
	 * \param host Host.
	 */
	void prepareHost(Host* host);

	/*!
	 * Sends an ARP Request packet to the specified service.
	 *
	 * \param host Host.
	 */
	void sendRequest(Host* host);

	/*!
	 * Sniffs the specified interfaces for ARP reply packets.
	 *
	 * \param ifaces Interfaces to sniff.
	 * \param hosts Hosts mapped to their IP addresses in decimal formats,
	 *              for faster look-ups during packet processing.
	 */
	void sniffReplies(std::unordered_set<Interface*> ifaces, std::unordered_map<unsigned int, Host*> hosts);

	/*!
	 * Populates the list of active interfaces on the current machine.
	 */
	void loadInterfaces();

	/*!
	 * Determines whether the specified IP address is on the specified interface.
	 *
	 * \param ip IP address to check.
	 * \param inf Interface to check against.
	 *
	 * \return Value indicating whether in range.
	 */
	static bool isIpOnIface(unsigned int ip, Interface* inf);

};
