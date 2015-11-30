#pragma once
#include "Stdafx.h"
#include "PortScanner.h"
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
	char adapter[260];

#if Unix

	/*!
	 * Interface number.
	 */
	int ifnum;

#endif
	
	/*!
	 * Human-friendly description of the interface.
	 */
	char description[132];
	
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
class ArpPinger : public PortScanner
{
public:
	
	/*!
	 * Number of milliseconds to wait for a reply packet.
	 */
	unsigned long timeout = 1000;

	/*!
	 * Scans a service to determine aliveness.
	 * 
	 * \param service Service.
	 */
	void Scan(Service* service) override;

	/*!
	 * Scans a list of services to determine aliveness.
	 * 
	 * \param services List of services.
	 */
	void Scan(Services* services) override;

	/*!
	 * Creates a new instance of this type.
	 */
	ArpPinger();

	/*!
	 * Frees up the resources allocated during the lifetime of this instance.
	 */
	~ArpPinger() override;

private:

	/*!
	 * List of available interfaces and their properties.
	 */
	std::vector<Interface*> interfaces;

	/*!
	 * Makes the required preparations in order to determine whether this
	 * service is eligible for this type of scanning or not.
	 *
	 * \param service Service.
	 */
	void prepService(Service* service);

	/*!
	 * Sends an ARP Request packet to the specified service.
	 *
	 * \param service Service.
	 */
	void sendRequest(Service* service);

	/*!
	 * Sniffs the specified interfaces for ARP reply packets.
	 *
	 * \param ifaces Interfaces to sniff.
	 * \param services Services mapped to their IP addresses in decimal formats,
	 *                 for faster look-ups during packet processing.
	 */
	void sniffReplies(std::unordered_set<Interface*> ifaces, std::unordered_map<unsigned int, Service*> services);

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
