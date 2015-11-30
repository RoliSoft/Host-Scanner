#pragma once
#include "Stdafx.h"
#include "ServiceScanner.h"

/*!
 * Implements a host scanner.
 * 
 * The purpose of this scanner is to scan the specified list of addresses
 * and determine which one is alive.
 */
class InternalScanner : public ServiceScanner
{
public:
	
	/*!
	 * Number of milliseconds to wait for connections to finish.
	 * Since this scanner uses multiple sub-scanners, this will be the
	 * applied timeout to each individual scanner, multiplying the final timeout.
	 */
	unsigned long timeout = 1000;

	/*!
	 * Indicates whether to use ICMP Echo Request packets.
	 */
	bool useIcmp = true;

	/*!
	 * Indicates whether to test common TCP ports with SYN scanner.
	 */
	bool useTcp = true;

	/*!
	 * Indicates whether to test common UDP ports with specifically crafted payloads.
	 */
	bool useUdp = true;

	/*!
	 * Scans a host to determine aliveness.
	 * 
	 * \param service Service.
	 */
	void Scan(Service* service) override;

	/*!
	 * Scans a list of hosts to determine aliveness.
	 * 
	 * \param services List of services.
	 */
	void Scan(Services* services) override;

	/*!
	 * Frees up the resources allocated during the lifetime of this instance.
	 */
	~InternalScanner() override;

private:
	
	/*!
	 * Creates a list of IP addresses based on the specified CIDR notation.
	 * 
	 * \param address IP address.
	 * \param cidr CIDR value.
	 */
	static void createCidrList(char* address, int cidr);
	
	/*!
	 * Creates a list of IP addresses starting from address specified by `start`,
	 * and finishing in address specified by `finish`, inclusively.
	 * 
	 * \param start IP address to start with.
	 * \param finish IP address to end with.
	 */
	static void createRangeList(char* start, char* finish);
	
	/*!
	 * Creates a bitmask from the specified value which will be used to generate
	 * an IP address list with a starting address and this being the CIDR value.
	 * 
	 * \param cidr CIDR value to create bitmask for.
	 */
	static unsigned createBitmask(int cidr);
	
	/*!
	 * Transforms the specified IP address from unsigned integer form to its string notation.
	 * 
	 * \param ip Numerical form of the IP address.
	 */
	static char* uintToIp(unsigned ip);

};
