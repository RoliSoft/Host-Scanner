#pragma once
#include "Stdafx.h"
#include "Host.h"

/*!
 * Represents a host scanner.
 */
class HostScanner
{
public:

	/*!
	 * Scans a host to determine service availability.
	 * 
	 * \param host Host.
	 */
	virtual void Scan(Host* host) = 0;

	/*!
	 * Scans a list of hosts to determine service availability.
	 * 
	 * \param hosts List of hosts.
	 */
	virtual void Scan(Hosts* hosts) = 0;

	/*!
	 * Scans a network range to determine service availability.
	 *
	 * \param address IP address.
	 * \param cidr CIDR value.
	 *
	 * \return List of scanned services.
	 */
	Hosts* ScanCidr(char* address, int cidr);

	/*!
	 * Scans a network range to determine service availability.
	 *
	 * \param start IP address to start with.
	 * \param finish IP address to end with.
	 *
	 * \return List of scanned services.
	 */
	Hosts* ScanRange(char* start, char* finish);

	/*!
	 * Dumps the scan results into the standard output.
	 *
	 * \param hosts List of hosts.
	 */
	static void DumpResults(Hosts* hosts);

	/*!
	 * Frees up the resources allocated during the lifetime of this instance.
	 */
	virtual ~HostScanner();

private:

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
