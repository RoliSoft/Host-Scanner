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
	 * Value indicating whether this instance is a passive scanner.
	 * 
	 * A passive scanner does not actively send packets towards the
	 * scanned target, it instead uses miscellaneous data sources to
	 * gather information regarding the target.
	 * 
	 * \return true if passive, false if not.
	 */
	virtual bool IsPassive() = 0;

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
	 * Generates a host list for a network range.
	 *
	 * \param address IP address.
	 * \param cidr CIDR value.
	 * \param hosts Existing list to fill, if any.
	 *
	 * \return List of hosts.
	 */
	static Hosts* GenerateCidr(const char* address, int cidr, Hosts* hosts = nullptr);

	/*!
	 * Generates a host list for a network range.
	 *
	 * \param start IP address to start with.
	 * \param finish IP address to end with.
	 * \param hosts Existing list to fill, if any.
	 *
	 * \return List of hosts.
	 */
	static Hosts* GenerateRange(const char* start, const char* finish, Hosts* hosts = nullptr);

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
	static const char* uintToIp(unsigned ip);

};
