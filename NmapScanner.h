#pragma once
#include <string>
#include "Stdafx.h"
#include "HostScanner.h"

/*!
 * Provides interoperability with Nmap.
 */
class NmapScanner : public HostScanner
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
	~NmapScanner() override;

private:

	/*!
	 * Runs Nmap on the specified hosts.
	 *
	 * \param hosts List of hosts.
	 * \param v6 Whether to turn on IPv6 support.
	 *
	 * \remarks Turning on IPv6 support means that IPv4 will be turned off.
	 *
	 * \return XML response from Nmap.
	 */
	std::string runNmap(Hosts* hosts, bool v6 = false);

	/*!
	 * Parses the specified XML output and updates matching hosts and services.
	 *
	 * \param xml XML response from Nmap.
	 * \param hosts List of hosts.
	 */
	void parseXml(std::string xml, Hosts* hosts);

};
