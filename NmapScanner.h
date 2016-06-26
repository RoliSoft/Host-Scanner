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
	 * Processes the specified XML output from nmap.
	 *
	 * \return Reconstructed list of hosts.
	 */
	Hosts* Process(const std::string& xml);

	/*!
	 * Gets the version number of the installed nmap executable.
	 *
	 * \return Version number of nmap.
	 */
	std::string GetVersion();

	/*!
	 * Frees up the resources allocated during the lifetime of this instance.
	 */
	~NmapScanner() override;

private:

	/*!
	 * The `-T` option of nmap. Value between 0..5, which maps
	 * to the same timeouts as the other scanners within this
	 * application. Level 6 will be 5, since 6 is not available.
	 */
	int delay = 3;

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
	 * \param append Whether to manipulate the host list or append to it.
	 */
	void parseXml(const std::string& xml, Hosts* hosts, bool append = false);

};
