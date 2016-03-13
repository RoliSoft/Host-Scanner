#pragma once
#include "Stdafx.h"
#include "HostScanner.h"
#include <string>

/*!
 * Implements a virtual scanner which returns data from all available passive scanners.
 */
class PassiveScanner : public HostScanner
{
public:
	
	/*!
	 * Shodan API key to use for the requests.
	 */
	std::string shodan_key;

	/*!
	 * Censys API username and password to use for the requests.
	 */
	std::string censys_auth;

	/*!
	 * Initializes a new instance of this class.
	 */
	PassiveScanner() = default;

	/*!
	 * Initializes a new instance of this class.
	 *
	 * \param shodan_key Shodan API key to use for the requests.
	 * \param censys_auth Censys API username and password to use for the requests.
	 */
	PassiveScanner(const std::string& shodan_key, const std::string& censys_auth);

	/*!
	 * Scans a host to determine service availability.
	 * 
	 * \param host Host.
	 */
	void Scan(Host* host) override;

	/*!
	 * Scans a list of hosts to determine service availability.
	 * 
	 * \param hosts List of hosts.
	 */
	void Scan(Hosts* hosts) override;

	/*!
	 * Frees up the resources allocated during the lifetime of this instance.
	 */
	~PassiveScanner() override;

private:

	/*!
	 * Merges two host results.
	 *
	 * \param src Scan result to merge.
	 * \param dst Destination for the merger.
	 */
	void mergeHosts(Host* src, Host* dst);

	/*!
	 * Merges two service results.
	 *
	 * \param src Service to merge.
	 * \param dst Destination for the merger.
	 */
	void mergeServices(Service* src, Service* dst);

};
