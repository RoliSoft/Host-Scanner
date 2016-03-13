#pragma once
#include "Stdafx.h"
#include "HostScanner.h"
#include <string>

/*!
 * Implements a passive scanner which returns Shodan data.
 */
class ShodanScanner : public HostScanner
{
public:
	
	/*!
	 * API key to use for the requests.
	 */
	std::string key;

	/*!
	 * API endpoint location.
	 */
	std::string endpoint = "api.shodan.io/shodan";

	/*!
	 * Initializes a new instance of this class.
	 */
	ShodanScanner() = default;

	/*!
	 * Initializes a new instance of this class.
	 *
	 * \param key API key to use for the requests.
	 */
	ShodanScanner(const std::string& key);

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
	~ShodanScanner() override;

private:

	/*!
	 * Gets the information available on the API for the specified host.
	 *
	 * \param host Host.
	 */
	void getHostInfo(Host* host);

};
