#pragma once
#include "Stdafx.h"
#include "HostScanner.h"
#include <string>

/*!
 * Implements a passive scanner which returns Mr. Looquer data.
 */
class LooquerScanner : public HostScanner
{
public:
	
	/*!
	 * API key to use for the requests.
	 */
	std::string key;

	/*!
	 * API endpoint location.
	 */
	std::string endpoint = "https://mrlooquer.com/api";

	/*!
	 * Initializes a new instance of this class.
	 */
	LooquerScanner() = default;

	/*!
	 * Initializes a new instance of this class.
	 *
	 * \param key API key to use for the requests.
	 */
	explicit LooquerScanner(const std::string& key);

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
	~LooquerScanner() override;

private:

	/*!
	 * Gets the information available on the API for the specified host.
	 *
	 * \param host Host.
	 */
	void getHostInfo(Host* host);

};
