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
	 * Initializes a new instance of this class.
	 */
	PassiveScanner() = default;

	/*!
	 * Initializes a new instance of this class.
	 *
	 * \param shodan_key Shodan API key to use for the requests.
	 * \param censys_auth Censys API username and password to use for the requests.
	 * \param looquer_key Mr Looquer API key to use for the requests.
	 */
	PassiveScanner(const std::string& shodan_key, const std::string& censys_auth, const std::string& looquer_key);

	/*!
	 * Sets the specified API key for the Shodan scanner.
	 *
	 * \param key API key to set.
	 */
	void SetShodanKey(const std::string& key);

	/*!
	 * Value indicating whether a Shodan API key was specified.
	 *
	 * \return true if key is present, otherwise false.
	 */
	bool HasShodanKey();

	/*!
	 * Sets the specified API endpoint location for the Shodan scanner.
	 *
	 * \param uri API location to set.
	 */
	void SetShodanEndpoint(const std::string& uri);

	/*!
	 * Sets the specified API key for the Censys scanner.
	 *
	 * \param key API key to set.
	 */
	void SetCensysKey(const std::string& key);

	/*!
	 * Value indicating whether a Censys API key was specified.
	 *
	 * \return true if key is present, otherwise false.
	 */
	bool HasCensysKey();

	/*!
	 * Sets the specified API endpoint location for the Censys scanner.
	 *
	 * \param uri API location to set.
	 */
	void SetCensysEndpoint(const std::string& uri);

	/*!
	 * Sets the specified API key for the Looquer scanner.
	 *
	 * \param key API key to set.
	 */
	void SetLooquerKey(const std::string& key);

	/*!
	* Value indicating whether a Looquer API key was specified.
	*
	* \return true if key is present, otherwise false.
	*/
	bool HasLooquerKey();

	/*!
	 * Sets the specified API endpoint location for the Looquer scanner.
	 *
	 * \param uri API location to set.
	 */
	void SetLooquerEndpoint(const std::string& uri);

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
	~PassiveScanner() override;

private:
	
	/*!
	 * Shodan API key to use for the requests.
	 */
	std::string shodan_key;

	/*!
	 * API endpoint location of Shodan.
	 */
	std::string shodan_uri;

	/*!
	 * Censys API username and password to use for the requests.
	 */
	std::string censys_auth;

	/*!
	 * API endpoint location of Censys.
	 */
	std::string censys_uri;
	
	/*!
	 * Mr Looquer API key to use for the requests.
	 */
	std::string looquer_key;

	/*!
	 * API endpoint location of Mr Looquer.
	 */
	std::string looquer_uri;

	/*!
	 * Merges two host results.
	 *
	 * \param src Scan result to merge.
	 * \param dst Destination for the merger.
	 */
	static void mergeHosts(Host* src, Host* dst);

	/*!
	 * Merges two service results.
	 *
	 * \param src Service to merge.
	 * \param dst Destination for the merger.
	 */
	static void mergeServices(Service* src, Service* dst);

};
