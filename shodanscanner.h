#pragma once
#include "Stdafx.h"
#include "PortScanner.h"

/*!
 * Implements a passive scanner which returns Shodan data.
 */
class ShodanScanner : public PortScanner
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
	 * Frees up the resources allocated during the lifetime of this instance.
	 */
	~ShodanScanner() override;

private:

	/*!
	 * Gets the information available on the API for the specified service.
	 *
	 * \param service Service.
	 */
	void getHostInfo(Service* service);

};
