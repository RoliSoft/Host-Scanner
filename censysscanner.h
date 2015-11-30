#pragma once
#include "Stdafx.h"
#include "ServiceScanner.h"
#include <tuple>

/*!
 * Implements a passive scanner which returns Censys data.
 */
class CensysScanner : public ServiceScanner
{
public:
	
	/*!
	 * API username and password to use for the requests.
	 */
	std::tuple<std::string, std::string> auth;

	/*!
	 * API endpoint location.
	 */
	std::string endpoint = "censys.io/api/v1";

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
	~CensysScanner() override;

private:

	/*!
	 * Gets the information available on the API for the specified service.
	 *
	 * \param service Service.
	 */
	void getHostInfo(Service* service);

};
