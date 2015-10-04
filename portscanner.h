#pragma once
#include "service.h"

/*!
 * Represents a port scanner.
 */
class PortScanner
{
public:

	/*!
	 * Scans a service to determine aliveness.
	 * 
	 * \param service Service.
	 */
	virtual void Scan(Service* service) = 0;

	/*!
	 * Scans a list of services to determine aliveness.
	 * 
	 * \param services List of services.
	 */
	virtual void Scan(Services* services) = 0;

	/*!
	 * Dumps the scan results into the standard output.
	 */
	void DumpResults(Services* services);

};