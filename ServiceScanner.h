#pragma once
#include "Stdafx.h"
#include "Service.h"

/*!
 * Represents a port scanner.
 */
class ServiceScanner
{
public:

	/*!
	 * Get a task which scans a service to determine its aliveness.
	 *
	 * \param service Service to scan.
	 * 
	 * \return Task to scan the specified service.
	 */
	virtual void* GetTask(Service* service) = 0;

	/*!
	 * Dumps the scan results into the standard output.
	 *
	 * \param services List of services.
	 */
	static void DumpResults(Services* services);

	/*!
	 * Frees up the resources allocated during the lifetime of this instance.
	 */
	virtual ~ServiceScanner();
	
};
