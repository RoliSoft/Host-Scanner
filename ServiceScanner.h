#pragma once
#include "Stdafx.h"
#include "Service.h"

/*!
 * Timeout option for the individual scans in milliseconds.
 * Default value is 3000ms for most scanners.
 */
#define OPT_TIMEOUT 1

/*!
 * Number of milliseconds to wait between sending packets to the same host.
 * Default value is 100ms for most scanners.
 */
#define OPT_DELAY 2

/*!
 * Boolean value indicating whether to wait for and grab the service banner.
 * Default value is true for scanners that support it.
 */
#define OPT_BANNER 5

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
	 * Gets the currently set value for the option key.
	 *
	 * \param option Option index, see `OPT_*` macros.
	 * \param value Pointer to the value to set.
	 *
	 * \return true if it succeeds, false if it fails.
	 */
	virtual bool GetOption(int option, void* value) = 0;

	/*!
	 * Sets a specified value for the option key.
	 *
	 * \param option Option index, see `OPT_*` macros.
	 * \param value Pointer to the value to set.
	 *
	 * \return true if it succeeds, false if it fails.
	 */
	virtual bool SetOption(int option, void* value) = 0;

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
