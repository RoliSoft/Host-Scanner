#pragma once
#include "Stdafx.h"
#include "Host.h"

/*!
 * Represents a host scanner.
 */
class HostScanner
{
public:

	/*!
	 * Scans a host to determine service availability.
	 * 
	 * \param host Host.
	 */
	virtual void Scan(Host* host) = 0;

	/*!
	 * Scans a list of hosts to determine service availability.
	 * 
	 * \param hosts List of hosts.
	 */
	virtual void Scan(Hosts* hosts) = 0;

	/*!
	 * Dumps the scan results into the standard output.
	 *
	 * \param hosts List of hosts.
	 */
	static void DumpResults(Hosts* hosts);

	/*!
	 * Frees up the resources allocated during the lifetime of this instance.
	 */
	virtual ~HostScanner();
	
};
