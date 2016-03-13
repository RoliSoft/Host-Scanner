#pragma once
#include "Stdafx.h"
#include "HostScanner.h"

/*!
 * Implements a host scanner.
 * 
 * The purpose of this scanner is to scan the specified list of addresses
 * and determine which one is alive.
 */
class InternalScanner : public HostScanner
{
public:
	
	/*!
	 * Number of milliseconds to wait for connections to finish.
	 * Since this scanner uses multiple sub-scanners, this will be the
	 * applied timeout to each individual scanner, multiplying the final timeout.
	 */
	unsigned long timeout = 3000;

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
	~InternalScanner() override;

};
