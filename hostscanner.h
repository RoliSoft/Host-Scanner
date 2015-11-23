#pragma once
#include "stdafx.h"
#include "portscanner.h"

/*!
 * Implements a host scanner.
 * 
 * The purpose of this scanner is to scan the specified list of addresses
 * and determine which one is alive.
 */
class HostScanner : public PortScanner
{
public:
	
	/*!
	 * Number of milliseconds to wait for connections to finish.
	 * Since this scanner uses multiple sub-scanners, this will be the
	 * applied timeout to each individual scanner, multiplying the final timeout.
	 */
	unsigned long timeout = 1000;

	/*!
	 * Indicates whether to use ICMP Echo Request packets.
	 */
	bool useIcmp = true;

	/*!
	 * Indicates whether to test common TCP ports with SYN scanner.
	 */
	bool useTcp = true;

	/*!
	 * Indicates whether to test common UDP ports with specifically crafted payloads.
	 */
	bool useUdp = true;

	/*!
	 * Scans a host to determine aliveness.
	 * 
	 * \param service Service.
	 */
	void Scan(Service* service) override;

	/*!
	 * Scans a list of hosts to determine aliveness.
	 * 
	 * \param services List of services.
	 */
	void Scan(Services* services) override;

	/*!
	 * Frees up the resources allocated during the lifetime of this instance.
	 */
	~HostScanner() override;

};
