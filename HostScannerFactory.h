#pragma once
#include "Stdafx.h"
#include "HostScanner.h"

/*
 * Implements the factory pattern for retrieving host scanner instances.
 */
class HostScannerFactory
{
public:

	/*!
	 * Gets a scanner instance which supports the specified criteria.
	 *
	 * \param passive Whether to fetch existing data via 3rd-party service.
	 * \param external Whether to use an external scanner.
	 * 
	 * \return Instance to be used for scanning.
	 */
	static HostScanner* Get(bool passive = false, bool external = false);

};
