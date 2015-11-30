#pragma once
#include "Stdafx.h"
#include "ServiceScanner.h"

/*
 * Implements the factory pattern for retrieving port scanner instances.
 */
class ServiceScannerFactory
{
public:

	/*!
	 * Gets a scanner instance which supports the specified criteria.
	 *
	 * \param protocol IP protocol.
	 * \param external Whether to use an external scanner.
	 */
	static ServiceScanner* Get(IPPROTO protocol, bool external = false);

};
