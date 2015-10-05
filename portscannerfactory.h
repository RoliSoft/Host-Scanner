#pragma once
#include "portscanner.h"

/*
 * Implements the factory pattern for retrieving port scanner instances.
 */
class PortScannerFactory
{
public:

	/*!
	 * Gets a scanner instance which supports the specified criteria.
	 *
	 * \param protocol IP protocol.
	 */
	static PortScanner* Get(IPPROTO protocol);

};
