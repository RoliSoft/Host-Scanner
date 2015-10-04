#pragma once
#include <vector>
#include "stdafx.h"

/*!
 * Represents a service in the form of an IP/port.
 */
class Service
{
public:

	/*!
	 * Remote address.
	 */
	char* address;

	/*!
	 * Remote port.
	 */
	unsigned short port;

	/*!
	 * Remote protocol.
	 */
	IPPROTO protocol;
	
	/*!
	 * Whether the service is alive at this host.
	 */
	bool alive = false;
	
	/*!
	 * Reason for the value specified in `alive`.
	 * Negative values are errors, positive values are scanner-dependent reasons.
	 */
	int reason = -1;

	/*!
	 * Service banner, if any.
	 */
	char* banner = nullptr;

	/*!
	 * Length of the service banner.
	 */
	int banlen = 0;

	/*!
	 * Object store reserved for the scanner.
	 */
	void* data = nullptr;

	/*!
	 * Creates a new instance of this type.
	 * 
	 * \param address Remote address.
	 * \param port Remote port.
	 * \param protocol Remote protocol, otherwise TCP.
	 */
	Service(char* address, unsigned short port, IPPROTO protocl = IPPROTO_TCP);

};

/*!
 * Represents a list of services.
 */
typedef std::vector<Service*> Services;