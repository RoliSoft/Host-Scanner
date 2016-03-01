#pragma once
#include <vector>
#include "Stdafx.h"
#include "Service.h"

/*!
 * Represents a host which hosts a collection of services.
 */
class Host
{
public:

	/*!
	 * Remote address.
	 */
	std::string address;
	
	/*!
	 * Whether the service is alive at this host.
	 */
	bool alive = false;
	
	/*!
	 * Reason for the value specified in `alive`.
	 * Negative values are errors, positive values are scanner-dependent reasons.
	 */
	AliveReason reason = AR_NotScanned;

	/*!
	 * List of services on this host.
	 */
	Services* services;

	/*!
	 * Creates a new instance of this type.
	 * 
	 * \param address Remote address.
	 */
	Host(std::string address);

	/*!
	 * Frees up the resources allocated during the lifetime of this instance.
	 */
	~Host();

};

/*!
 * Represents a list of hosts.
 */
typedef std::vector<Host*> Hosts;
