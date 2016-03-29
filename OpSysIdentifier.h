#pragma once
#include "Stdafx.h"
#include "Host.h"

/*!
 * Represents an operating system identifier.
 */
class OpSysIdentifier
{
public:

	/*!
	 * Processes the specified host.
	 * 
	 * \param host Scanned host.
	 */
	virtual bool Scan(Host* host) = 0;

	/*!
	 * Tries to processes the specified host with all known implementations of this class.
	 *
	 * \param host Scanned host.
	 */
	static bool AutoProcess(Host* host);

	/*!
	 * Frees up the resources allocated during the lifetime of this instance.
	 */
	virtual ~OpSysIdentifier();
	
};
