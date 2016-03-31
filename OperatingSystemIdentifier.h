#pragma once
#include "Stdafx.h"
#include "Host.h"

/*!
 * Represents an operating system identifier.
 */
class OperatingSystemIdentifier
{
public:

	/*!
	 * Processes the specified host.
	 * 
	 * \param host Scanned host.
	 * 
	 * \return true if the operating system was identified,
	 * 		   otherwise false.
	 */
	virtual bool Scan(Host* host) = 0;

	/*!
	 * Tries to processes the specified host with all known implementations of this class.
	 *
	 * \param host Scanned host.
	 * 
	 * \return true if the operating system was identified,
	 * 		   otherwise false.
	 */
	static bool AutoProcess(Host* host);

	/*!
	 * Resolves the value of the enum `OpSys` to its textual representation.
	 *
	 * \param opsys Enum value.
	 *
	 * \return Textual representation.
	 */
	static std::string OpSysString(OpSys opsys);

	/*!
	 * Frees up the resources allocated during the lifetime of this instance.
	 */
	virtual ~OperatingSystemIdentifier();
	
};
