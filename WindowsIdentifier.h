#pragma once
#include "Stdafx.h"
#include "OperatingSystemIdentifier.h"

/*!
 * Implements functionality for identifying Windows based on service banners.
 */
class WindowsIdentifier : public OperatingSystemIdentifier
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
	bool Scan(Host* host) override;

	/*!
	 * Frees up the resources allocated during the lifetime of this instance.
	 */
	~WindowsIdentifier() override;

};
