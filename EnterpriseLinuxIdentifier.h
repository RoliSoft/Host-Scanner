#pragma once
#include "Stdafx.h"
#include "OperatingSystemIdentifier.h"
#include <unordered_map>

/*!
 * Implements functionality for identifying Red Hat and CentOS based on service banners.
 */
class EnterpriseLinuxIdentifier : public OperatingSystemIdentifier
{
public:

	/*!
	* OpenSSH version numbers mapped to the RHEL/CentOS version they came with.
	*/
	static const std::unordered_map<std::string, int> BundledVersions;
	
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
	~EnterpriseLinuxIdentifier() override;


};
