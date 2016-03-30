#pragma once
#include "Stdafx.h"
#include "OpSysIdentifier.h"
#include <unordered_map>

/*!
 * Implements functionality for identifying Red Hat and CentOS based on service banners.
 */
class EnterpriseLinuxIdentifier : public OpSysIdentifier
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
	~EnterpriseLinuxIdentifier() override;

private:

	/*!
	 * OpenSSH version numbers mapped to the RHEL/CentOS version they came with.
	 */
	static std::unordered_map<std::string, int> bundledVersions;

};
