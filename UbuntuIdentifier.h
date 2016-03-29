#pragma once
#include "Stdafx.h"
#include "OpSysIdentifier.h"
#include <unordered_map>

/*!
 * Implements functionality for identifying Ubuntu based on service banners.
 */
class UbuntuIdentifier : public OpSysIdentifier
{
public:
	
	/*!
	 * Processes the specified host.
	 * 
	 * \param host Scanned host.
	 */
	bool Scan(Host* host) override;

	/*!
	 * Frees up the resources allocated during the lifetime of this instance.
	 */
	~UbuntuIdentifier() override;

private:

	/*!
	 * Ubuntu distribution names mapped to their version numbers.
	 */
	static std::unordered_map<std::string, float> versionNames;

	/*!
	 * OpenSSH version numbers mapped to the Ubuntu version they came with.
	 */
	static std::unordered_map<std::string, float> bundledVersions;

};
