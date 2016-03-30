#pragma once
#include "Stdafx.h"
#include "OpSysIdentifier.h"
#include <unordered_map>

/*!
 * Implements functionality for identifying Debian based on service banners.
 */
class DebianIdentifier : public OpSysIdentifier
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
	~DebianIdentifier() override;

private:

	/*!
	 * Debian distribution names mapped to their version numbers.
	 */
	static std::unordered_map<std::string, int> versionNames;

	/*!
	 * OpenSSH version numbers mapped to the Debian version they came with.
	 */
	static std::unordered_map<std::string, int> bundledVersions;

};
