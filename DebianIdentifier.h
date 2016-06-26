#pragma once
#include "Stdafx.h"
#include "OperatingSystemIdentifier.h"
#include <unordered_map>

/*!
 * Implements functionality for identifying Debian based on service banners.
 */
class DebianIdentifier : public OperatingSystemIdentifier
{
public:

	/*!
	 * Debian distribution names mapped to their version numbers.
	 */
	static const std::unordered_map<std::string, int> VersionNames;

	/*!
	 * OpenSSH version numbers mapped to the Debian version they came with.
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
	~DebianIdentifier() override;

};
