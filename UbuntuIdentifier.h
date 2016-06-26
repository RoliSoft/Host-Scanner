#pragma once
#include "Stdafx.h"
#include "OperatingSystemIdentifier.h"
#include <unordered_map>
#include <unordered_set>

/*!
 * Implements functionality for identifying Ubuntu based on service banners.
 */
class UbuntuIdentifier : public OperatingSystemIdentifier
{
public:

	/*!
	 * Ubuntu distribution names mapped to their version numbers.
	 */
	static const std::unordered_map<std::string, double> VersionNames;

	/*!
	 * OpenSSH version numbers mapped to the Ubuntu version they came with.
	 */
	static const std::unordered_map<std::string, double> BundledVersions;

	/*!
	 * List of Long Term Support versions.
	 */
	static const std::unordered_set<double> LtsVersions;
	
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
	~UbuntuIdentifier() override;

};
