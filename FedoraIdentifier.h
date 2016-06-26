#pragma once
#include "Stdafx.h"
#include "OperatingSystemIdentifier.h"
#include <unordered_map>

/*!
 * Implements functionality for identifying Fedora based on service banners.
 */
class FedoraIdentifier : public OperatingSystemIdentifier
{
public:

	/*!
	* OpenSSH version numbers mapped to the Fedora version they came with.
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
	~FedoraIdentifier() override;

};
