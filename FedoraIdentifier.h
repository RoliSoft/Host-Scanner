#pragma once
#include "Stdafx.h"
#include "OpSysIdentifier.h"
#include <unordered_map>

/*!
 * Implements functionality for identifying Fedora based on service banners.
 */
class FedoraIdentifier : public OpSysIdentifier
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
	~FedoraIdentifier() override;

private:

	/*!
	 * OpenSSH version numbers mapped to the Fedora version they came with.
	 */
	static std::unordered_map<std::string, int> bundledVersions;

};
