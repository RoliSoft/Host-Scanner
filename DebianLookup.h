#pragma once
#include "Stdafx.h"
#include "VendorPackageLookup.h"

/*!
 * Implements the functionality to search Debian packages.
 */
class DebianLookup : public VendorPackageLookup
{
public:
	
	/*!
	 * Looks up the status of a vulnerability in the vendor's repository.
	 *
	 * \param cve Identifier of the vulnerability.
	 * \param distrib Operating system distribution.
	 * \param ver Version number of distribution.
	 *
	 * \return List of vulnerable packages.
	 */
	std::unordered_set<std::string> FindVulnerability(const std::string& cve, OpSys distrib = OpSys::Debian, float ver = 0.0) override;
	
	/*!
	 * Generates a command which upgrades the specified vulnerable packages
	 * on the host system.
	 *
	 * \param pkgs Vulnerable packages to upgrade.
	 * \param distrib Operating system distribution.
	 * \param ver Version number of distribution.
	 *
	 * \return Upgrade command.
	 */
	std::string GetUpgradeCommand(const std::unordered_set<std::string>& pkgs, OpSys distrib = OpSys::Debian, float ver = 0.0) override;

	/*!
	 * Frees up the resources allocated during the lifetime of this instance.
	 */
	~DebianLookup() override;

};
