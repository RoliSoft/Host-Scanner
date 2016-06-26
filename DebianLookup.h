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
	 * \return If not affected an empty map, otherwise a map of vulnerable
	 *         packages associated to the version number that patches it,
	 *         or empty string if package is not yet fixed.
	 */
	std::unordered_map<std::string, std::string> FindVulnerability(const std::string& cve, OpSys distrib = OpSys::Debian, double ver = 0.0) override;
	
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
	std::string GetUpgradeCommand(const std::unordered_set<std::string>& pkgs, OpSys distrib = OpSys::Debian, double ver = 0.0) override;

	/*!
	 * Frees up the resources allocated during the lifetime of this instance.
	 */
	~DebianLookup() override;

};
