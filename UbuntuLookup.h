#pragma once
#include "Stdafx.h"
#include "VendorPackageLookup.h"

/*!
 * Implements the functionality to search Ubuntu packages.
 */
class UbuntuLookup : public VendorPackageLookup
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
	std::unordered_map<std::string, std::string> FindVulnerability(const std::string& cve, OpSys distrib = OpSys::Ubuntu, double ver = 0.0) override;
	
	/*!
	 * Gets the changelog of a package from the vendor's repository.
	 *
	 * \param pkg Name of the package.
	 * \param distrib Operating system distribution.
	 * \param ver Version number of distribution.
	 * 
	 * \return List of version numbers and their release dates.
	 */
	std::vector<std::pair<std::string, long>> GetChangelog(const std::string& pkg, OpSys distrib = OpSys::Ubuntu, double ver = 0.0) override;
	
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
	std::string GetUpgradeCommand(const std::unordered_set<std::string>& pkgs, OpSys distrib = OpSys::Ubuntu, double ver = 0.0) override;

	/*!
	 * Frees up the resources allocated during the lifetime of this instance.
	 */
	~UbuntuLookup() override;

};
