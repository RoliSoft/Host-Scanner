#pragma once
#include "Stdafx.h"
#include "Host.h"
#include <unordered_set>
#include <unordered_map>

/*!
 * Provides the functionality to search vendor repositories.
 */
class VendorPackageLookup
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
	virtual std::unordered_map<std::string, std::string> FindVulnerability(const std::string& cve, OpSys distrib = OpSys::Unidentified, double ver = 0.0) = 0;

	/*!
	 * Gets the changelog of a package from the vendor's repository.
	 *
	 * \param pkg Name of the package.
	 * \param distrib Operating system distribution.
	 * \param ver Version number of distribution.
	 * 
	 * \return List of version numbers and their release dates.
	 */
	virtual std::vector<std::pair<std::string, long>> GetChangelog(const std::string& pkg, OpSys distrib = OpSys::Unidentified, double ver = 0.0) = 0;

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
	virtual std::string GetUpgradeCommand(const std::unordered_set<std::string>& pkgs, OpSys distrib = OpSys::Unidentified, double ver = 0.0) = 0;

	/*!
	 * Determines whether the specified CVE identifier is syntactically correct.
	 *
	 * \param cve Identifier of the vulnerability.
	 *
	 * \return true if it is correct, false if it is not.
	 */
	static bool ValidateCVE(const std::string& cve);

	/*!
	 * Frees up the resources allocated during the lifetime of this instance.
	 */
	virtual ~VendorPackageLookup();
	
};
