#pragma once
#include "Stdafx.h"
#include "Host.h"
#include <unordered_set>
#include <unordered_map>

/*!
 * Structure which contains the information available from the vendor regarding a vulnerability.
 */
struct VendorVulnInfo
{

	/*!
	 * Map of version numbers which fix the vulnerability associated to
	 * the operating system distribution they are packaged with, or an empty
	 * string, if a vulnerability is not yet fixed in the distribution.
	 */
	std::unordered_map<std::string, std::string> Fixes;

	/*!
	 * List of vulnerable packages.
	 */
	std::unordered_set<std::string> Packages;

};

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
	 * \return List of vulnerable packages.
	 */
	virtual std::unordered_set<std::string> FindVulnerability(const std::string& cve, OpSys distrib = OpSys::Unidentified, double ver = 0.0) = 0;

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
