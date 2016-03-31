#pragma once
#include "Stdafx.h"
#include "Host.h"

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
	 */
	virtual void FindVulnerability(const std::string& cve) = 0;

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
