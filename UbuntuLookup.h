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
	 */
	void FindVulnerability(const std::string& cve) override;

	/*!
	 * Frees up the resources allocated during the lifetime of this instance.
	 */
	~UbuntuLookup() override;

};
