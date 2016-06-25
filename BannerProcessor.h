#pragma once
#include "Stdafx.h"
#include "Service.h"

/*!
 * Represents a banner processor.
 */
class BannerProcessor
{
public:

	/*!
	 * Processes the banner of a service.
	 * 
	 * \param service Scanned service.
	 */
	void Scan(Service* service);
	
	/*!
	 * Processes the specified service banner.
	 * 
	 * \param banner Service banner.
	 * \param processVendor Whether to process vendor level patches appended to the end of the version
	 *                      number. This removes the patch level from the CPE version and appends it to
	 *                      the end via a semicolon separator.
	 * 
	 * \return Matching CPE entries.
	 */
	virtual std::vector<std::string> Scan(const std::string& banner, bool processVendor = true) = 0;

	/*!
	 * Tries to processes the specified service banner with all known implementations of this class.
	 *
	 * \param banner Service banner.
	 * \param processVendor Whether to process vendor level patches appended to the end of the version
	 *                      number. This removes the patch level from the CPE version and appends it to
	 *                      the end via a semicolon separator.
	 * 
	 * \return Matching CPE entries.
	 */
	static std::vector<std::string> AutoProcess(const std::string& banner, bool processVendor = true);

	/*!
	 * Frees up the resources allocated during the lifetime of this instance.
	 */
	virtual ~BannerProcessor();
	
};
