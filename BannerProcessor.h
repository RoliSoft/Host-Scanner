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
	 * 
	 * \return Matching CPE entries.
	 */
	virtual std::vector<std::string> Scan(const std::string& banner) = 0;

	/*!
	 * Tries to processes the specified service banner with all known implementations of this class.
	 *
	 * \param banner Service banner.
	 * 
	 * \return Matching CPE entries.
	 */
	static std::vector<std::string> AutoProcess(const std::string& banner);

	/*!
	 * Frees up the resources allocated during the lifetime of this instance.
	 */
	virtual ~BannerProcessor();
	
};
