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
	 * Frees up the resources allocated during the lifetime of this instance.
	 */
	virtual ~BannerProcessor();
	
};
