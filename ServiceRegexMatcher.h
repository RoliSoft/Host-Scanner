#pragma once
#include <string>
#include "Stdafx.h"
#include "BannerProcessor.h"

/*!
 * Implements a bulk regular expression matcher against service banners.
 */
class ServiceRegexMatcher : public BannerProcessor
{
public:
	
	/*!
	 * Processes the banner of a service.
	 * 
	 * \param service Scanned service.
	 */
	void Scan(Service* service) override;

	/*!
	 * Frees up the resources allocated during the lifetime of this instance.
	 */
	~ServiceRegexMatcher() override;

};
