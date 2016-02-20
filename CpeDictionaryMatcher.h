#pragma once
#include <string>
#include "Stdafx.h"
#include "BannerProcessor.h"

/*!
 * Implements fuzzy matching of CPE names to service banners.
 */
class CpeDictionaryMatcher : public BannerProcessor
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
	~CpeDictionaryMatcher() override;

};
