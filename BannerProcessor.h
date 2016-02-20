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
	virtual void Scan(Service* service) = 0;

	/*!
	 * Frees up the resources allocated during the lifetime of this instance.
	 */
	virtual ~BannerProcessor();
	
};
