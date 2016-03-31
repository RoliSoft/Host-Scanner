#pragma once
#include "VendorPackageLookup.h"

/*
 * Implements the factory pattern for retrieving vendor package lookup instances.
 */
class VendorLookupFactory
{
public:

	/*!
	 * Gets a vendor package lookup instance which supports the specified operating system.
	 *
	 * \param opSys Operating system for which to retrieve lookup instance.
	 * 
	 * \return Instance to be used for package lookups, or nullptr for unsupported systems.
	 */
	static VendorPackageLookup* Get(OpSys opSys);

};
