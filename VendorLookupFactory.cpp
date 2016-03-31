#include "VendorLookupFactory.h"
#include "DebianLookup.h"
#include "UbuntuLookup.h"
#include "EnterpriseLinuxLookup.h"

VendorPackageLookup* VendorLookupFactory::Get(OpSys opSys)
{
	switch (opSys)
	{
	case Debian:
		return new DebianLookup();

	case Ubuntu:
		return new UbuntuLookup();

	case Fedora:
	case EnterpriseLinux:
		return new EnterpriseLinuxLookup();

	default:
		return nullptr;
	}
}
