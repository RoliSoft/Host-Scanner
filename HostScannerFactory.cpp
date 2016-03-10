#include "Stdafx.h"
#include "HostScannerFactory.h"
#include "ShodanScanner.h"
#include "NmapScanner.h"
#include "InternalScanner.h"

HostScanner* HostScannerFactory::Get(bool passive, bool external)
{
	if (passive)
	{
		return new ShodanScanner();
	}

	if (external)
	{
		return new NmapScanner();
	}

	return new InternalScanner();
}
