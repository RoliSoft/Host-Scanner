#include "WindowsIdentifier.h"
#include <boost/regex.hpp>

using namespace std;
using namespace boost;

bool WindowsIdentifier::Scan(Host* host)
{
	auto isWin = false;

	// check if any Microsoft services are running

	static regex wintag("\\b(?:microsoft.?(iis|ftp|esmtp|httpapi)|cygwin|windows|win32|win64)\\b", regex::icase);

	for (auto service : *host->services)
	{
		if (service->banner.empty())
		{
			continue;
		}

		smatch sm;

		if (regex_search(service->banner, sm, wintag))
		{
			isWin = true;
		}
	}

	if (isWin)
	{
		host->opSys = OpSys::WindowsNT;
		host->cpe.push_back("o:microsoft:windows");
	}

	return isWin;
}

WindowsIdentifier::~WindowsIdentifier()
{
}
