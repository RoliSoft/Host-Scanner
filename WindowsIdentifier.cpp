#include "WindowsIdentifier.h"
#include <boost/regex.hpp>

using namespace std;
using namespace boost;

bool WindowsIdentifier::Scan(Host* host)
{
	auto isWin = false;

	// check if any Microsoft services are running

	static regex wintag("\\b(?:microsoft.?(iis|ftp|esmtp|httpapi)|cygwin|windows)\\b", regex::icase);

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
	}

	return isWin;
}

WindowsIdentifier::~WindowsIdentifier()
{
}
