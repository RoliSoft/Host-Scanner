#include "ShodanScanner.h"
#include "Utils.h"

using namespace std;

void ShodanScanner::Scan(Service* service)
{
	getHostInfo(service);
}

void ShodanScanner::Scan(Services* services)
{
	for (auto service : *services)
	{
		getHostInfo(service);
	}
}

void ShodanScanner::getHostInfo(Service* service)
{
	auto json = getURL("https://" + endpoint + "/host/" + service->address + "?key=" + key);

	// TODO parse JSON
}

ShodanScanner::~ShodanScanner()
{
}
