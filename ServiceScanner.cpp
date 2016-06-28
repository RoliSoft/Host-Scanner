#include "ServiceScanner.h"
#include <sstream>

using namespace std;

void ServiceScanner::DumpResults(Services* services)
{
	for (auto service : *services)
	{
		if (!service->alive && (service->reason == AR_TimedOut || service->reason == AR_NotScanned || service->reason == AR_IcmpUnreachable))
		{
			continue;
		}

		log(service->alive ? MSG : DBG, service->address + ":" + to_string(service->port) + " is " + (service->alive ? "open" : "closed") + " (" + Service::ReasonString(service->reason) + ")");

		if (service->banner.length() > 0)
		{
			stringstream ss;
			ss << " -> ";

			for (auto i = 0u; i < service->banner.length(); i++)
			{
				if (service->banner[i] == '\r') continue;

				if (service->banner[i] == '\n')
				{
					if ((service->banner.length() - i) > 3)
					{
						ss << endl << " -> ";
					}
					else
					{
						ss << " ";
					}
				}
				else if (service->banner[i] >= ' ' && service->banner[i] <= '~')
				{
					ss << service->banner[i];
				}
				else
				{
					ss << ".";
				}
			}

			log(VRB, ss.str(), false);
		}
	}
}

ServiceScanner::~ServiceScanner()
{
}
