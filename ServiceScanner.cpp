#include "ServiceScanner.h"
#include <sstream>

using namespace std;

void ServiceScanner::DumpResults(Services* services)
{
	for (auto service : *services)
	{
		log(MSG, string(service->address) + ":" + to_string(service->port) + " is " + (service->alive ? "open" : "closed") + " (" + to_string(service->reason) + ")");

		if (service->banlen > 0)
		{
			stringstream ss;
			ss << " -> ";

			for (int i = 0; i < service->banlen; i++)
			{
				if (service->banner[i] == '\r') continue;

				if (service->banner[i] == '\n')
				{
					if ((service->banlen - i) > 3)
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

			log(DBG, ss.str());
		}
	}
}

ServiceScanner::~ServiceScanner()
{
}
