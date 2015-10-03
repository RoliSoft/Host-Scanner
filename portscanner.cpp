#include "portscanner.h"
#include <iostream>

using namespace std;

void PortScanner::DumpResults(Services* services)
{
	for (auto service : *services)
	{
		cout << service->address << ":" << service->port << " is " << (service->alive ? "open" : "closed") << endl;
	}
}
