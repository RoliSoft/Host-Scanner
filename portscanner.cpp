#include "portscanner.h"
#include <iostream>

using namespace std;

void PortScanner::DumpResults(Services* services)
{
	for (auto service : *services)
	{
		cout << service->address << ":" << service->port << " is " << (service->alive ? "open" : "closed") << " (" << service->reason << ")" << endl;

		if (service->banlen > 0)
		{
			cout << " -> ";
			for (int i = 0; i < service->banlen; i++)
			{
				if (service->banner[i] == '\r') continue;

				if (service->banner[i] == '\n')
				{
					if ((service->banlen - i) > 3)
					{
						cout << endl << " -> ";
					}
					else
					{
						cout << " ";
					}
				}
				else if (service->banner[i] >= ' ' && service->banner[i] <= '~')
				{
					cout << service->banner[i];
				}
				else
				{
					cout << ".";
				}
			}
			cout << endl;
		}
	}
}

PortScanner::~PortScanner()
{
}
