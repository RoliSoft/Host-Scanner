#include "Service.h"

using namespace std;

Service::Service(string address, unsigned short port, IPPROTO protocol)
	: address(address), port(port), protocol(protocol),
	  alive(false), reason(AR_NotScanned), banner(""), cpe(vector<string>()), data(nullptr)
{
}

Service::~Service()
{
}

void freeServices(Services& services)
{
	for (auto& service : services)
	{
		delete service;
	}

	services.clear();
}
