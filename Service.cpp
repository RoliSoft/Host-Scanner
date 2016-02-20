#include "Service.h"

Service::Service(const char* address, unsigned short port, IPPROTO protocol)
	: address(address), port(port), protocol(protocol),
	  alive(false), reason(AR_NotScanned), banner(nullptr), banlen(0), cpe(""), data(nullptr)
{
}

Service::~Service()
{
	delete banner;
}

void freeServices(Services& services)
{
	for (auto& service : services)
	{
		delete service;
	}

	services.clear();
}
