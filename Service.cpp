#include "Service.h"

Service::Service(const char* address, unsigned short port, IPPROTO protocol)
	: address(address), port(port), protocol(protocol)
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
