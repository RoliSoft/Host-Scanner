#include "Host.h"

Host::Host(const char* address)
	: address(address), services(new Services())
{
}

Host::~Host()
{
	for (auto& service : *services)
	{
		delete service;
	}

	services->clear();
}
