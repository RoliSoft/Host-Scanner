#include "Host.h"

Host::Host(std::string address)
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
