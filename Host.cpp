#include "Host.h"

Host::Host(const std::string& address)
	: address(address), services(new Services()), data(nullptr)
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
