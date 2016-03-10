#include "Host.h"

Host::Host(const std::string& address)
	: address(address), services(new Services()), data(nullptr)
{
}

Host::Host(const std::string& address, const std::set<unsigned short>& tcps, const std::set<unsigned short>& udps)
	: address(address), services(new Services()), data(nullptr)
{
	if (tcps.size() > 0)
	{
		for (auto tcp : tcps)
		{
			services->push_back(new Service(address, tcp, IPPROTO_TCP));
		}
	}

	if (udps.size() > 0)
	{
		for (auto udp : udps)
		{
			services->push_back(new Service(address, udp, IPPROTO_UDP));
		}
	}
}

Service* Host::AddService(Service* service)
{
	if (address == service->address)
	{
		services->push_back(service);

		return service;
	}

	return nullptr;
}

Service* Host::AddService(unsigned short port, IPPROTO protocol)
{
	auto service = new Service(address, port, protocol);

	services->push_back(service);

	return service;
}

int Host::AddServices(const Services& servlist)
{
	auto count = 0;

	for (auto service : servlist)
	{
		if (address == service->address)
		{
			services->push_back(service);

			count++;
		}
	}

	return count;
}

int Host::AddServices(const std::set<unsigned short>& ports, IPPROTO protocol)
{
	auto count = 0;

	for (auto port : ports)
	{
		services->push_back(new Service(address, port, protocol));

		count++;
	}

	return count;
}

Host::~Host()
{
	for (auto& service : *services)
	{
		delete service;
	}

	services->clear();
}

void freeHosts(Hosts& hosts)
{
	for (auto& host : hosts)
	{
		delete host;
	}

	hosts.clear();
}
