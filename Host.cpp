#include "Host.h"

using namespace std;

Host::Host(const Host& host)
	: address(host.address), alive(host.alive), reason(host.reason),
	  services(new Services()), data(host.data)
{
	for (auto service : *host.services)
	{
		services->push_back(new Service(*service));
	}
}

Host::Host(const string& address)
	: address(address), services(new Services()), data(nullptr)
{
}

Host::Host(const string& address, const set<unsigned short>& tcps, const set<unsigned short>& udps)
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
		service->host = this;

		services->push_back(service);

		return service;
	}

	return nullptr;
}

Service* Host::AddService(unsigned short port, IPPROTO protocol)
{
	auto service = new Service(address, port, protocol);

	service->host = this;

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
			service->host = this;

			services->push_back(service);

			count++;
		}
	}

	return count;
}

int Host::AddServices(const set<unsigned short>& ports, IPPROTO protocol)
{
	auto count = 0;

	for (auto port : ports)
	{
		auto service = new Service(address, port, protocol);

		service->host = this;

		services->push_back(service);

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
