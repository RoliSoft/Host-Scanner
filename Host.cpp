#include "Host.h"

using namespace std;

Host::Host(const Host& host)
	: address(host.address), alive(host.alive), reason(host.reason), cpe(host.cpe),
	  services(new Services()), opSys(host.opSys), osVer(host.osVer), date(host.date), data(host.data)
{
	for (auto service : *host.services)
	{
		services->push_back(new Service(*service));
	}
}

Host::Host(const string& address)
	: address(address), cpe(), services(new Services()), opSys(OpSys::Unidentified), osVer(0), date(), data(nullptr)
{
}

Host::Host(const string& address, const set<unsigned short>& tcps, const set<unsigned short>& udps)
	: address(address), cpe(), services(new Services()), opSys(OpSys::Unidentified), osVer(0), date(), data(nullptr)
{
	if (tcps.size() > 0)
	{
		for (auto tcp : tcps)
		{
			auto service = new Service(address, tcp, IPPROTO_TCP);

			service->host = this;

			services->push_back(service);
		}
	}

	if (udps.size() > 0)
	{
		for (auto udp : udps)
		{
			auto service = new Service(address, udp, IPPROTO_UDP);

			service->host = this;

			services->push_back(service);
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

	delete services;
}

void freeHosts(Hosts& hosts)
{
	for (auto& host : hosts)
	{
		delete host;
	}

	hosts.clear();
}
