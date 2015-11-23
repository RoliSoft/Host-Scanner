#include "hostscanner.h"
#include "icmppinger.h"
#include "tcpscanner.h"
#include "udpscanner.h"
#include <unordered_map>
#include <boost/lexical_cast.hpp>
#include <boost/range/adaptor/filtered.hpp>
#include <iostream>

using namespace std;
using namespace boost;

void HostScanner::Scan(Service* service)
{
	Services services = { service };
	Scan(&services);
}

void HostScanner::Scan(Services* services)
{
	using namespace adaptors;

	auto isAlive   = [](Service* serv) { return  serv->alive; };
	auto isntAlive = [](Service* serv) { return !serv->alive; };

	// start off by scanning with the ICMP Pinger

	if (useIcmp)
	{
		IcmpPinger icmp;
		icmp.Scan(services);

		if (all_of(services->cbegin(), services->cend(), isAlive))
		{
			return;
		}
	}

	// if there are addresses which have not replied, start TCP scan

	if (useTcp)
	{
		vector<unsigned short> commonTcp = { 80, 443, 22, 25, 445, 139 }; // http, https, ssh, smtp, ms-ds, netbios

		Services servsTcp;
		unordered_map<char*, Service*> servsMap;

		for (auto serv : *services | filtered(isntAlive))
		{
			for (auto port : commonTcp)
			{
				servsTcp.push_back(new Service(serv->address, port, IPPROTO_TCP));
			}

			servsMap[serv->address] = serv;
		}

		TcpScanner tcp;
		tcp.grabBanner = false;
		tcp.runScripts = false;
		tcp.Scan(&servsTcp);

		for (auto servTcp : servsTcp | filtered(isAlive))
		{
			servsMap[servTcp->address]->alive    = true;
			servsMap[servTcp->address]->reason   = servTcp->reason;
			servsMap[servTcp->address]->protocol = IPPROTO_TCP;
		}

		freeServices(servsTcp);

		if (all_of(services->cbegin(), services->cend(), isAlive))
		{
			return;
		}
	}

	// if there are hosts still offline, try UDP scan

	if (useUdp)
	{
		vector<unsigned short> commonUdp = { 161, 137 }; // snmp, netbios

		Services servsUdp;
		unordered_map<char*, Service*> servsMap;

		for (auto serv : *services | filtered(isntAlive))
		{
			for (auto port : commonUdp)
			{
				servsUdp.push_back(new Service(serv->address, port, IPPROTO_UDP));
			}

			servsMap[serv->address] = serv;
		}

		UdpScanner udp;
		udp.grabBanner = false;
		udp.runScripts = false;
		udp.Scan(&servsUdp);

		for (auto servUdp : servsUdp | filtered(isAlive))
		{
			servsMap[servUdp->address]->alive    = true;
			servsMap[servUdp->address]->reason   = servUdp->reason;
			servsMap[servUdp->address]->protocol = IPPROTO_UDP;
		}

		freeServices(servsUdp);

		if (all_of(services->cbegin(), services->cend(), isAlive))
		{
			return;
		}
	}
}

HostScanner::~HostScanner()
{
}

void HostScanner::createCidrList(char* address, int cidr)
{
	unsigned int ip, bitmask, gateway, broadcast;

	inet_pton(AF_INET, address, &ip);
	ip = ntohl(ip);

	bitmask = createBitmask(cidr);

	gateway   = ip &  bitmask;
	broadcast = ip | ~bitmask;

	for (ip = gateway; ip <= broadcast; ip++)
	{
		cout << uintToIp(ip) << endl;
	}
}

void HostScanner::createRangeList(char* start, char* finish)
{
	unsigned int ip, low, high;

	inet_pton(AF_INET, start,  &low);
	inet_pton(AF_INET, finish, &high);

	low  = ntohl(low);
	high = ntohl(high);

	if (high < low)
	{
		swap(low, high);
	}

	for (ip = low; ip <= high; ip++)
	{
		cout << uintToIp(ip) << endl;
	}
}

unsigned int HostScanner::createBitmask(int cidr)
{
	cidr = max(0, min(cidr, 32));

	unsigned int bitmask = UINT_MAX;

	for (int i = 0; i < 33 - cidr - 1; i++)
	{
		bitmask <<= 1;
	}

	return bitmask;
}

char* HostScanner::uintToIp(unsigned int ip)
{
	auto addr = new char[16];
	sprintf(addr, "%d.%d.%d.%d", (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
	return addr;
}
