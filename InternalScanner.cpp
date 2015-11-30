#include "InternalScanner.h"
#include "IcmpPinger.h"
#include "TcpScanner.h"
#include "UdpScanner.h"
#include <unordered_map>
#include <boost/lexical_cast.hpp>
#include <boost/range/adaptor/filtered.hpp>
#include <iostream>

using namespace std;
using namespace boost;

void InternalScanner::Scan(Host* host)
{
	Hosts hosts = { host };
	Scan(&hosts);
}

void InternalScanner::Scan(Hosts* hosts)
{
	using namespace adaptors;

	auto isAlive   = [](auto* serv) { return  serv->alive; };
	auto isntAlive = [](auto* serv) { return !serv->alive; };

	unordered_map<char*, Host*> hostMap;

	for (auto host : *hosts | filtered(isntAlive))
	{
		hostMap[host->address] = host;
	}

	// start off by scanning with the ICMP Pinger

	if (useIcmp)
	{
		Services servsIcmp;

		for (auto host : *hosts | filtered(isntAlive))
		{
			servsIcmp.push_back(new Service(host->address, 0, IPPROTO_ICMP));
		}

		IcmpPinger icmp;
		icmp.Scan(&servsIcmp);

		for (auto servIcmp : servsIcmp | filtered(isAlive))
		{
			hostMap[servIcmp->address]->alive  = true;
			hostMap[servIcmp->address]->reason = servIcmp->reason;
			hostMap[servIcmp->address]->services->push_back(new Service(*servIcmp));
		}

		freeServices(servsIcmp);

		if (all_of(hosts->cbegin(), hosts->cend(), isAlive))
		{
			return;
		}
	}

	// if there are addresses which have not replied, start TCP scan

	if (useTcp)
	{
		vector<unsigned short> commonTcp = { 80, 443, 22, 25, 445, 139 }; // http, https, ssh, smtp, ms-ds, netbios

		Services servsTcp;

		for (auto host : *hosts | filtered(isntAlive))
		{
			for (auto port : commonTcp)
			{
				servsTcp.push_back(new Service(host->address, port, IPPROTO_TCP));
			}
		}

		TcpScanner tcp;
		tcp.grabBanner = false;
		tcp.runScripts = false;
		tcp.Scan(&servsTcp);

		for (auto servTcp : servsTcp | filtered(isAlive))
		{
			hostMap[servTcp->address]->alive  = true;
			hostMap[servTcp->address]->reason = servTcp->reason;
			hostMap[servTcp->address]->services->push_back(new Service(*servTcp));
		}

		freeServices(servsTcp);

		if (all_of(hosts->cbegin(), hosts->cend(), isAlive))
		{
			return;
		}
	}

	// if there are hosts still offline, try UDP scan

	if (useUdp)
	{
		vector<unsigned short> commonUdp = { 161, 137 }; // snmp, netbios

		Services servsUdp;

		for (auto host : *hosts | filtered(isntAlive))
		{
			for (auto port : commonUdp)
			{
				servsUdp.push_back(new Service(host->address, port, IPPROTO_UDP));
			}
		}

		UdpScanner udp;
		udp.grabBanner = false;
		udp.runScripts = false;
		udp.Scan(&servsUdp);

		for (auto servUdp : servsUdp | filtered(isAlive))
		{
			hostMap[servUdp->address]->alive  = true;
			hostMap[servUdp->address]->reason = servUdp->reason;
			hostMap[servUdp->address]->services->push_back(new Service(*servUdp));
		}

		freeServices(servsUdp);

		if (all_of(hosts->cbegin(), hosts->cend(), isAlive))
		{
			return;
		}
	}
}

InternalScanner::~InternalScanner()
{
}
