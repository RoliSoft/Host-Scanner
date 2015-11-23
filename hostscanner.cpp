#include "hostscanner.h"
#include "icmppinger.h"
#include "tcpscanner.h"
#include "udpscanner.h"
#include <unordered_map>
#include <boost/lexical_cast.hpp>
#include <boost/range/adaptor/filtered.hpp>

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

	vector<unsigned short> commonTcp = { 80, 443, 22, 25, 445, 139 }; // http, https, ssh, smtp, ms-ds, netbios

	Services servsTcp;
	unordered_map<char*, Service*> servsMap;

	for (auto serv : *services | filtered(isntAlive))
	{
		if (useTcp)
		{
			for (auto port : commonTcp)
			{
				servsTcp.push_back(new Service(serv->address, port, IPPROTO_TCP));
			}
		}

		servsMap[serv->address] = serv;
	}

	if (useTcp)
	{
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

		for (auto serv : *services | filtered(isntAlive))
		{
			for (auto port : commonUdp)
			{
				servsUdp.push_back(new Service(serv->address, port, IPPROTO_UDP));
			}
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
