#include "InternalScanner.h"
#include "TaskQueueRunner.h"
#include "TcpScanner.h"
#include "UdpScanner.h"
#include "IcmpPinger.h"

using namespace std;

void InternalScanner::Scan(Host* host)
{
	Hosts hosts = { host };
	Scan(&hosts);
}

void InternalScanner::Scan(Hosts* hosts)
{
	TaskQueueRunner tqr(hosts->size() * hosts->front()->services->size(), 65535);

	TcpScanner tcp;
	tcp.timeout = timeout;

	UdpScanner udp;
	udp.timeout = timeout;

	IcmpPinger icmp;
	icmp.timeout = timeout;
	
	Services servs;

	for (auto host : *hosts)
	{
		for (auto service : *host->services)
		{
			servs.push_back(service);
		}
	}

	stable_sort(servs.begin(), servs.end(), [](Service* a, Service* b) { return a->port < b->port; });

	for (auto service : servs)
	{
		switch (service->protocol)
		{
		case IPPROTO_TCP:
			tqr.Enqueue(tcp.GetTask(service));
			break;

		case IPPROTO_UDP:
			tqr.Enqueue(udp.GetTask(service));
			break;

		case IPPROTO_ICMP:
		case IPPROTO_ICMPV6:
			tqr.Enqueue(icmp.GetTask(service));
			break;
		}
	}

	servs.clear();

	tqr.Run();
}

InternalScanner::~InternalScanner()
{
}
