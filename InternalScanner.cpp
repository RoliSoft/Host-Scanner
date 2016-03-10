#include "InternalScanner.h"
#include "TaskQueueRunner.h"
#include "TcpScanner.h"

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
		tqr.Enqueue(tcp.GetTask(service));
	}

	servs.clear();

	tqr.Run();
}

InternalScanner::~InternalScanner()
{
}
