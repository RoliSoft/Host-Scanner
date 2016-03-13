#include "Stdafx.h"
#include "InternalScanner.h"
#include "TaskQueueRunner.h"
#include <unordered_map>
#include "ServiceScannerFactory.h"

using namespace std;

void InternalScanner::Scan(Host* host)
{
	Hosts hosts = { host };
	Scan(&hosts);
}

void InternalScanner::Scan(Hosts* hosts)
{
	unordered_map<IPPROTO, ServiceScanner*> scanners;

	TaskQueueRunner tqr(hosts->size() * hosts->front()->services->size(), 65535);

	Services servs;

	for (auto host : *hosts)
	{
		for (auto service : *host->services)
		{
			servs.push_back(service);
		}
	}

	stable_sort(servs.begin(), servs.end(), [](Service* a, Service* b)
	{
		return a->port < b->port;
	});

	for (auto service : servs)
	{
		auto scanner = scanners[service->protocol];

		if (scanner == nullptr)
		{
			scanner = ServiceScannerFactory::Get(service->protocol);

			if (scanner == nullptr)
			{
				continue;
			}

			scanner->SetOption(OPT_TIMEOUT, &timeout);

			scanners[service->protocol] = scanner;
		}

		tqr.Enqueue(scanner->GetTask(service));
	}

	servs.clear();

	tqr.Run();

	for (auto scanner : scanners)
	{
		delete scanner.second;
	}
}

InternalScanner::~InternalScanner()
{
}
