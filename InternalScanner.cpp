#include "Stdafx.h"
#include "InternalScanner.h"
#include "TaskQueueRunner.h"
#include <unordered_map>
#include "ServiceScannerFactory.h"

using namespace std;

bool InternalScanner::GetOption(int option, void* value)
{
	switch (option)
	{
	case OPT_TIMEOUT:
		*reinterpret_cast<unsigned long*>(value) = timeout;
		return true;

	case OPT_DELAY:
		*reinterpret_cast<unsigned long*>(value) = delay;
		return true;

	default:
		return false;
	}
}

bool InternalScanner::SetOption(int option, void* value)
{
	switch (option)
	{
	case OPT_TIMEOUT:
		timeout = *reinterpret_cast<unsigned long*>(value);
		return true;

	case OPT_DELAY:
		delay = *reinterpret_cast<unsigned long*>(value);
		return true;

	default:
		return false;
	}
}

bool InternalScanner::IsPassive()
{
	return false;
}

void InternalScanner::Scan(Host* host)
{
	Hosts hosts = { host };
	Scan(&hosts);
}

void InternalScanner::Scan(Hosts* hosts)
{
	unordered_map<IPPROTO, ServiceScanner*> scanners;

	TaskQueueRunner tqr(hosts->size() * hosts->front()->services->size(), 65535);

	// traverse hosts and create list of services

	Services servs;

	for (auto host : *hosts)
	{
		for (auto service : *host->services)
		{
			servs.push_back(service);
		}
	}

	// the reason why stable_sort is used here is because otherwise the queue
	// would otherwise have the first IP with all of its ports, then the second,
	// and so on. this would put a huge strain on the IPs sequentially.
	// through sorting the list by port number, the queue will go through the
	// ports sequentially, iterating through the list of IPs for each port.
	// while this results in the same amount of load for the scanner, it will
	// be much more gentle on the scanned targets. as for why stable sort is
	// used, it's because the the "normal" sort is not guaranteed to preserve
	// the order between equal elements, which would make the IP addresses list
	// rather randomized. by using stable sort, the IP addresses will keep their
	// sequential order by port, and as such the load will be kept to a minimum.

	stable_sort(servs.begin(), servs.end(), [](Service* a, Service* b)
	{
		return a->port < b->port;
	});

	// create task for each service and add it to the queue

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
			scanner->SetOption(OPT_DELAY,   &delay);

			scanners[service->protocol] = scanner;
		}

		tqr.Enqueue(scanner->GetTask(service));
	}

	servs.clear();

	// run the queue

	tqr.Run();

	// clean-up

	for (auto scanner : scanners)
	{
		delete scanner.second;
	}
}

InternalScanner::~InternalScanner()
{
}
