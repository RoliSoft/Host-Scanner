#include "PassiveScanner.h"
#include "ShodanScanner.h"
#include "CensysScanner.h"
#include <future>

using namespace std;

PassiveScanner::PassiveScanner(const string& shodan_key, const string& censys_auth)
	: shodan_key(shodan_key), censys_auth(censys_auth)
{
}

bool PassiveScanner::IsPassive()
{
	return true;
}

void PassiveScanner::Scan(Host* host)
{
	static ShodanScanner ss(shodan_key);
	static CensysScanner cs(censys_auth);

	auto shost = new Host(*host);
	auto chost = new Host(*host);

	auto sf = async(launch::async, [shost]() { ss.Scan(shost); });
	auto sc = async(launch::async, [chost]() { cs.Scan(chost); });

	sf.wait();
	sc.wait();

	mergeHosts(shost, host);
	mergeHosts(chost, host);

	delete shost;
	delete chost;
}

void PassiveScanner::Scan(Hosts* hosts)
{
	for (auto host : *hosts)
	{
		Scan(host);
	}
}

void PassiveScanner::mergeHosts(Host* src, Host* dst)
{
	if (src->alive && !dst->alive)
	{
		dst->alive = src->alive;
	}

	if (dst->reason == AR_NotScanned || dst->reason == AR_ScanFailed)
	{
		dst->reason = src->reason;
	}

	for (auto srcsrv : *src->services)
	{
		Service* dstsrv = nullptr;

		for (auto tmpsrv : *dst->services)
		{
			if (tmpsrv->port == srcsrv->port && tmpsrv->protocol == srcsrv->protocol)
			{
				dstsrv = tmpsrv;
				break;
			}
		}

		if (dstsrv != nullptr)
		{
			mergeServices(srcsrv, dstsrv);
		}
		else
		{
			dst->services->push_back(new Service(*srcsrv));
		}
	}
}

void PassiveScanner::mergeServices(Service* src, Service* dst)
{
	if (src->alive && !dst->alive)
	{
		dst->alive = src->alive;
	}

	if (dst->reason == AR_NotScanned || dst->reason == AR_ScanFailed)
	{
		dst->reason = src->reason;
	}

	if (dst->banner.length() < src->banner.length())
	{
		dst->banner = src->banner;
	}

	if (src->cpe.size() != 0)
	{
		dst->cpe.insert(dst->cpe.end(), src->cpe.begin(), src->cpe.end());
	}
}

PassiveScanner::~PassiveScanner()
{
}
