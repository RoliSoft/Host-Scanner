#include "PassiveScanner.h"
#include "ShodanScanner.h"
#include "CensysScanner.h"
#include "LooquerScanner.h"
#include <future>

using namespace std;

PassiveScanner::PassiveScanner(const string& shodan_key, const string& censys_auth, const string& looquer_key)
	: shodan_key(shodan_key), censys_auth(censys_auth), looquer_key(looquer_key)
{
}

void PassiveScanner::SetShodanKey(const string& key)
{
	shodan_key = key;
}

bool PassiveScanner::HasShodanKey()
{
	return !shodan_key.empty();
}

void PassiveScanner::SetShodanEndpoint(const string& uri)
{
	shodan_uri = uri;
}

void PassiveScanner::SetCensysKey(const string& key)
{
	censys_auth = key;
}

bool PassiveScanner::HasCensysKey()
{
	return !censys_auth.empty();
}

void PassiveScanner::SetCensysEndpoint(const string& uri)
{
	censys_uri = uri;
}

void PassiveScanner::SetLooquerKey(const string& key)
{
	looquer_key = key;
}

bool PassiveScanner::HasLooquerKey()
{
	return !looquer_key.empty();
}

void PassiveScanner::SetLooquerEndpoint(const string& uri)
{
	looquer_uri = uri;
}

bool PassiveScanner::IsPassive()
{
	return true;
}

void PassiveScanner::Scan(Host* host)
{
	static ShodanScanner ss(shodan_key);
	static CensysScanner cs(censys_auth);
	static LooquerScanner ls(looquer_key);

	if (!shodan_uri.empty())
	{
		ss.SetEndpoint(shodan_uri);
	}

	if (!censys_uri.empty())
	{
		cs.SetEndpoint(censys_uri);
	}

	if (!looquer_uri.empty())
	{
		ls.SetEndpoint(looquer_uri);
	}

	auto shost = new Host(*host);
	auto chost = new Host(*host);
	auto lhost = new Host(*host);

	auto sf = async(launch::async, [shost]() { ss.Scan(shost); });
	auto sc = async(launch::async, [chost]() { cs.Scan(chost); });
	auto sl = async(launch::async, [lhost]() { ls.Scan(lhost); });

	sf.wait();
	sc.wait();
	sl.wait();

	mergeHosts(shost, host);
	mergeHosts(chost, host);
	mergeHosts(lhost, host);

	delete shost;
	delete chost;
	delete lhost;
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
