#include "Service.h"
#include <unordered_map>

using namespace std;

Service::Service(const Service& service)
	: address(service.address), port(service.port), protocol(service.protocol),
	  alive(service.alive), reason(service.reason), banner(service.banner),
	  cpe(service.cpe), date(service.date), host(service.host), data(service.data)
{
}

Service::Service(const string& address, unsigned short port, IPPROTO protocol)
	: address(address), port(port), protocol(protocol),
	  alive(false), reason(AR_NotScanned), banner(""), cpe(), date(), host(nullptr), data(nullptr)
{
}

string Service::ReasonString(AliveReason reason)
{
	static unordered_map<int, string> reasons = {
		{ AR_ScanFailed,        "ScanFailed" },
		{ AR_NotScanned,        "NotScanned" },
		{ AR_InProgress,        "InProgress" },
		{ AR_InProgress_Extra,  "InProgressExtra" },
		{ AR_TimedOut,          "TimedOut" },
		{ AR_IcmpUnreachable,   "IcmpUnreachable" },
		{ AR_ReplyReceived,     "ReplyReceived" }
	};

	auto iter = reasons.find(reason);

	return iter != reasons.end() ? iter->second : "Unkown";
}

Service::~Service()
{
}

void freeServices(Services& services)
{
	for (auto& service : services)
	{
		delete service;
	}

	services.clear();
}
