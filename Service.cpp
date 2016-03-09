#include "Service.h"
#include <unordered_map>

using namespace std;

Service::Service(string address, unsigned short port, IPPROTO protocol)
	: address(address), port(port), protocol(protocol),
	  alive(false), reason(AR_NotScanned), banner(""), cpe(), data(nullptr)
{
}

string Service::ReasonString(AliveReason reason)
{
	static unordered_map<int, string> reasons = {
		{ AR_ScanFailed,        "ScanFailed" },
		{ AR_NotScanned,        "NotScanned" },
		{ AR_InProgress,        "InProgress" },
		{ AR_InProgress2,       "InProgress2" },
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
