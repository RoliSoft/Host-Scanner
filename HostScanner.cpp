#include "HostScanner.h"
#include "ServiceScanner.h"
#include <iostream>
#include <climits>

using namespace std;

Hosts* HostScanner::GenerateCidr(const char* address, int cidr, Hosts* hosts)
{
	// get lowest and highest IP for supplied CIDR

	unsigned int ip, bitmask, gateway, broadcast;

	inet_pton(AF_INET, address, &ip);
	ip = ntohl(ip);

	bitmask = createBitmask(cidr);

	gateway   = ip &  bitmask;
	broadcast = ip | ~bitmask;

	// generate list of hosts for range

	if (hosts == nullptr)
	{
		hosts = new Hosts();
	}

	for (ip = gateway; ip <= broadcast; ip++)
	{
		hosts->push_back(new Host(uintToIp(ip)));
	}

	return hosts;
}

Hosts* HostScanner::GenerateRange(const char* start, const char* finish, Hosts* hosts)
{
	// parse supplied addresses

	unsigned int ip, low, high;

	inet_pton(AF_INET, start,  &low);
	inet_pton(AF_INET, finish, &high);

	low  = ntohl(low);
	high = ntohl(high);

	if (high < low)
	{
		swap(low, high);
	}

	// generate list of hosts for range

	if (hosts == nullptr)
	{
		hosts = new Hosts();
	}

	for (ip = low; ip <= high; ip++)
	{
		hosts->push_back(new Host(uintToIp(ip)));
	}

	return hosts;
}

void HostScanner::DumpResults(Hosts* hosts)
{
	for (auto host : *hosts)
	{
		ServiceScanner::DumpResults(host->services);
	}
}

HostScanner::~HostScanner()
{
}

unsigned int HostScanner::createBitmask(int cidr)
{
	cidr = max(0, min(cidr, 32));

	unsigned int bitmask = UINT_MAX;

	for (int i = 0; i < 33 - cidr - 1; i++)
	{
		bitmask <<= 1;
	}

	return bitmask;
}

const char* HostScanner::uintToIp(unsigned int ip)
{
	auto addr = new char[16];
	snprintf(addr, 16, "%u.%u.%u.%u", (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
	return addr;
}
