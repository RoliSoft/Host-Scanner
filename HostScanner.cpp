#include "HostScanner.h"
#include "ServiceScanner.h"
#include <iostream>
#include <climits>

using namespace std;

Hosts* HostScanner::ScanCidr(char* address, int cidr)
{
	// get lowest and highest IP for supplied CIDR

	unsigned int ip, bitmask, gateway, broadcast;

	inet_pton(AF_INET, address, &ip);
	ip = ntohl(ip);

	bitmask = createBitmask(cidr);

	gateway   = ip &  bitmask;
	broadcast = ip | ~bitmask;

	// generate list of hosts for range

	auto hosts = new Hosts();

	for (ip = gateway; ip <= broadcast; ip++)
	{
		hosts->push_back(new Host(uintToIp(ip)));
	}

	// scan generated list

	Scan(hosts);

	return hosts;
}

Hosts* HostScanner::ScanRange(char* start, char* finish)
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

	auto hosts = new Hosts();

	for (ip = low; ip <= high; ip++)
	{
		hosts->push_back(new Host(uintToIp(ip)));
	}

	// scan generated list

	Scan(hosts);

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

char* HostScanner::uintToIp(unsigned int ip)
{
	auto addr = new char[16];
	snprintf(addr, 16, "%d.%d.%d.%d", (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
	return addr;
}
