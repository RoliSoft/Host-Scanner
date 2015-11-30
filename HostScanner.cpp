#include "HostScanner.h"
#include "ServiceScanner.h"
#include <iostream>

using namespace std;

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
