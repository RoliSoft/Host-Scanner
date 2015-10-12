#include "arppinger.h"
#include <iostream>
#include <vector>

#if Windows
	#include <pcap.h>
#elif Linux
	#include <cstring>
#endif

using namespace std;

void ArpPinger::Scan(Service* service)
{
	initSocket(service);

	int iters = timeout / 10;

	for (int i = 0; i <= iters; i++)
	{
		if (i != 0)
		{
			sleep(10);
		}

		pollSocket(service, i == iters - 1);

		if (service->reason != AR_InProgress)
		{
			break;
		}
	}
}

void ArpPinger::Scan(Services* services)
{
	for (auto service : *services)
	{
		initSocket(service);
	}

	int iters = timeout / 10;
	int left = services->size();

	for (int i = 0; i <= iters; i++)
	{
		if (i != 0)
		{
			sleep(10);
		}

		for (auto service : *services)
		{
			if (service->reason != AR_InProgress)
			{
				continue;
			}

			pollSocket(service, i == iters - 1);

			if (service->reason != AR_InProgress)
			{
				left--;
			}
		}

		if (left <= 0)
		{
			break;
		}
	}
}

vector<Interface> ArpPinger::getInterfaces()
{
	vector<Interface> ifs;

	// allocate 1 structure and call GetAdaptersInfo in order to get the number
	// of interfaces to allocate for; this is the official way to do it...

	auto ads = new IP_ADAPTER_INFO;
	unsigned long adLen = sizeof(IP_ADAPTER_INFO);

	if (GetAdaptersInfo(ads, &adLen) == ERROR_BUFFER_OVERFLOW)
	{
		delete ads;
		ads = new IP_ADAPTER_INFO[adLen / sizeof(IP_ADAPTER_INFO) + 1];

		// call again, this time with enough space

		GetAdaptersInfo(ads, &adLen);
	}

	// iterate through interfaces

	auto ad = ads;
	while (ad)
	{
		// skip over non-ethernet or non-point-to-point interfaces

		if (ad->Type != MIB_IF_TYPE_ETHERNET && ad->Type != MIB_IF_TYPE_PPP)
		{
			ad = ad->Next;
			continue;
		}

		// skip over interfaces which are not connected, or are otherwise
		// in a state where they don't have IPv4 connectivity

		if (string(ad->IpAddressList.IpAddress.String) == "0.0.0.0")
		{
			ad = ad->Next;
			continue;
		}

		// copy info, convert IP addresses stored as string

		Interface inf;

		memcpy(inf.adapter,     ad->AdapterName, sizeof(inf.adapter));
		memcpy(inf.description, ad->Description, sizeof(inf.description));
		memcpy(inf.macaddr,     ad->Address,     sizeof(inf.macaddr));

		inet_pton(AF_INET, ad->IpAddressList.IpAddress.String, &inf.ipaddr);
		inet_pton(AF_INET, ad->IpAddressList.IpMask.String,    &inf.ipmask);
		inet_pton(AF_INET, ad->GatewayList.IpAddress.String,   &inf.ipgate);

		ifs.push_back(inf);

		// advance in linked list

		ad = ad->Next;
	}

	// clean-up

	delete ads;

	return ifs;
}

bool ArpPinger::isIpOnIface(unsigned int ip, Interface& inf)
{
	// convert to host byte order

	unsigned int iph = ntohl(ip);
	unsigned int msk = ntohl(inf.ipmask);
	unsigned int net = ntohl(inf.ipgate == 0 ? inf.ipaddr : inf.ipgate);

	// do the range check

	unsigned int low  = net &  msk;
	unsigned int high = low | ~msk;

	return iph >= low && iph <= high;
}

void ArpPinger::initSocket(Service* service)
{
	// get interfaces

	auto ifs = getInterfaces();

	// parse address
	
	unsigned int addr;
	inet_pton(AF_INET, service->address, &addr);

	// check which interface's range is this address in

	Interface inf;

	auto found = false;
	for (auto& in : ifs)
	{
		if (isIpOnIface(addr, in))
		{
			//cout << service->address << " is in " << in.description << endl;
			inf = in;
			found = true;
			break;
		}
	}

	if (!found)
	{
		service->alive = AR_ScanFailed;
		return;
	}
	
	// open winpcap to the found interface

	pcap_t *pcap;
	char errbuf[PCAP_ERRBUF_SIZE];
	if ((pcap = pcap_open(string("rpcap://\\Device\\NPF_" + string(inf.adapter)).c_str(), 100, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL)
	{
		service->alive = AR_ScanFailed;
		return;
	}
	
	// construct the payload

	int pktLen = max(sizeof(EthHeader) + sizeof(ArpHeader), 60);
	auto pkt = new char[pktLen];
	memset(pkt, 0, pktLen);

	// first the ethernet frame

	auto ethPkt = reinterpret_cast<EthHeader*>(pkt);

	ethPkt->typ = htons(0x0806);

	memset(ethPkt->dst, 0xFF, sizeof(ethPkt->dst));
	memcpy(ethPkt->src, inf.macaddr, sizeof(ethPkt->src));

	// then the ARP request

	auto arpPkt = reinterpret_cast<ArpHeader*>(pkt + sizeof(*ethPkt));

	arpPkt->htype = htons(1);      // Ethernet
	arpPkt->ptype = htons(0x0800); // IP
	arpPkt->hlen = 6;              // MAC address is 6 bytes
	arpPkt->plen = 4;              // IP address is 4 bytes
	arpPkt->opcode = htons(ARP_OP_REQUEST); // request info

	memcpy(arpPkt->srcmac, inf.macaddr, sizeof(arpPkt->srcmac));
	memcpy(arpPkt->srcip, &inf.ipaddr,  sizeof(arpPkt->srcip));

	memset(arpPkt->dstmac, 0xFF, sizeof(arpPkt->dstmac));
	memcpy(arpPkt->dstip, &addr, sizeof(arpPkt->dstip));

	// send the packet

	auto res = pcap_sendpacket(pcap, reinterpret_cast<const unsigned char*>(pkt), pktLen);

	if (res != 0)
	{
		service->alive = AR_ScanFailed;
	}

	// clean-up

	delete pkt;

	pcap_close(pcap);
}

void ArpPinger::pollSocket(Service* service, bool last)
{
}

ArpPinger::~ArpPinger()
{
}
