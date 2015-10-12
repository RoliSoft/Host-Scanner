#include "arppinger.h"
#include <iostream>
#include <vector>
#include <unordered_map>
#include <tuple>

#if Windows
	#include <pcap.h>
#elif Unix

	#include <cstring>
	#include <ifaddrs.h>
	#include <sys/ioctl.h>
	#include <net/if.h>
	#include <net/ethernet.h>
	// Linux
	#ifdef AF_PACKET
		#include <netpacket/packet.h>
	#endif

	// BSD
	#ifdef AF_LINK
		#include <net/if_dl.h>
	#endif
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
	static vector<Interface> ifs;

	if (ifs.size() != 0)
	{
		return ifs;
	}

#if Windows

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

	for (auto ad = ads; ad != nullptr; ad = ad->Next)
	{
		// skip over non-ethernet or non-point-to-point interfaces,
		// and those which are not connected, or are otherwise
		// in a state where they don't have IPv4 connectivity

		if ((ad->Type != MIB_IF_TYPE_ETHERNET && ad->Type != MIB_IF_TYPE_PPP) || string(ad->IpAddressList.IpAddress.String) == "0.0.0.0")
		{
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
	}

	// clean-up

	delete ads;

#elif Unix

	// get the available interfaces

	struct ifaddrs* ads;
	getifaddrs(&ads);

	// iterate through interfaces

	unordered_map<string, tuple<int, unsigned char*>> macs;

	for (auto ad = ads; ad != nullptr; ad = ad->ifa_next)
	{
		// check AF_PACKET/LINKs to save the interface numbers and MAC addresses for later

#ifdef AF_PACKET
		
		// Linux

		if (ad->ifa_addr != nullptr && ad->ifa_addr->sa_family == AF_PACKET)
		{
			auto sll = reinterpret_cast<struct sockaddr_ll*>(ad->ifa_addr);
			macs[ad->ifa_name] = make_tuple(sll->sll_ifindex, sll->sll_addr);
			continue;
		}

#endif
#ifdef AF_LINK

		// BSD

		if (ad->ifa_addr != nullptr && ad->ifa_addr->sa_family == AF_LINK)
		{
			auto sdl = reinterpret_cast<struct sockaddr_dl*>(ad->ifa_addr);
			macs[ad->ifa_name] = make_tuple(sdl->sdl_index, sdl->sdl_data);
			continue;
		}

#endif

		// skip loopback interfaces and those without IPv4 connectivity

		if (ad->ifa_addr == nullptr || ad->ifa_addr->sa_family != AF_INET || (ad->ifa_flags & IFF_UP) != IFF_UP || (ad->ifa_flags & IFF_LOOPBACK) == IFF_LOOPBACK)
		{
			continue;
		}

		// copy info

		Interface inf;

		strncpy(inf.adapter,     ad->ifa_name, sizeof(inf.adapter));
		strncpy(inf.description, ad->ifa_name, sizeof(inf.description));

		inf.ipaddr = (reinterpret_cast<struct sockaddr_in*>(ad->ifa_addr))->sin_addr.s_addr;
		inf.ipmask = (reinterpret_cast<struct sockaddr_in*>(ad->ifa_netmask))->sin_addr.s_addr;
		inf.ipgate = (reinterpret_cast<struct sockaddr_in*>(ad->ifa_ifu.ifu_broadaddr))->sin_addr.s_addr;

		// since only the broadcast address is specified, the gateway address
		// should be determinable based on the netmask and broadcast address.
		// this may not be entirely accurate, but enough for our purposes.

		inf.ipgate = htonl(ntohl(inf.ipgate) & ntohl(inf.ipmask));

		ifs.push_back(inf);
	}

	// copy over temporarily stored interface numbers and MAC addresses

	for (auto& inf : ifs)
	{
		auto it = macs.find(inf.adapter);

		if (it != macs.end())
		{
			auto tpl = (*it).second;

			inf.ifnum = get<0>(tpl);

			memcpy(inf.macaddr, get<1>(tpl), sizeof(inf.macaddr));
		}
	}

	// clean-up

	freeifaddrs(ads);

#endif

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
		service->reason = AR_ScanFailed;
		return;
	}

	service->reason = AR_InProgress;
	
#if Windows

	// open winpcap to the found interface

	pcap_t *pcap;
	char errbuf[PCAP_ERRBUF_SIZE];

	if ((pcap = pcap_open(string("rpcap://\\Device\\NPF_" + string(inf.adapter)).c_str(), 100, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL)
	{
		service->reason = AR_ScanFailed;
		return;
	}

#elif Unix

	// prepare the structures pointing to the interface

	struct sockaddr_ll dev;
	memset(&dev, 0, sizeof(dev));

	dev.sll_ifindex = inf.ifnum;
	dev.sll_family  = AF_PACKET;
	dev.sll_halen   = 6;

	memcpy(dev.sll_addr, inf.macaddr, dev.sll_halen);

	// create raw socket

	auto sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	if (sock < 0)
	{
		// root is required for raw sockets

		service->reason = AR_ScanFailed;
		return;
	}

	// set it to non-blocking

	unsigned long mode = 1;
	ioctlsocket(sock, FIONBIO, &mode);

#endif
	
	// construct the payload

	auto pktLen = max(int(sizeof(EthHeader) + sizeof(ArpHeader)), 60);
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

	// send the packet, then clean-up

#if Windows

	auto res = pcap_sendpacket(pcap, reinterpret_cast<const unsigned char*>(pkt), pktLen);

	if (res != 0)
	{
		service->reason = AR_ScanFailed;
	}

	pcap_close(pcap);

#elif Unix

	auto res = sendto(sock, pkt, pktLen, 0, reinterpret_cast<struct sockaddr*>(&dev), sizeof(dev));

	if (res <= 0)
	{
		service->reason = AR_ScanFailed;
	}

	close(sock);

#endif

	delete pkt;
}

void ArpPinger::pollSocket(Service* service, bool last)
{
}

ArpPinger::~ArpPinger()
{
}
