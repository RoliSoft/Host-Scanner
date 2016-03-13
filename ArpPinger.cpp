#include "ArpPinger.h"
#include <iostream>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <tuple>
#include <thread>
#include <ctime>
#include <chrono>

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
		#include <linux/filter.h>
	#endif

	// BSD
	#ifdef AF_LINK
		#include <fcntl.h>
		#include <net/if_dl.h>
		#include <net/bpf.h>

		#define ETH_P_ARP 0x0806
	#endif

#endif

using namespace std;

ArpPinger::ArpPinger()
	: interfaces()
{
}

bool ArpPinger::IsPassive()
{
	return false;
}

ArpPinger::~ArpPinger()
{
	if (interfaces.size() != 0)
	{
		for (auto& iface : interfaces)
		{
			delete iface;
		}
	}
}

void ArpPinger::Scan(Host* host)
{
	prepareHost(host);

	if (host->reason != AR_InProgress)
	{
		return;
	}

	unordered_map<unsigned int, Host*> hostmap = {
		{ reinterpret_cast<ArpScanData*>(host->data)->ipaddr, host }
	};

	unordered_set<Interface*> ifaces = {
		reinterpret_cast<ArpScanData*>(host->data)->iface
	};

	thread thd(&ArpPinger::sniffReplies, this, ifaces, hostmap);

	sendRequest(host);

	thd.join();

	if (host->reason == AR_InProgress)
	{
		host->reason = AR_TimedOut;
	}
}

void ArpPinger::Scan(Hosts* hosts)
{
	unordered_map<unsigned int, Host*> hostmap;
	unordered_set<Interface*> ifaces;

	for (auto& host : *hosts)
	{
		prepareHost(host);

		if (host->reason != AR_InProgress)
		{
			continue;
		}

		hostmap[reinterpret_cast<ArpScanData*>(host->data)->ipaddr] = host;
		ifaces.emplace(reinterpret_cast<ArpScanData*>(host->data)->iface);
	}

	thread thd(&ArpPinger::sniffReplies, this, ifaces, hostmap);

	for (auto host : *hosts)
	{
		if (host->reason != AR_InProgress)
		{
			continue;
		}

		sendRequest(host);
	}

	thd.join();

	for (auto host : *hosts)
	{
		if (host->reason == AR_InProgress)
		{
			host->reason = AR_TimedOut;
		}
	}
}

void ArpPinger::loadInterfaces()
{
	if (interfaces.size() != 0)
	{
		return;
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

		auto inf = new Interface();

		memcpy(inf->adapter,     ad->AdapterName, sizeof(inf->adapter));
		memcpy(inf->description, ad->Description, sizeof(inf->description));
		memcpy(inf->macaddr,     ad->Address,     sizeof(inf->macaddr));

		inet_pton(AF_INET, ad->IpAddressList.IpAddress.String, &inf->ipaddr);
		inet_pton(AF_INET, ad->IpAddressList.IpMask.String,    &inf->ipmask);
		inet_pton(AF_INET, ad->GatewayList.IpAddress.String,   &inf->ipgate);

		interfaces.push_back(inf);
	}

	// clean-up

	delete[] ads;

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
			macs[ad->ifa_name] = make_tuple(sdl->sdl_index, reinterpret_cast<unsigned char*>(sdl->sdl_data + sdl->sdl_nlen));
			continue;
		}

#endif

		// skip loopback interfaces and those without IPv4 connectivity

		if (ad->ifa_addr == nullptr || ad->ifa_addr->sa_family != AF_INET || (ad->ifa_flags & IFF_UP) != IFF_UP || (ad->ifa_flags & IFF_LOOPBACK) == IFF_LOOPBACK)
		{
			continue;
		}

		// copy info

		auto inf = new Interface();

		strncpy(inf->adapter,     ad->ifa_name, sizeof(inf->adapter));
		strncpy(inf->description, ad->ifa_name, sizeof(inf->description));

		inf->ipaddr = (reinterpret_cast<struct sockaddr_in*>(ad->ifa_addr))->sin_addr.s_addr;
		inf->ipmask = (reinterpret_cast<struct sockaddr_in*>(ad->ifa_netmask))->sin_addr.s_addr;
		inf->ipgate = (reinterpret_cast<struct sockaddr_in*>(ad->
#ifdef AF_PACKET
				ifa_ifu.ifu_broadaddr
#endif
#ifdef AF_LINK
				ifa_broadaddr
#endif
			))->sin_addr.s_addr;

		// since only the broadcast address is specified, the gateway address
		// should be determinable based on the netmask and broadcast address.
		// this may not be entirely accurate, but enough for our purposes.

		inf->ipgate = htonl(ntohl(inf->ipgate) & ntohl(inf->ipmask));

		interfaces.push_back(inf);
	}

	// copy over temporarily stored interface numbers and MAC addresses

	for (auto& inf : interfaces)
	{
		auto it = macs.find(inf->adapter);

		if (it != macs.end())
		{
			auto tpl = (*it).second;

			inf->ifnum = get<0>(tpl);

			memcpy(inf->macaddr, get<1>(tpl), sizeof(inf->macaddr));
		}
	}

	// clean-up

	freeifaddrs(ads);

#endif
}

bool ArpPinger::isIpOnIface(unsigned int ip, Interface* inf)
{
	// convert to host byte order

	unsigned int iph = ntohl(ip);
	unsigned int msk = ntohl(inf->ipmask);
	unsigned int net = ntohl(inf->ipgate == 0 ? inf->ipaddr : inf->ipgate);

	// do the range check

	unsigned int low  = net &  msk;
	unsigned int high = low | ~msk;

	return iph >= low && iph <= high;
}

void ArpPinger::prepareHost(Host* host)
{
	// get interfaces

	if (interfaces.size() == 0)
	{
		loadInterfaces();
	}

	// parse address
	
	unsigned int addr;
	inet_pton(AF_INET, host->address.c_str(), &addr);

	// check which interfaces' range is this address in

	Interface* iface = nullptr;

	for (auto& inf : interfaces)
	{
		if (isIpOnIface(addr, inf))
		{
			iface = inf;
			break;
		}
	}

	if (iface == nullptr)
	{
		host->reason = AR_ScanFailed;
		log(ERR, "Host '" + host->address + "' is not local to any of the interfaces.");
		return;
	}

	auto data    = new ArpScanData();
	host->data   = data;
	data->ipaddr = addr;
	data->iface  = iface;
	host->reason = AR_InProgress;
}

void ArpPinger::sendRequest(Host* host)
{
	if (host->reason != AR_InProgress || host->data == nullptr)
	{
		return;
	}

	auto data = reinterpret_cast<ArpScanData*>(host->data);

#if Windows

	// open winpcap to the found interface

	pcap_t *pcap;
	char errbuf[PCAP_ERRBUF_SIZE];

	if ((pcap = pcap_open(string("rpcap://\\Device\\NPF_" + string(data->iface->adapter)).c_str(), 100, PCAP_OPENFLAG_PROMISCUOUS, 10, NULL, errbuf)) == NULL)
	{
		host->reason = AR_ScanFailed;
		log(ERR, "Failed to open PCAP device: " + string(data->iface->adapter));
		return;
	}

#elif Linux

	// prepare the structures pointing to the interface

	struct sockaddr_ll dev;
	memset(&dev, 0, sizeof(dev));

	dev.sll_ifindex = data->iface->ifnum;
	dev.sll_family  = AF_PACKET;
	dev.sll_halen   = 6;

	memcpy(dev.sll_addr, data->iface->macaddr, dev.sll_halen);

	// create raw socket

	auto sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	if (sock < 0)
	{
		// root is required for raw sockets

		host->reason = AR_ScanFailed;
		log(ERR, "Failed to open socket with PF_PACKET/SOCK_RAW.");
		return;
	}

	// set it to non-blocking

	unsigned long mode = 1;
	ioctl(sock, FIONBIO, &mode);

#elif BSD

	// find and open the next available Berkeley Packet Filter device

	int bpf = 0;
	for (int i = 0; i < 1000; i++)
	{
		bpf = open(("/dev/bpf" + to_string(i)).c_str(), O_RDWR);

		if (bpf != -1)
		{
			break;
		}
	}

	if (bpf < 0)
	{
		host->reason = AR_ScanFailed;
		log(ERR, "Failed to allocate a BPF device.");
		return;
	}

	// bind device to the desired interface

	struct ifreq bif;
	strcpy(bif.ifr_name, data->iface->adapter);

	if (ioctl(bpf, BIOCSETIF, &bif) > 0)
	{
		host->reason = AR_ScanFailed;
		log(ERR, "Failed to bind BPF device to interface '" + string(data->iface->adapter) + "': " + string(strerror(errno)));
		close(bpf);
		return;
	}

#endif
	
	// construct the payload

	auto pktLen = max(int(sizeof(EthHeader) + sizeof(ArpHeader)), 60);
	auto pkt = new char[pktLen];
	memset(pkt, 0, pktLen);

	// first the ethernet frame

	auto ethPkt = reinterpret_cast<EthHeader*>(pkt);

	ethPkt->typ = htons(0x0806); // ARP

	memset(ethPkt->dst, 0xFF, sizeof(ethPkt->dst)); // FF:FF:FF:FF:FF:FF is broadcast
	memcpy(ethPkt->src, data->iface->macaddr, sizeof(ethPkt->src));

	// then the ARP request

	auto arpPkt = reinterpret_cast<ArpHeader*>(pkt + sizeof(*ethPkt));

	arpPkt->htype = htons(1);      // Ethernet
	arpPkt->ptype = htons(0x0800); // IP
	arpPkt->hlen = 6;              // MAC address is 6 bytes
	arpPkt->plen = 4;              // IP address is 4 bytes
	arpPkt->opcode = htons(ARP_OP_REQUEST); // request info

	memcpy(arpPkt->srcmac, data->iface->macaddr, sizeof(arpPkt->srcmac));
	memcpy(arpPkt->srcip, &data->iface->ipaddr,  sizeof(arpPkt->srcip));

	memset(arpPkt->dstmac, 0xFF, sizeof(arpPkt->dstmac));
	memcpy(arpPkt->dstip, &data->ipaddr, sizeof(arpPkt->dstip));

	// send the packet, then clean-up

#if Windows

	auto res = pcap_sendpacket(pcap, reinterpret_cast<const unsigned char*>(pkt), pktLen);

	if (res != 0)
	{
		host->reason = AR_ScanFailed;
		log(ERR, "Failed to send packet through PCAP: " + string(pcap_geterr(pcap)));
	}

	pcap_close(pcap);

#elif Linux

	auto res = sendto(sock, pkt, pktLen, 0, reinterpret_cast<struct sockaddr*>(&dev), sizeof(dev));

	if (res <= 0)
	{
		host->reason = AR_ScanFailed;
		log(ERR, "Failed to send packet through socket: " + string(strerror(errno)));
	}

	close(sock);

#elif BSD

	auto res = write(bpf, pkt, pktLen);

	if (res <= 0)
	{
		host->reason = AR_ScanFailed;
		log(ERR, "Failed to send packet through BPF: " + string(strerror(errno)));
	}

	close(bpf);

#endif

	delete[] pkt;

	delete data;
}

void ArpPinger::sniffReplies(unordered_set<Interface*> ifaces, unordered_map<unsigned int, Host*> hosts)
{
	if (ifaces.size() == 0 || hosts.size() == 0)
	{
		return;
	}

#if Windows

	// iterate through the interfaces and setup a winpcap for all of them

	vector<pcap_t*> pcaps;

	for (auto& iface : ifaces)
	{
		// open winpcap to the interface

		pcap_t *pcap;
		char errbuf[PCAP_ERRBUF_SIZE];

		if ((pcap = pcap_open(string("rpcap://\\Device\\NPF_" + string(iface->adapter)).c_str(), 60, PCAP_OPENFLAG_PROMISCUOUS, 10, NULL, errbuf)) == NULL)
		{
			log(ERR, "Failed to open PCAP for interface '" + string(iface->adapter) + "': " + string(pcap_geterr(pcap)));
			continue;
		}

		// compile the code to filter packets

		struct bpf_program bfcode;
		if (pcap_compile(pcap, &bfcode, "arp", 1, iface->ipmask) < 0)
		{
			log(ERR, "Failed to compile filter for PCAP for interface '" + string(iface->adapter) + "': " + string(pcap_geterr(pcap)));
			continue;
		}

		// attach compiled code to instance

		if (pcap_setfilter(pcap, &bfcode) < 0)
		{
			log(ERR, "Failed to attach filter to PCAP for interface '" + string(iface->adapter) + "': " + string(pcap_geterr(pcap)));
			continue;
		}

		pcaps.push_back(pcap);
	}

	if (pcaps.size() == 0)
	{
		log(ERR, "Failed to open any PCAP devices.");
		return;
	}

	// iterate through the received packets on all interfaces until timeout

	auto res = 0;
	struct pcap_pkthdr* header;
	const unsigned char* data;

	auto start = chrono::steady_clock::now();

	while (chrono::duration_cast<chrono::milliseconds>(chrono::steady_clock::now() - start).count() < static_cast<long long>(timeout))
	{
		for (auto& pcap : pcaps)
		{
			// capture packet from interface

			res = pcap_next_ex(pcap, &header, &data);

			// check if a valid packet has been captured

			if (res <= 0 || header->caplen < sizeof(EthHeader) + sizeof(ArpHeader))
			{
				continue;
			}

			// skip ethernet frame and parse ARP packet

			auto arpPkt = reinterpret_cast<ArpHeader*>(const_cast<unsigned char*>(data) + sizeof(EthHeader));

			if (ntohs(arpPkt->opcode) != ARP_OP_REPLY)
			{
				continue;
			}

			// when reply packet is found, mark its host object as alive

			auto it = hosts.find(*reinterpret_cast<unsigned int*>(&arpPkt->srcip));

			if (it != hosts.end())
			{
				auto serv = (*it).second;
				serv->alive = true;
				serv->reason = AR_ReplyReceived;
			}
		}
	}

	// clean-up

	for (auto& pcap : pcaps)
	{
		pcap_close(pcap);
	}

#elif Linux

	// open universal listening socket

	int sock;

	if ((sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
	{
		log(ERR, "Failed to open socket with AF_PACKET/SOCK_RAW/ETH_P_ALL.");
		return;
	}

	// set it to non-blocking

	unsigned long mode = 1;
	ioctl(sock, FIONBIO, &mode);

	// attach filter code to instance

	auto bfcode = new struct sock_filter[4];
	bfcode[0] = // ldh  [12]				; skip 12 bytes
	            BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 12);
	bfcode[1] = // jeq  #0x806  jt 2  jf 3	; if Eth type is ARP goto 2 else 3
		        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETH_P_ARP, 0, 1);
	bfcode[2] = // ret  #262144				; return packet [when ARP]
		        BPF_STMT(BPF_RET + BPF_K, sizeof(struct EthHeader) + sizeof(struct ArpHeader));
	bfcode[3] = // ret  #0					; return null
		        BPF_STMT(BPF_RET + BPF_K, 0);

	struct sock_fprog bfprog;
	bfprog.filter = bfcode;
	bfprog.len = 4;

	if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &bfprog, sizeof(bfprog)) == -1)
	{
		close(sock);
		delete[] bfcode;
		log(ERR, "Failed to compile and attach filter to socket: " + string(strerror(errno)));
		return;
	}

	// iterate through the received packets on all interfaces until timeout

	auto res   = 0;
	auto data  = new unsigned char[60];
	auto start = chrono::steady_clock::now();

	while (chrono::duration_cast<chrono::milliseconds>(chrono::steady_clock::now() - start).count() < static_cast<long long>(timeout))
	{
		// capture packet from interface

		res = recv(sock, data, 60, 0);

		// check if a valid packet has been captured

		if (res < int(sizeof(struct EthHeader) + sizeof(struct ArpHeader)))
		{
			continue;
		}

		// skip ethernet frame and parse ARP packet

		auto arpPkt = reinterpret_cast<struct ArpHeader*>(data + sizeof(struct EthHeader));

		if (ntohs(arpPkt->opcode) != ARP_OP_REPLY)
		{
			continue;
		}

		// when reply packet is found, mark its host object as alive

		auto it = hosts.find(*reinterpret_cast<unsigned int*>(&arpPkt->srcip));

		if (it != hosts.end())
		{
			auto serv = (*it).second;
			serv->alive = true;
			serv->reason = AR_ReplyReceived;
		}
	}

	// clean-up

	close(sock);

	delete[] data;
	delete[] bfcode;

#elif BSD

	// set up filter code for bpf
	// [see linux one above for comments]
	
	auto bfcode = new struct bpf_insn[4];
	bfcode[0] = BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 12);
	bfcode[1] = BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETH_P_ARP, 0, 1);
	bfcode[2] = BPF_STMT(BPF_RET + BPF_K, sizeof(struct EthHeader) + sizeof(struct ArpHeader));
	bfcode[3] = BPF_STMT(BPF_RET + BPF_K, 0);

	// iterate through the interfaces and setup a bpf for all of them

	vector<int> bpfs;

	for (auto& iface : ifaces)
	{
		// find and open the next available Berkeley Packet Filter device

		int bpf = 0;
		for (int i = 0; i < 1000; i++)
		{
			bpf = open(("/dev/bpf" + to_string(i)).c_str(), O_RDWR);

			if (bpf != -1)
			{
				break;
			}
		}

		if (bpf < 0)
		{
			log(ERR, "Failed to allocate a BPF device for interface '" + string(iface->adapter) + "'.");
			continue;
		}

		// bind device to the desired interface

		struct ifreq bif;
		strcpy(bif.ifr_name, iface->adapter);

		if (ioctl(bpf, BIOCSETIF, &bif) > 0)
		{
			close(bpf);
			log(ERR, "Failed to bind BPF device to interface '" + string(iface->adapter) + "': " + string(strerror(errno)));
			continue;
		}

		// enable immediate return mode

		int en = 1;
		ioctl(bpf, BIOCIMMEDIATE, &en);

		// set it to non-blocking

		unsigned long mode = 1;
		ioctl(bpf, FIONBIO, &mode);

		// attach filter code to instance

		struct bpf_program bfprog;
		bfprog.bf_insns = bfcode;
		bfprog.bf_len = 4;

		if (ioctl(bpf, BIOCSETF, &bfprog) < 0)
		{
			close(bpf);
			log(ERR, "Failed to compile and attach filter to BPF device for interface '" + string(iface->adapter) + "': " + string(strerror(errno)));
			continue;
		}

		bpfs.push_back(bpf);
	}

	if (bpfs.size() == 0)
	{
		delete[] bfcode;
		log(ERR, "Failed to open any BPF devices.");
		return;
	}

	// iterate through the received packets on all interfaces until timeout

	auto res = 0;
	auto start = chrono::steady_clock::now();

	while (chrono::duration_cast<chrono::milliseconds>(chrono::steady_clock::now() - start).count() < static_cast<long long>(timeout))
	{
		for (auto& bpf : bpfs)
		{
			// request buffer length

			int blen = 1;

			if (ioctl(bpf, BIOCGBLEN, &blen) == -1)
			{
				continue;
			}

			// allocate buffer and capture packets

			auto data = new unsigned char[blen];

			res = read(bpf, data, blen);

			// check if read was successful

			if (res <= 0)
			{
				delete[] data;
				continue;
			}

			// iterate through captured packets

			auto pkt = reinterpret_cast<unsigned char*>(data);

			while (pkt < data + res)
			{
				// extract packet

				auto bh = reinterpret_cast<struct bpf_hdr*>(pkt);

				// check if a valid packet has been captured

				if (bh->bh_caplen < int(sizeof(struct EthHeader) + sizeof(struct ArpHeader)))
				{
					pkt += BPF_WORDALIGN(bh->bh_hdrlen + bh->bh_caplen);
					continue;
				}

				// skip ethernet frame and parse ARP packet

				auto arpPkt = reinterpret_cast<struct ArpHeader*>(pkt + bh->bh_hdrlen + sizeof(struct EthHeader));

				if (ntohs(arpPkt->opcode) != ARP_OP_REPLY)
				{
					pkt += BPF_WORDALIGN(bh->bh_hdrlen + bh->bh_caplen);
					continue;
				}

				// when reply packet is found, mark its host object as alive

				auto it = hosts.find(*reinterpret_cast<unsigned int*>(&arpPkt->srcip));

				if (it != hosts.end())
				{
					auto serv = (*it).second;
					serv->alive = true;
					serv->reason = AR_ReplyReceived;
				}

				// advance to next packet

				pkt += BPF_WORDALIGN(bh->bh_hdrlen + bh->bh_caplen);
			}

			delete[] data;
		}
	}

	// clean-up

	for (auto& bpf : bpfs)
	{
		close(bpf);
	}

	delete[] bfcode;

#endif
}
