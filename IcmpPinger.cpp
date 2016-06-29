#include "IcmpPinger.h"
#include "TaskQueueRunner.h"
#include "Host.h"
#include "Utils.h"
#include <iostream>
#include <chrono>
#include <thread>

#if Unix
	#include <cstring>
#endif

using namespace std;

unsigned short IcmpPinger::sequence = 0;

bool IcmpPinger::GetOption(int option, void* value)
{
	switch (option)
	{
	case OPT_TIMEOUT:
		*reinterpret_cast<unsigned long*>(value) = timeout;
		return true;

	default:
		return false;
	}
}

bool IcmpPinger::SetOption(int option, void* value)
{
	switch (option)
	{
	case OPT_TIMEOUT:
		timeout = *reinterpret_cast<unsigned long*>(value);
		return true;

	default:
		return false;
	}
}

void* IcmpPinger::GetTask(Service* service)
{
	return MFN_TO_PTR(IcmpPinger::initSocket, this, service);
}

void* IcmpPinger::initSocket(Service* service)
{
	// parse address

	struct addrinfo hint, *info = nullptr;
	memset(&hint, 0, sizeof(struct addrinfo));
	hint.ai_family = AF_UNSPEC; // allow both v4 and v6
	hint.ai_flags = AI_NUMERICHOST; // disable DNS lookups

	getaddrinfo(service->address.c_str(), "echo", &hint, &info);

	if (info == nullptr)
	{
		service->reason = AR_ScanFailed;
		log(ERR, "Failed to resolve IP address `" + service->address + "`");
		return nullptr;
	}

	service->protocol = info->ai_family == AF_INET6 ? IPPROTO(IPPROTO_ICMPV6) : IPPROTO(IPPROTO_ICMP);

	// create raw socket

	auto sock = socket(info->ai_family, SOCK_RAW, service->protocol);

	if (
#if Windows
		sock == INVALID_SOCKET
#else
		sock < 0
#endif
		)
	{
		// admin rights are required for raw sockets

		service->reason = AR_ScanFailed;
		log(ERR, "Failed to open socket with AF_INET" + string(info->ai_family == AF_INET6 ? "6" : "") + "/SOCK_RAW: " + getNetErrStr());
		freeaddrinfo(info);
		return nullptr;
	}

	auto data = new IcmpScanData();

	service->data = data;
	data->socket  = sock;

	service->reason = AR_InProgress;
	data->timeout   = chrono::system_clock::now() + chrono::milliseconds(timeout);

	// max out TTL

	unsigned char ttl = 255;
	setsockopt(sock, IPPROTO_IP, IP_TTL, reinterpret_cast<const char*>(&ttl), sizeof(ttl));

	// set it to non-blocking

	unsigned long mode = 1;
	ioctlsocket(sock, FIONBIO, &mode);

	// construct the payload

	struct IcmpEcho pkt;
	memset(&pkt, 0, sizeof(pkt));

	pkt.type = info->ai_family == AF_INET6 ? ICMP6_ECHO_REQUEST : ICMP_ECHO_REQUEST;
	pkt.id   = static_cast<unsigned short>(sock);
	pkt.seq  = sequence++;

	for (int i = 0; i < 32; i++)
	{
		pkt.data[i] = rand() % 256;
	}

	pkt.checksum = checksum(reinterpret_cast<unsigned short*>(&pkt), sizeof(pkt));

	// "connect", then send probe packet
	// the connect function in case of ICMP just stores the address,
	// so send()/recv() will work without them, no need to store the addrinfo

	log(DBG, "Sending payload to icmp://" + service->address + "...");

	service->date = service->host->date = chrono::system_clock::now();

	auto res = connect(sock, reinterpret_cast<struct sockaddr*>(info->ai_addr), info->ai_addrlen);

	if (
		res < 0
#if Windows
		&& WSAGetLastError() != WSAEWOULDBLOCK
#else
		&& errno != EINPROGRESS
#endif
		)
	{
		service->reason = AR_ScanFailed;
		log(ERR, "Failed to connect to icmp://" + service->address + ": " + getNetErrStr());

		freeaddrinfo(info);
		service->data = nullptr;
		delete data;

		return nullptr;
	}

	res = send(sock, reinterpret_cast<char*>(&pkt), sizeof(pkt), 0);

	if (res < 0)
	{
		service->reason = AR_ScanFailed;
		log(ERR, "Failed to send packet to icmp://" + service->address + ": " + getNetErrStr());

		freeaddrinfo(info);
		service->data = nullptr;
		delete data;

		return nullptr;
	}

	// clean-up

	freeaddrinfo(info);

	// return next task

	return MFN_TO_PTR(IcmpPinger::pollSocket, this, service);
}

void* IcmpPinger::pollSocket(Service* service)
{
	if (service->reason != AR_InProgress || service->data == nullptr)
	{
		return nullptr;
	}

	auto data = reinterpret_cast<IcmpScanData*>(service->data);

	char buf[1024];
	int buflen = 1024;

	// see if any responses were received

	auto res = recv(data->socket, buf, buflen, 0);

	service->alive = false;

	if (res > 0)
	{
		// for IPv4, the raw socket response includes the IP header,
		// while for IPv6, it does not. this seems to be consistent on both
		// operating systems. 20 bytes is the fixed-length IPv4 header size.

		auto ofs = service->protocol == IPPROTO_ICMPV6 ? 0 : 20;
		auto pkt = reinterpret_cast<IcmpEcho*>(reinterpret_cast<char*>(&buf) + ofs);

		// parse the reply

		if (pkt->id != static_cast<unsigned short>(data->socket))
		{
			// not our packet, discard it for now

			if (data->timeout < chrono::system_clock::now())
			{
				service->reason = AR_TimedOut;

				log(INT, "Waiting for icmp://" + service->address + " timed out...");
			}
			else
			{
				// return the current task to try polling the socket again

				return MFN_TO_PTR(IcmpPinger::pollSocket, this, service);
			}
		}
		else
		{
			if ((service->protocol == IPPROTO_ICMP   && pkt->type == ICMP_ECHO_REPLY )
			 || (service->protocol == IPPROTO_ICMPV6 && pkt->type == ICMP6_ECHO_REPLY))
			{
				service->alive  = true;
				service->reason = AR_ReplyReceived;

				log(DBG, "Got reply from icmp://" + service->address + "...");
			}
			else
			{
				// if not an echo reply, but references the echo request, assume it's an error message

				service->reason = AR_IcmpUnreachable;

				log(INT, "Got ICMP unreachable for icmp://" + service->address + "...");
			}
		}
	}
	else
	{
		if (data->timeout < chrono::system_clock::now())
		{
			service->reason = AR_TimedOut;

			log(INT, "Waiting for icmp://" + service->address + " timed out...");
		}
		else
		{
			// return the current task to try polling the socket again

			return MFN_TO_PTR(IcmpPinger::pollSocket, this, service);
		}
	}

	// clean-up

	service->data = nullptr;

	closesocket(data->socket);

	delete data;

	// return end-of-task

	return nullptr;
}

unsigned short IcmpPinger::checksum(unsigned short* buf, int len)
{
	unsigned int sum = 0;

	for (sum = 0; len > 1; len -= 2)
	{
		sum += *buf++;
	}

	if (len == 1)
	{
		sum += *reinterpret_cast<unsigned char*>(buf);
	}

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += sum >> 16;

	return static_cast<unsigned short>(~sum);
}

IcmpPinger::~IcmpPinger()
{
}
