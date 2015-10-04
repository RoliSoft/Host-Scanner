#include "udpscanner.h"
#include <boost/lexical_cast.hpp>
#include <iostream>

using namespace std;
using namespace boost;

void UdpScanner::Scan(Service* service)
{
	initSocket(service);

	int iters = timeout / 10;

	for (int i = 0; i < iters; i++)
	{
		pollSocket(service, i == iters - 1);

		if (service->reason != AR_InProgress)
		{
			break;
		}

		sleep(10);
	}
}

void UdpScanner::Scan(Services* services)
{
	for (auto service : *services)
	{
		initSocket(service);
	}

	int iters = timeout / 10;
	int left = services->size();

	for (int i = 0; i < iters; i++)
	{
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

		sleep(10);
	}
}

void UdpScanner::initSocket(Service* service)
{
	// parse address

	struct addrinfo hint, *info = nullptr;
	memset(&hint, 0, sizeof(struct addrinfo));
	hint.ai_family = AF_UNSPEC; // allow both v4 and v6
	hint.ai_flags = AI_NUMERICHOST; // disable DNS lookups

	auto port = lexical_cast<string>(service->port);
	getaddrinfo(service->address, port.c_str(), &hint, &info);
	
	// create socket

	auto sock = socket(info->ai_family, SOCK_DGRAM, IPPROTO_UDP);

	auto data = new UdpScanData();
	service->data = data;
	data->socket = sock;

	service->reason = AR_InProgress;

	// set it to non-blocking

	u_long mode = 1;
	ioctlsocket(sock, FIONBIO, &mode);
	
	// allocate buffer

	char* buf = "\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00"; // DNS status request

	// "connect", then send probe packet
	// the connect function in case of UDP just stores the address and port,
	// so send()/recv() will work without them, no need to store the addrinfo

	connect(sock, reinterpret_cast<struct sockaddr*>(info->ai_addr), info->ai_addrlen);
	send(sock, buf, 13, 0);
}

void UdpScanner::pollSocket(Service* service, bool last)
{
	if (service->reason != AR_InProgress || service->data == nullptr)
	{
		return;
	}

	auto data = reinterpret_cast<UdpScanData*>(service->data);

	char buf[1024];
	int buflen = 1024;

	// see if any responses were received

	auto res = recv(data->socket, buf, buflen, 0);

	// TODO receive ICMP Port Unreachable messages; may not be possible on Windows

	service->alive = res > 0;

	if (res > 0)
	{
		service->reason = AR_ReplyReceived;

		// save service banner

		service->banlen = res;
		service->banner = new char[res];

		memcpy(service->banner, buf, res);
	}
	else
	{
		if (last)
		{
			service->reason = AR_TimedOut;
		}
		else
		{
			return;
		}
	}

	// clean-up

	service->data = nullptr;

	closesocket(data->socket);

	delete data;
}

UdpScanner::~UdpScanner()
{
}