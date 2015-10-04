#include "tcpscanner.h"
#include <boost/lexical_cast.hpp>
#include <iostream>

using namespace std;
using namespace boost;

void TcpScanner::Scan(Service* service)
{
	initSocket(service);

	int iters = timeout / 10;

	for (int i = 0; i <= iters; i++)
	{
		if (i != 0)
		{
			sleep(10);
		}

		switch (service->reason)
		{
		case AR_InProgress:
			pollSocket(service, i == iters - 1);
			break;

		case AR_InProgress2:
			readBanner(service, i == iters - 1);
			break;

		default:
			continue;
		}

		if (service->reason != AR_InProgress && service->reason != AR_InProgress2)
		{
			break;
		}
	}
}

void TcpScanner::Scan(Services* services)
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
			switch (service->reason)
			{
			case AR_InProgress:
				pollSocket(service, i == iters - 1);
				break;

			case AR_InProgress2:
				readBanner(service, i == iters - 1);
				break;

			default:
				continue;
			}

			if (service->reason != AR_InProgress && service->reason != AR_InProgress2)
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

void TcpScanner::initSocket(Service* service)
{
	// parse address

	struct addrinfo hint, *info = nullptr;
	memset(&hint, 0, sizeof(struct addrinfo));
	hint.ai_family = AF_UNSPEC; // allow both v4 and v6
	hint.ai_flags = AI_NUMERICHOST; // disable DNS lookups

	auto port = lexical_cast<string>(service->port);
	getaddrinfo(service->address, port.c_str(), &hint, &info);
	
	// create socket

	auto sock = socket(info->ai_family, SOCK_STREAM, IPPROTO_TCP);

	auto data = new TcpScanData();
	service->data = data;
	data->socket = sock;

	service->reason = AR_InProgress;

	// set it to non-blocking

	u_long mode = 1;
	ioctlsocket(sock, FIONBIO, &mode);

	// set up the OS's choice of signaling for non-blocking sockets

#if Windows

	WSAEVENT evt = WSACreateEvent();
	WSAEventSelect(sock, evt, FD_WRITE);
	WSAResetEvent(evt);
	data->event = evt;

#elif Linux

	data->fdset = new fd_set();
	FD_ZERO(data->fdset);
	FD_SET(sock, data->fdset);

#endif

	// start non-blocking connection process

	connect(sock, reinterpret_cast<struct sockaddr*>(info->ai_addr), info->ai_addrlen);
}

void TcpScanner::pollSocket(Service* service, bool last)
{
	if (service->reason != AR_InProgress || service->data == nullptr)
	{
		return;
	}

	auto data = reinterpret_cast<TcpScanData*>(service->data);

#if Windows

	// check if the event was signalled

	auto sigr = WSAWaitForMultipleEvents(1, &data->event, false, 0, false);
	auto serr = WSAGetLastError();

	// the return value 258 is not documented in MSDN, however this
	// is what seems to be returned in case of errors

	if (sigr == 258 && serr != WSAEWOULDBLOCK)
	{
		service->alive = false;
		service->reason = AR_IcmpUnreachable;
	}
	else if (sigr == 0)
	{
		service->alive = true;
	}

#elif Linux

	// check if socket is writable

	TIMEVAL tv = { 0, 0 };
	select(data->socket + 1, nullptr, data->fdset, nullptr, &tv);

	if (FD_ISSET(data->socket, data->fdset))
	{
		// since it seems writability bit will be set on connection refused errors,
		// check if this is a legit instance of writable socket or an error

		int serr;
		socklen_t slen = sizeof(serr);
		getsockopt(data->socket, SOL_SOCKET, SO_ERROR, &serr, &slen);
		
		service->alive = serr == 0;

		if (serr == ECONNREFUSED)
		{
			service->reason = AR_IcmpUnreachable;
		}
	}

#endif

	// mark service accordingly

	if (service->alive)
	{
		service->reason = AR_InProgress2;
		readBanner(service, last);
		return;
	}
	else
	{
		if (last)
		{
			service->reason = AR_TimedOut;
		}
		else if (service->reason == AR_InProgress)
		{
#if Linux
			FD_ZERO(data->fdset);
			FD_SET(data->socket, data->fdset);
#endif
			return;
		}
	}

	// clean-up

	service->data = nullptr;

	closesocket(data->socket);

#if Windows
	WSACloseEvent(data->event);
#elif Linux
	delete data->fdset;
#endif

	delete data;
}

void TcpScanner::readBanner(Service* service, bool last)
{
	if (service->reason != AR_InProgress2 || service->data == nullptr)
	{
		return;
	}

	if (service->banlen > 0)
	{
		service->reason = AR_ReplyReceived;
		return;
	}

	auto data = reinterpret_cast<TcpScanData*>(service->data);

	char buf[1024];
	int buflen = 1024;

	auto res = recv(data->socket, buf, buflen, 0);
	if (res > 0)
	{
		// received a service banner

		service->banlen = res;
		service->banner = new char[res];

		memcpy(service->banner, buf, res);

		// TODO run further protocol probes
	}
	else if (!last)
	{
		return;
	}

	service->reason = AR_ReplyReceived;

	// clean-up

	service->data = nullptr;

	shutdown(data->socket, SD_BOTH);
	closesocket(data->socket);

#if Windows
	WSACloseEvent(data->event);
#elif Linux
	delete data->fdset;
#endif

	delete data;
}

TcpScanner::~TcpScanner()
{
}