#include "tcpscanner.h"
#include <chrono>
#include <thread>
#include <boost/lexical_cast.hpp>

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
			this_thread::sleep_for(chrono::milliseconds(10));
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
			this_thread::sleep_for(chrono::milliseconds(10));
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

	unsigned long mode = 1;
	ioctlsocket(sock, FIONBIO, &mode);

	// allocate file descriptor set

	data->fdset = new fd_set();
	FD_ZERO(data->fdset);
	FD_SET(sock, data->fdset);

	// start non-blocking connection process

	connect(sock, reinterpret_cast<struct sockaddr*>(info->ai_addr), info->ai_addrlen);

	// clean-up

	freeaddrinfo(info);
}

void TcpScanner::pollSocket(Service* service, bool last)
{
	if (service->reason != AR_InProgress || service->data == nullptr)
	{
		return;
	}

	TIMEVAL tv = { 0, 0 };
	auto data = reinterpret_cast<TcpScanData*>(service->data);

	// check if socket is writable, which basically means the connection was successful

	// for some reason, Linux requires the first parameter to be counterintuitively socket+1, while Windows doesn't
	// time spent searching for this error: ~1.5 hours

	select(
		data->socket
#if Unix
			+ 1
#endif
		, nullptr, data->fdset, nullptr, &tv
	);

	// check if the writable flag is set

	auto isOpen = FD_ISSET(data->socket, data->fdset);

#if Unix
	if (isOpen)
	{
		// yet again Linux decided to troll me. all select() requests will become "writable", and you have
		// to check if there was an error or not, to actually determine if the connect() was successful

		int serr;
		socklen_t slen = sizeof(serr);
		getsockopt(data->socket, SOL_SOCKET, SO_ERROR, &serr, &slen);
		isOpen = serr == 0;

		if (serr == ECONNREFUSED)
		{
			service->reason = AR_IcmpUnreachable;
		}
	}
#endif

	service->alive = isOpen == 1;

	// mark service accordingly

	if (isOpen)
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
			FD_ZERO(data->fdset);
			FD_SET(data->socket, data->fdset);
			return;
		}
	}

	// clean-up

	service->data = nullptr;

	closesocket(data->socket);

	delete data->fdset;
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

	delete data->fdset;
	delete data;
}

TcpScanner::~TcpScanner()
{
}
