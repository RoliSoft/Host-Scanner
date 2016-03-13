#include "TcpScanner.h"
#include "TaskQueueRunner.h"
#include <chrono>
#include <thread>
#include <functional>
#include <boost/lexical_cast.hpp>

using namespace std;
using namespace boost;

bool TcpScanner::GetOption(int option, void* value)
{
	switch (option)
	{
	case OPT_TIMEOUT:
		timeout = *reinterpret_cast<int*>(value);
		return true;

	case OPT_BANNER:
		grabBanner = *reinterpret_cast<bool*>(value);
		return true;

	default:
		return false;
	}
}

bool TcpScanner::SetOption(int option, void* value)
{
	switch (option)
	{
	case OPT_TIMEOUT:
		value = &timeout;
		return true;

	case OPT_BANNER:
		value = &grabBanner;
		return true;

	default:
		return false;
	}
}

void* TcpScanner::GetTask(Service* service)
{
	return MFN_TO_PTR(TcpScanner::initSocket, this, service);
}

void* TcpScanner::initSocket(Service* service)
{
	// parse address

	struct addrinfo hint, *info = nullptr;
	memset(&hint, 0, sizeof(struct addrinfo));
	hint.ai_family = AF_UNSPEC; // allow both v4 and v6
	hint.ai_flags = AI_NUMERICHOST; // disable DNS lookups

	auto port = lexical_cast<string>(service->port);
	getaddrinfo(service->address.c_str(), port.c_str(), &hint, &info);
	
	// create socket

	auto sock = socket(info->ai_family, SOCK_STREAM, IPPROTO_TCP);

	auto data = new TcpScanData();

	service->data = data;
	data->socket  = sock;

	service->reason = AR_InProgress;
	data->timeout   = chrono::system_clock::now() + chrono::milliseconds(timeout);

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

	// return next task

	return MFN_TO_PTR(TcpScanner::pollSocket, this, service);
}

void* TcpScanner::pollSocket(Service* service)
{
	if (service->reason != AR_InProgress || service->data == nullptr)
	{
		return nullptr;
	}

	TIMEVAL tv = { 0, 0 };
	auto data = reinterpret_cast<TcpScanData*>(service->data);

	// check if socket is writable, which basically means the connection was successful

	// for some reason, Linux requires the first parameter to be counterintuitively socket+1, while Windows doesn't.
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
		if (grabBanner)
		{
			service->reason = AR_InProgress_Extra;
			data->timeout   = chrono::system_clock::now() + chrono::milliseconds(timeout);

			return readBanner(service);
		}
		else
		{
			service->reason = AR_ReplyReceived;
			shutdown(data->socket, SD_BOTH);
		}
	}
	else
	{
		if (data->timeout < chrono::system_clock::now())
		{
			service->reason = AR_TimedOut;
		}
		else if (service->reason == AR_InProgress)
		{
			FD_ZERO(data->fdset);
			FD_SET(data->socket, data->fdset);

			// return the current task to try polling the socket again

			return MFN_TO_PTR(TcpScanner::pollSocket, this, service);
		}
	}

	// clean-up

	service->data = nullptr;

	closesocket(data->socket);

	delete data->fdset;
	delete data;

	// return end-of-task

	return nullptr;
}

void* TcpScanner::readBanner(Service* service)
{
	if (service->reason != AR_InProgress_Extra || service->data == nullptr)
	{
		return nullptr;
	}

	auto data = reinterpret_cast<TcpScanData*>(service->data);

	char buf[1024];
	int buflen = 1024;

	auto res = recv(data->socket, buf, buflen, 0);
	if (res > 0)
	{
		// received a service banner

		service->banner = string(buf, res);
	}
	else if (data->timeout >= chrono::system_clock::now())
	{
		// return the current task to try polling the socket again

		return MFN_TO_PTR(TcpScanner::readBanner, this, service);
	}

	service->reason = AR_ReplyReceived;

	// clean-up

	service->data = nullptr;

	shutdown(data->socket, SD_BOTH);
	closesocket(data->socket);

	delete data->fdset;
	delete data;

	// return end-of-task

	return nullptr;
}

TcpScanner::~TcpScanner()
{
}
