#include "tcpscanner.h"
#include <boost/lexical_cast.hpp>

using namespace std;
using namespace boost;

void TcpScanner::Scan(Services* services)
{
	for (auto service : *services)
	{
		initSocket(service);
	}

	sleep(timeout);

	for (auto service : *services)
	{
		pollSocket(service);
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

	auto data = new ActiveTcpScanData();
	service->data = data;
	data->socket = sock;

	// set it to non-blocking

	u_long mode = 1;
	ioctlsocket(sock, FIONBIO, &mode);

	// allocate file descriptor set

	data->fdset = new fd_set();
	FD_ZERO(data->fdset);
	FD_SET(sock, data->fdset);

	// start non-blocking connection process

	connect(sock, reinterpret_cast<struct sockaddr*>(info->ai_addr), info->ai_addrlen);
}

void TcpScanner::pollSocket(Service* service)
{
	if (service->data == nullptr)
	{
		return;
	}

	TIMEVAL tv = { 0, 0 };
	auto data = reinterpret_cast<ActiveTcpScanData*>(service->data);

	// check if socket is writable, which basically means the connection was successful

	// for some reason, Linux requires the first parameter to be counterintuitively socket+1, while Windows doesn't
	// time spent searching for this error: ~1.5 hours

	select(
		data->socket
#if Linux
			+ 1
#endif
		, nullptr, data->fdset, nullptr, &tv
	);

	// check if the writable flag is set

	auto isOpen = FD_ISSET(data->socket, data->fdset);

#if Linux
	if (isOpen)
	{
		// yet again Linux decided to troll me. all select() requests will become "writable", and you have
		// to check if there was an error or not, to actually determine if the connect() was successful

		int serr;
		socklen_t slen = sizeof(serr);
		getsockopt(data->socket, SOL_SOCKET, SO_ERROR, &serr, &slen);
		isOpen = serr == 0;
	}
#endif

	service->alive = isOpen == 1;

	// clean-up

	service->data = nullptr;

	closesocket(data->socket);

	delete data->fdset;
	delete data;
}