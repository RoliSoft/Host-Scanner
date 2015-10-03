#if _WIN32
	#define Windows 1
#elif __linux__
	#define Linux 1
#endif


#if Windows
	#include <winsock2.h>
	#include <ws2tcpip.h>

	#define sleep(t) Sleep(t)

	#pragma comment(lib, "ws2_32.lib")
#elif Linux
	#include <unistd.h>
	#include <sys/socket.h>
	#include <sys/ioctl.h>
	#include <netinet/in.h>
	#include <arpa/inet.h>

	#define ioctlsocket(x,y,z) ioctl(x,y,z)
	#define sleep(t) usleep(t*1000)
	#define closesocket(s) close(s)

	typedef int SOCKET;
	typedef struct timeval TIMEVAL;
#endif

#include <iostream>
#include <vector>
#include <unordered_map>

using namespace std;

struct service
{
	const char* address;
	unsigned short port;
	SOCKET socket;
	vector<fd_set*>* fdsets;
};

void initService(struct service* serv)
{
	// set-up address to probe

	struct sockaddr_in addr;
	addr.sin_port = htons(serv->port);
	addr.sin_family = AF_INET;
	inet_pton(AF_INET, serv->address, &addr.sin_addr.s_addr);

	// create socket

	auto sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	serv->socket = sock;
	serv->fdsets = new vector<fd_set*>();

	// set it to non-blocking

	u_long mode = 1;
	ioctlsocket(sock, FIONBIO, &mode);

	// allocate file descriptor sets

	auto rdset = new fd_set();
	FD_ZERO(rdset);
	FD_SET(sock, rdset);

	serv->fdsets->push_back(rdset); // 0 -> read

	auto wrset = new fd_set();
	FD_ZERO(wrset);
	FD_SET(sock, wrset);

	serv->fdsets->push_back(wrset); // 1 -> write

	auto exset = new fd_set();
	FD_ZERO(exset);
	FD_SET(sock, exset);

	serv->fdsets->push_back(exset); // 2 -> error

	// start non-blocking connection process

	connect(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
}

void evalService(struct service *serv)
{
	TIMEVAL tv = { 0, 0 };

	// check if socket is writable, which basically means the connection was successful

	// for some reason, Linux requires the first parameter to be counterintuitively socket+1, while Windows doesn't
	// time spent searching for this error: ~1.5 hours

	select(
		serv->socket
#if Linux
			+ 1
#endif
		, serv->fdsets->at(0), serv->fdsets->at(1), serv->fdsets->at(2), &tv
	);

	// check if the writable flag is set

	auto isOpen = FD_ISSET(serv->socket, serv->fdsets->at(1));

#if Linux
	if (isOpen)
	{
		// yet again Linux decided to troll me. all select() requests will become "writable", and you have
		// to check if there was an error or not, to actually determine if the connect() was successful

		int serr;
		socklen_t slen = sizeof(serr);
		getsockopt(serv->socket, SOL_SOCKET, SO_ERROR, &serr, &slen);
		isOpen = serr == 0;
	}
#endif

	if (isOpen)
	{
		cout << "Port " << serv->port << " is open." << endl;
	}
	else
	{
		cout << "Port " << serv->port << " is NOT open." << endl;
	}

	// clean-up

	closesocket(serv->socket);
}

int main()
{
#if Windows
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		cerr << "Failed to initialize WinSock." << endl;
		return EXIT_FAILURE;
	}
#endif

	vector<service> servs = {
		{ "178.62.249.168", 21 },
		{ "178.62.249.168", 22 },
		{ "178.62.249.168", 25 },
		{ "178.62.249.168", 80 },
		{ "178.62.249.168", 81 },
		{ "178.62.249.168", 443 },
		{ "178.62.249.168", 465 },
		{ "178.62.249.168", 587 }
	};

	// start non-blocking connections

	for (auto& serv : servs)
	{
		initService(&serv);
	}

	// wait an arbitrary amount of milliseconds for connections

	sleep(100);

	// collect the result of the connections

	for (auto& serv : servs)
	{
		evalService(&serv);
	}

#if Windows
	WSACleanup();
#endif

	system("pause");
	return EXIT_SUCCESS;
}