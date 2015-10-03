#if WIN32
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#endif

#include <iostream>

using namespace std;

int main()
{
#if WIN32
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		cerr << "Failed to initialize WinSock." << endl;
		return EXIT_FAILURE;
	}
#endif

	// set-up address to probe

	struct sockaddr_in addr;
	addr.sin_port = htons(80);
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr("178.62.249.168");

	// create socket

	auto sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	// set it to non-blocking

	u_long mode = 1;
	ioctlsocket(sock, FIONBIO, &mode);

	fd_set rdset;
	FD_ZERO(&rdset);
	FD_SET(sock, &rdset);

	fd_set wrset;
	FD_ZERO(&wrset);
	FD_SET(sock, &wrset);

	fd_set exset;
	FD_ZERO(&exset);
	FD_SET(sock, &exset);

	TIMEVAL tv = { 0, 0 };

	// start connection process

	auto res = connect(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));

	// wait for connection

	Sleep(1000);
	select(sock, &rdset, &wrset, &exset, &tv);
	
	// evaluate results

	if (FD_ISSET(sock, &wrset))
	{
		cout << "Port 80 is open." << endl;
	}
	else
	{
		cout << "Port 80 is not open." << endl;
	}

	// clean-up

	closesocket(sock);

#if WIN32
	WSACleanup();
#endif

	system("pause");
	return EXIT_SUCCESS;
}