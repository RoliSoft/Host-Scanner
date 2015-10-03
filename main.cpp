#include "tcpscanner.h"
#include <iostream>

using namespace std;

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

	Services servs = {
		new Service("178.62.249.168", 21),
		new Service("178.62.249.168", 22),
		new Service("178.62.249.168", 25),
		new Service("178.62.249.168", 80),
		new Service("2a03:b0c0:2:d0::19:6001", 81),
		new Service("2a03:b0c0:2:d0::19:6001", 443),
		new Service("2a03:b0c0:2:d0::19:6001", 465),
		new Service("2a03:b0c0:2:d0::19:6001", 587)
	};

	{
		auto tcps = new TcpScanner();
		tcps->Scan(&servs);
		tcps->DumpResults(&servs);
	}

#if Windows
	WSACleanup();
	system("pause");
#endif

	return EXIT_SUCCESS;
}