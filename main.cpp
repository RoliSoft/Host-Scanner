#include <iostream>
#include <string>
#include "stdafx.h"
#include "utils.h"
#include "udpscanner.h"

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

#if Windows
	WSACleanup();
	system("pause");
#endif

	return EXIT_SUCCESS;
}
