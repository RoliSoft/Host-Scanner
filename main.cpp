#include <iostream>
#include <string>
#include <tuple>
#include "stdafx.h"
#include "utils.h"

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

	auto app = get<1>(splitPath(getAppPath()));
	cout << "   _   _           _     _____                                 " << endl;
	cout << "  | | | |         | |   /  ___|                                " << endl;
	cout << "  | |_| | ___  ___| |_  \\ `--.  ___ __ _ _ __  _ __   ___ _ __ " << endl;
	cout << "  |  _  |/ _ \\/ __| __|  `--. \\/ __/ _` | '_ \\| '_ \\ / _ \\ '__|" << endl;
	cout << "  | | | | (_) \\__ \\ |_  /\\__/ / (_| (_| | | | | | | |  __/ |   " << endl;
	cout << "  \\_| |_/\\___/|___/\\__| \\____/ \\___\\__,_|_| |_|_| |_|\\___|_|   " << endl;
	cout << "                                                               " << endl;
	cout << "           https://github.com/RoliSoft/Host-Scanner" << endl;
	cout << endl;
	cout << "usage: " << app << endl;
	cout << "help: " << endl;
	cout << endl;
	cout << "  ! CLI is not yet implemented." << endl;
	cout << endl;

#if Windows
	WSACleanup();
	system("pause");
#endif

	return EXIT_SUCCESS;
}
