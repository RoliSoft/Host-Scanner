#include <iostream>
#include <string>
#include <tuple>
#include <boost/program_options.hpp>
#include "stdafx.h"
#include "utils.h"
#include "color.h"

using namespace std;
namespace po = boost::program_options;

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

	Color::Init();

	po::options_description desc("arguments");
	desc.add_options()
		("help,h", "Shows this message.")
	;

	auto app = get<1>(splitPath(getAppPath()));
	cout << Color::Green;
	cout << "   _   _           _     _____                                 " << endl;
	cout << "  | | | |         | |   /  ___|                                " << endl;
	cout << "  | |_| | ___  ___| |_  \\ `--.  ___ __ _ _ __  _ __   ___ _ __ " << endl;
	cout << "  |  _  |/ _ \\/ __| __|  `--. \\/ __/ _` | '_ \\| '_ \\ / _ \\ '__|" << endl;
	cout << "  | | | | (_) \\__ \\ |_  /\\__/ / (_| (_| | | | | | | |  __/ |   " << endl;
	cout << "  \\_| |_/\\___/|___/\\__| \\____/ \\___\\__,_|_| |_|_| |_|\\___|_|   " << endl;
	cout << "                                                               " << endl;
	cout << "           https://github.com/RoliSoft/Host-Scanner" << endl;
	cout << Color::Default;
	cout << endl;
	cout << "usage: " << app << " [args]" << endl;
	cout << desc << endl;

#if Windows
	WSACleanup();
	system("pause");
#endif

	return EXIT_SUCCESS;
}
