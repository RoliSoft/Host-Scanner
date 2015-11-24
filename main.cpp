#include <iostream>
#include <string>
#include <tuple>
#include <boost/program_options.hpp>
#include <curl/curl.h>
#include "stdafx.h"
#include "utils.h"
#include "format.h"
#include "hostscanner.h"

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

	curl_global_init(CURL_GLOBAL_DEFAULT);

	Format::Init();

	po::options_description desc("arguments");
	desc.add_options()
		("help,h", "Shows this message.")
	;

	auto app = get<1>(splitPath(getAppPath()));
	cout << Format::Green;
	cout << "   _   _           _     _____                                 " << endl;
	cout << "  | | | |         | |   /  ___|                                " << endl;
	cout << "  | |_| | ___  ___| |_  \\ `--.  ___ __ _ _ __  _ __   ___ _ __ " << endl;
	cout << "  |  _  |/ _ \\/ __| __|  `--. \\/ __/ _` | '_ \\| '_ \\ / _ \\ '__|" << endl;
	cout << "  | | | | (_) \\__ \\ |_  /\\__/ / (_| (_| | | | | | | |  __/ |   " << endl;
	cout << "  \\_| |_/\\___/|___/\\__| \\____/ \\___\\__,_|_| |_|_| |_|\\___|_|   " << endl;
	cout << "                                                               " << endl;
	cout << "           " << Format::Underline << "https://github.com/RoliSoft/Host-Scanner" << Format::Normal << endl;
	cout << Format::Default << endl;
	cout << "usage: " << app << " [args]" << endl;
	cout << desc << endl;

	curl_global_cleanup();

#if Windows
	WSACleanup();
	system("pause");
#endif

	return EXIT_SUCCESS;
}
