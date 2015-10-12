#include <iostream>
#include <string>
#include <tuple>
#include <boost/program_options.hpp>
#include "stdafx.h"
#include "utils.h"
#include "format.h"
#include "portscannerfactory.h"
#include "arppinger.h"

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
	/*cout << "usage: " << app << " [args]" << endl;
	cout << desc << endl;*/

	/*Services servs = {
		new Service("178.62.249.168", 0, IPPROTO_ICMP),
		new Service("0.1.2.3", 0, IPPROTO_ICMP)
	};*/

	Services servs = {
		/*new Service("2a03:b0c0:2:d0::19:6001", 0, IPPROTO_NONE),*/
		new Service("192.168.1.1", 0, IPPROTO_NONE),
		new Service("192.168.1.2", 0, IPPROTO_NONE),
		new Service("192.168.1.3", 0, IPPROTO_NONE),
		new Service("192.168.1.4", 0, IPPROTO_NONE),
		new Service("192.168.1.5", 0, IPPROTO_NONE),
		new Service("192.168.1.6", 0, IPPROTO_NONE),
		new Service("192.168.1.7", 0, IPPROTO_NONE),
		new Service("192.168.1.27", 0, IPPROTO_NONE),
		new Service("192.168.1.39", 0, IPPROTO_NONE),
		new Service("192.168.1.168", 0, IPPROTO_NONE),
		new Service("192.168.1.217", 0, IPPROTO_NONE),
		new Service("178.62.249.168", 0, IPPROTO_NONE),
		/*new Service("2a02:2f07:d288:a600:7526:db45:baf4:9a8", 0, IPPROTO_NONE)*/
	};

	auto arp = new ArpPinger();
	arp->Scan(&servs);
	arp->DumpResults(&servs);

#if Windows
	WSACleanup();
	system("pause");
#endif

	return EXIT_SUCCESS;
}
