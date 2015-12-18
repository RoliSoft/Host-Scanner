/*

	Host Scanner
	Copyright (C) 2015 RoliSoft <root@rolisoft.net>

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU Affero General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU Affero General Public License for more details.

	You should have received a copy of the GNU Affero General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

#include <iostream>
#include <string>
#include <tuple>
#include <fstream>
#include <boost/program_options.hpp>
#include <boost/program_options/parsers.hpp>
#include "Stdafx.h"
#include "Utils.h"
#include "Format.h"
#include "InternalScanner.h"
#include "ShodanScanner.h"
#include "CensysScanner.h"

#if HAVE_CURL
	#include <curl/curl.h>
#endif

using namespace std;
namespace po = boost::program_options;

int main(int argc, char *argv[])
{
#if Windows
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		cerr << "Failed to initialize WinSock." << endl;
		return EXIT_FAILURE;
	}
#endif

#if HAVE_CURL
	curl_global_init(CURL_GLOBAL_DEFAULT);
#endif

	Format::Init();

	po::options_description desc("arguments", 120);
	desc.add_options()
		("target,t", po::value<vector<string>>(),
			"List of targets to scan:\n"
			"  Each can be a hostname, IP address, IP range or CIDR.\n"
			"  E.g. `192.168.1.1/24` is equivalent to `192.168.1.0-192.168.1.255`.")
		("port,p", po::value<string>(),
			"Ports to scan:\n"
			"  Can be a single port (80), a list (22,80) or a range (1-1024).\n"
			"  Range can be unbounded from either sides, simultaneously.\n"
			"  E.g. `1024-` will scan ports 1024-65535. `-` will scan all ports.")
		("scanner,s", po::value<string>(),
			"Scanner instance to use:\n"
			"  internal - Uses the built-in scanner. (active)\n"
			"  nmap     - Uses 3rd-party application Nmap. (active)\n"
			"  shodan   - Uses data from Shodan. (passive; requires API key)\n"
			"  censys   - Uses data from Censys. (passive; requires API key)")
		("shodan-key", po::value<string>(), "Specifies an API key for Shodan.")
		("censys-key", po::value<string>(), "Sepcifies an API key for Censys in the `uid:secret` format.")
		("passive,p", "Globally disables active reconnaissance. Functionality using active scanning will break, but ensures no accidental active scans will be initiated, which might get construed as hostile.")
		("no-logo,q", "Suppresses the ASCII logo.")
		("version,v", "Display version information.")
		("help,h", "Displays this message.")
	;

	po::positional_options_description pos;
	pos.add("target", -1);

	po::variables_map vm;
	po::store(po::command_line_parser(argc, argv).options(desc).positional(pos).run(), vm);

	ifstream inifs("HostScanner.ini");
	if (inifs.good())
	{
		po::store(po::parse_config_file(inifs, desc, true), vm);
		inifs.close();
	}

	po::notify(vm);

	if (vm.count("no-logo") == 0)
	{
		auto app = get<1>(splitPath(getAppPath()));
		cout << Format::Green;
		cout << "  " << Format::Bold << " _   _ "  << Format::Normal << Format::Green << "          _    "   << Format::Bold << " _____"   << Format::Normal << Format::Green << "                                 "    << endl;
		cout << "  " << Format::Bold << "| | | |"  << Format::Normal << Format::Green << "         | |   "   << Format::Bold << "/  ___|"  << Format::Normal << Format::Green << "                                "     << endl;
		cout << "  " << Format::Bold << "| |_| |"  << Format::Normal << Format::Green << " ___  ___| |_  "   << Format::Bold << "\\ `--."  << Format::Normal << Format::Green << "  ___ __ _ _ __  _ __   ___ _ __ "    << endl;
		cout << "  " << Format::Bold << "|  _  |"  << Format::Normal << Format::Green << "/ _ \\/ __| __|  " << Format::Bold << "`--. \\"  << Format::Normal << Format::Green << "/ __/ _` | '_ \\| '_ \\ / _ \\ '__|"  << endl;
		cout << "  " << Format::Bold << "| | | |"  << Format::Normal << Format::Green << " (_) \\__ \\ |_  " << Format::Bold << "/\\__/ /" << Format::Normal << Format::Green << " (_| (_| | | | | | | |  __/ |   "     << endl;
		cout << "  " << Format::Bold << "\\_| |_/" << Format::Normal << Format::Green << "\\___/|___/\\__| " << Format::Bold << "\\____/"  << Format::Normal << Format::Green << " \\___\\__,_|_| |_|_| |_|\\___|_|   " << endl;
		cout << endl;
		cout << "           " << Format::Bold << "https" << Format::Normal << Format::Green << "://" << Format::Bold << "github.com" << Format::Normal << Format::Green << "/" << Format::Bold << "RoliSoft" << Format::Normal << Format::Green << "/" << Format::Bold << "Host-Scanner" << Format::Normal << Format::Default << endl;
		cout << endl;
		cout << "usage: " << app << " [args] targets" << endl;
		cout << desc << endl;
	}

	if (vm.count("shodan-key") != 0)
	{
		cout << vm["shodan-key"].as<string>() << endl;
	}

#if HAVE_CURL
	curl_global_cleanup();
#endif

#if Windows
	WSACleanup();
	system("pause");
#endif

	return EXIT_SUCCESS;
}
