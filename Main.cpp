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
#include <boost/program_options.hpp>
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

#if HAVE_CURL
	curl_global_init(CURL_GLOBAL_DEFAULT);
#endif

	Format::Init();

	po::options_description desc("arguments");
	desc.add_options()
		("help,h", "Shows this message.")
	;

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
	cout << "usage: " << app << " [args]" << endl;
	cout << desc << endl;

#if HAVE_CURL
	curl_global_cleanup();
#endif

#if Windows
	WSACleanup();
	system("pause");
#endif

	return EXIT_SUCCESS;
}
