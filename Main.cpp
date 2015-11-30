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
#include <curl/curl.h>
#include "Stdafx.h"
#include "Utils.h"
#include "Format.h"
#include "InternalScanner.h"

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
