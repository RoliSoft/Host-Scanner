/*

	Host Scanner
	Copyright (C) 2016 RoliSoft <root@rolisoft.net>

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

#include <iostream>
#include <string>
#include <tuple>
#include <vector>
#include <set>
#include <unordered_set>
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include "Stdafx.h"
#include "Utils.h"
#include "Format.h"
#include "HostScanner.h"
#include "InternalScanner.h"
#include "NmapScanner.h"
#include "ShodanScanner.h"
#include "CensysScanner.h"

#if HAVE_CURL
	#include <curl/curl.h>
#endif

using namespace std;
namespace fs = boost::filesystem;
namespace po = boost::program_options;

void log(int level, const string& msg)
{
	ostream* os;

	switch (level)
	{
	case ERR:
		os = &cerr;
		cout << Format::Bold << Format::Red << "[!] " << Format::Default << Format::Normal;
		break;
	case WRN:
		os = &cerr;
		cout << Format::Bold << Format::Yellow << "[!] " << Format::Default << Format::Normal;
		break;
	case VRB:
		os = &cout;
		cout << Format::Green << "[.] " << Format::Default;
		break;
	case DBG:
		os = &cout;
		cout << Format::Green << "[ ] " << Format::Default;
		break;
	default:
		os = &cout;
		cout << Format::Green << "[*] " << Format::Default;
		break;
	}

	*os << msg << endl;
}

inline int scan(const po::variables_map& vm)
{
	int retval = EXIT_SUCCESS;

	string p_scanner;
	string p_port;
	vector<string> p_target;

	HostScanner* scanner = nullptr;
	Hosts* hosts = nullptr;
	set<int> ports;

	// get scanner

	if (vm.count("scanner") != 0)
	{
		p_scanner = vm["scanner"].as<string>();
		boost::trim(p_scanner);
		boost::to_lower(p_scanner);
	}
	else
	{
		p_scanner = "internal";
	}

	if (p_scanner == "internal" || p_scanner.length() == 0)
	{
		scanner = new InternalScanner();
	}
	else if (p_scanner == "nmap")
	{
		scanner = new InternalScanner();// TODO NmapScanner();
	}
#if HAVE_CURL
	else if (p_scanner == "shodan")
	{
		string key;

		if (vm.count("shodan-key") != 0)
		{
			key = vm["shodan-key"].as<string>();
		}

		if (key.length() < 2)
		{
			log(ERR, "Shodan requires an API key via --shodan-key from https://account.shodan.io/");
			retval = EXIT_FAILURE;
			goto cleanup;
		}

		scanner = new ShodanScanner();
		(reinterpret_cast<ShodanScanner*>(scanner))->key = key;
	}
	else if (p_scanner == "censys")
	{
		string key;

		if (vm.count("censys-key") != 0)
		{
			key = vm["censys-key"].as<string>();
		}

		if (key.length() < 2 || key.find(":") == string::npos)
		{
			log(ERR, "Censys requires token in `uid:secret` format via --censys-key from https://censys.io/account");
			retval = EXIT_FAILURE;
			goto cleanup;
		}

		scanner = new CensysScanner();
		(reinterpret_cast<CensysScanner*>(scanner))->auth = key;
	}
#else
	else if (p_scanner == "shodan" || p_scanner == "censys")
	{
		log(ERR, "Scanner '" + p_scanner + "' is not available as this version of the binary was compiled without libcurl.");
		retval = EXIT_FAILURE;
		goto cleanup;
	}
#endif
	else
	{
		log(ERR, "Scanner '" + p_scanner + "' is not supported.");
		retval = EXIT_FAILURE;
		goto cleanup;
	}

	// check passive

	if (vm.count("passive") != 0 && !(p_scanner == "shodan" || p_scanner == "censys"))
	{
		log(ERR, "Scanner '" + p_scanner + "' is not passive.");
		retval = EXIT_FAILURE;
		goto cleanup;
	}

	// read ports

	if (vm.count("port") != 0)
	{
		p_port = vm["port"].as<string>();
	}

	if (p_port == "-")
	{
		log(VRB, "Scanning all 65535 ports.");
	}
	else if (p_port.length() == 0)
	{
		log(VRB, "Scanning top 100 ports.");
	}
	else
	{
		// read all listed ports

		vector<string> s_ports;
		split(s_ports, p_port, boost::is_any_of(","), boost::token_compress_on);

		for (auto& s_port : s_ports)
		{
			// check if range

			if (s_port.find("-") != string::npos)
			{
				// check if unbounded

				int a, b;

				if (boost::starts_with(s_port, "-"))
				{
					// from 1 to n	

					a = 1;
					b = atoi(s_port.substr(1).c_str());
				}
				else if (boost::ends_with(s_port, "-"))
				{
					// from n to 65535

					a = atoi(s_port.c_str());
					b = 65535;
				}
				else
				{
					// range specified

					vector<string> s_range;
					split(s_range, s_port, boost::is_any_of("-"), boost::token_compress_on);

					if (s_range.size() < 2)
					{
						log(ERR, "Unable to parse '" + s_port + "' in port list.");
						retval = EXIT_FAILURE;
						goto cleanup;
					}

					a = atoi(s_range[0].c_str());
					b = atoi(s_range[1].c_str());

					if (a > b)
					{
						swap(a, b);
					}
				}

				if (a < 1 || a > 65535 || b < 1 || b > 65535)
				{
					log(ERR, "Port range '" + s_port + "' is invalid.");
					retval = EXIT_FAILURE;
					goto cleanup;
				}

				for (int i = a; i <= b; i++)
				{
					ports.emplace(i);
				}
			}
			else
			{
				int port = atoi(s_port.c_str());

				if (port < 0 || port > 65535)
				{
					log(ERR, "Port '" + s_port + "' out of range.");
					retval = EXIT_FAILURE;
					goto cleanup;
				}

				ports.emplace(port);
			}
		}

		if (ports.size() < 1)
		{
			log(ERR, "Failed to parse ports from '" + p_port + "'.");
			retval = EXIT_FAILURE;
			goto cleanup;
		}

		log(VRB, "Scanning " + to_string(ports.size()) + " ports.");
	}

	// read targets

	if (vm.count("target") != 0)
	{
		p_target = vm["target"].as<vector<string>>();
	}

	if (p_target.size() == 0)
	{
		log(ERR, "No targets to scan.");
		retval = EXIT_FAILURE;
		goto cleanup;
	}
	else
	{
		unordered_set<string> f_target;

		// merge targets specified via positional parameters and targets separated by comma

		for (auto& s_target : p_target)
		{
			if (s_target.find(",") != string::npos)
			{
				vector<string> t_target;
				split(t_target, s_target, boost::is_any_of(","));
				f_target.insert(t_target.begin(), t_target.end());
			}
			else
			{
				f_target.emplace(s_target);
			}
		}

		hosts = new Hosts();

		// iterate final target list

		for (auto& s_target : f_target)
		{
			if (s_target.find("/") != string::npos)
			{
				// CIDR

				vector<string> s_cidr;
				split(s_cidr, s_target, boost::is_any_of("/"), boost::token_compress_on);

				if (s_cidr.size() != 2)
				{
					log(ERR, "CIDR notation '" + s_target + "' is invalid.");
					retval = EXIT_FAILURE;
					goto cleanup;
				}

				string addr = s_cidr[0];
				int cidr = atoi(s_cidr[1].c_str());

				if (cidr < 0 || cidr > 32)
				{
					log(ERR, "CIDR notation '" + s_target + "' is out of range.");
					retval = EXIT_FAILURE;
					goto cleanup;
				}

				log(VRB, "Scanning hosts in " + addr + "/" + to_string(cidr) + ".");

				scanner->GenerateCidr(addr.c_str(), cidr, hosts);
			}
			else if (s_target.find("-") != string::npos)
			{
				// range

				vector<string> s_range;
				split(s_range, s_target, boost::is_any_of("-"), boost::token_compress_on);

				if (s_range.size() != 2)
				{
					log(ERR, "Range notation '" + s_target + "' is invalid.");
					retval = EXIT_FAILURE;
					goto cleanup;
				}

				if (s_range[1].find("-") != string::npos)
				{
					log(ERR, "Only last octet can be a range in '" + s_target + "'.");
					retval = EXIT_FAILURE;
					goto cleanup;
				}

				auto lastsep = s_range[0].find_last_of(".");

				if (lastsep == string::npos)
				{
					log(ERR, "Failed to find last octet in '" + s_target + "'.");
					retval = EXIT_FAILURE;
					goto cleanup;
				}

				string from = s_range[0];
				string to   = s_range[0].substr(0, lastsep) + "." + s_range[1];

				log(VRB, "Scanning hosts " + from + " to " + to + ".");

				scanner->GenerateRange(from.c_str(), to.c_str(), hosts);
			}
			else
			{
				// IP or host

				log(VRB, "Scanning host " + s_target + ".");

				hosts->push_back(new Host(s_target.c_str()));
			}
		}
	}

	// start scan

	log("Initiating scan against " + pluralize(hosts->size(), "host") + "...");

	scanner->Scan(hosts);

	scanner->DumpResults(hosts);

cleanup:
	if (scanner != nullptr)
	{
		delete scanner;
	}

	if (hosts != nullptr)
	{
		delete hosts;
	}

	return retval;
}

int main(int argc, char *argv[])
{
#if Windows
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		log(ERR, "Failed to initialize WinSock.");
		return EXIT_FAILURE;
	}
#endif

#if HAVE_CURL
	curl_global_init(CURL_GLOBAL_DEFAULT);
#endif

	Format::Init();

	po::options_description desc("arguments", 100);
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
		("passive,x", "Globally disables active reconnaissance. Functionality using active scanning will break, but ensures no accidental active scans will be initiated, which might get construed as hostile.")
		("no-logo,q", "Suppresses the ASCII logo.")
		("version,v", "Display version information.")
		("help,h", "Displays this message.")
	;

	po::positional_options_description pos;
	pos.add("target", -1);

	po::variables_map vm;
	po::store(po::command_line_parser(argc, argv).options(desc).positional(pos).run(), vm);

	vector<string> paths = {
#if Windows
		get<0>(splitPath(getAppPath())) + "\\HostScanner.ini",
		getEnvVar("APPDATA") + "\\RoliSoft\\Host Scanner\\HostScanner.ini"
#else
		get<0>(splitPath(getAppPath())) + "/HostScanner.ini",
		getEnvVar("HOME") + "/.HostScanner.conf",
		"/etc/HostScanner/HostScanner.conf"
#endif
	};

	for (auto path : paths)
	{
		fs::path fp(path);

		if (fs::exists(fp) && fs::is_regular_file(fp))
		{
			po::store(po::parse_config_file<char>(path.c_str(), desc, true), vm);
		}
	}

	po::notify(vm);

	int  retval  = EXIT_SUCCESS;
	bool handled = false;

	if (vm.count("no-logo") == 0)
	{
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
	}

	if (vm.count("target") != 0 && !(vm.count("version") != 0 || vm.count("help") != 0))
	{
		handled = true;
		retval  = scan(vm);
	}
	else if (vm.count("version") != 0)
	{
		handled = true;

		if (vm.count("no-logo") == 0)
		{
			cout << "           " << string((40 - (14 + strlen(VERSION_STRING))) / 2, ' ');
		}

		cout << Format::Green << Format::Bold << "Host Scanner v" << VERSION_STRING << Format::Normal << Format::Default << endl;

		if (vm.count("no-logo") == 0)
		{
			cout << endl;
		}
	}
	else // if (vm.count("help") != 0)
	{
		auto app = get<1>(splitPath(getAppPath()));
		cout << "usage: " << app << " [args] targets" << endl;
		cout << desc << endl;

		if (vm.count("help") != 0)
		{
			handled = true;
		}
	}

#if HAVE_CURL
	curl_global_cleanup();
#endif

#if Windows
	WSACleanup();
#endif

	return !handled ? EXIT_FAILURE : retval;
}
