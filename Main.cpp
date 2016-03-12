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
#include "UdpScanner.h"

#if HAVE_CURL
	#include <curl/curl.h>
#endif

using namespace std;
namespace fs = boost::filesystem;
namespace po = boost::program_options;

/*!
 * Logs the specified message.
 * 
 * Messages at warning or error level will be sent to the standard
 * error, while messages below it will be sent to the standard
 * output. Verbose and debug levels are only printed if the user
 * requested such levels to be shown.
 *
 * \param level The message's severity level.
 * \param msg The message's content.
 */
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

/*!
 * Parses the specified argument value to the port arguments, and
 * generates the corresponding list of ports to be used for scanning.
 *
 * \param portstr Specified value of the argument.
 * \param isudp Value indicating whether the processed argument string
 * 				was specified for the UDP port list.
 * \param retval Reference to the return value. On error, the function will
 * 				 returns an empty set and sets this argument to `EXIT_FAILURE`.
 *
 * \return List of port numbers.
 */
set<unsigned short>* parse_ports(const string& portstr, int& retval, bool isudp = false)
{
	auto ports = new set<unsigned short>();

	if (portstr == "-")
	{
		log(VRB, "Scanning all 65535 ports.");

		for (auto i = 0; i < 65535; i++)
		{
			ports->emplace(i);
		}

		return ports;
	}
	
	if (portstr.length() == 0 || boost::iequals(portstr, "t") || boost::iequals(portstr, "top"))
	{
		if (isudp)
		{
			auto entries = UdpScanner::GetPayloads();

			for (auto entry : entries)
			{
				if (entry.first == 0)
				{
					// skip generic payload
					
					continue;
				}

				ports->emplace(entry.first);
			}

			if (ports->size() == 0)
			{
				log(ERR, "Unable to generate port list based on known payloads.");
				retval = EXIT_FAILURE;
			}
			else
			{
				log(VRB, "Scanning " + to_string(ports->size()) + " ports with known payloads.");
			}
		}
		else
		{
			log(VRB, "Scanning top 100 ports.");

			ports->insert({
				7 , 9 , 13 , 21 , 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135, 139, 143, 144, 179,
				199 , 389, 427, 443, 445, 465, 513, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026,
				1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389,
				3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070,
				8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157
			});
		}

		return ports;
	}

	// read all listed ports

	vector<string> portarr;
	split(portarr, portstr, boost::is_any_of(","), boost::token_compress_on);

	for (auto& s_port : portarr)
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
					return ports;
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
				return ports;
			}

			for (int i = a; i <= b; i++)
			{
				ports->emplace(i);
			}
		}
		else
		{
			int port = atoi(s_port.c_str());

			if (port < 0 || port > 65535)
			{
				log(ERR, "Port '" + s_port + "' out of range.");
				retval = EXIT_FAILURE;
				return ports;
			}

			ports->emplace(port);
		}
	}

	if (ports->size() == 0)
	{
		log(ERR, "Failed to parse ports from '" + portstr + "'.");
		retval = EXIT_FAILURE;
	}
	else
	{
		log(VRB, "Scanning " + to_string(ports->size()) + " " + (isudp ? "UDP" : "TCP") + " ports.");
	}

	return ports;
}

/*!
 * Parses the specified argument values to the host argument, and
 * generates the corresponding list of hosts to be used for scanning.
 *
 * \param hoststrs Specified values of the argument.
 * \param scanner Scanner object instance.
 * \param retval Reference to the return value. On error, the function will
 * 				 returns an empty array and sets this argument to `EXIT_FAILURE`.
 *
 * \return List of hosts.
 */
Hosts* parse_hosts(const vector<string>& hoststrs, HostScanner* scanner, int& retval)
{
	unordered_set<string> hostarr;

	// merge targets specified via positional parameters and targets separated by comma

	for (auto& hoststr : hoststrs)
	{
		if (hoststr.find(",") != string::npos)
		{
			vector<string> host;
			split(host, hoststr, boost::is_any_of(","));
			hostarr.insert(host.begin(), host.end());
		}
		else
		{
			hostarr.emplace(hoststr);
		}
	}

	auto hosts = new Hosts();

	// iterate final target list

	for (auto& s_target : hostarr)
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
				return hosts;
			}

			string addr = s_cidr[0];
			int cidr = atoi(s_cidr[1].c_str());

			if (cidr < 0 || cidr > 32)
			{
				log(ERR, "CIDR notation '" + s_target + "' is out of range.");
				retval = EXIT_FAILURE;
				return hosts;
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
				return hosts;
			}

			if (s_range[1].find("-") != string::npos)
			{
				log(ERR, "Only last octet can be a range in '" + s_target + "'.");
				retval = EXIT_FAILURE;
				return hosts;
			}

			auto lastsep = s_range[0].find_last_of(".");

			if (lastsep == string::npos)
			{
				log(ERR, "Failed to find last octet in '" + s_target + "'.");
				retval = EXIT_FAILURE;
				return hosts;
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

	if (hosts->size() == 0)
	{
		log(ERR, "No targets to scan.");
		retval = EXIT_FAILURE;
	}

	return hosts;
}

/*!
 * Processes the arguments the user passed to the application when launching
 * it, spawns the requested `HostScanner` type of instance, and builds the
 * list of `Host` objects to be scanned based on the specified criteria.
 *
 * \param vm The variable map containing the process arguments.
 *
 * \return Return value to be used as an exit code.
 */
int scan(const po::variables_map& vm)
{
	int retval = EXIT_SUCCESS;

	string scannerstr, portstr, udportstr;
	vector<string> hoststrs;

	HostScanner *scanner = nullptr;
	Hosts *hosts = nullptr;
	set<unsigned short> *ports = nullptr, *udports = nullptr;

	// get scanner

	if (vm.count("scanner") != 0)
	{
		scannerstr = vm["scanner"].as<string>();
		boost::trim(scannerstr);
		boost::to_lower(scannerstr);
	}
	else
	{
		scannerstr = "internal";
	}

	if (scannerstr == "internal" || scannerstr.length() == 0)
	{
		scanner = new InternalScanner();
	}
	else if (scannerstr == "nmap")
	{
		scanner = new NmapScanner();
	}
#if HAVE_CURL
	else if (scannerstr == "shodan")
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
	else if (scannerstr == "censys")
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
		log(ERR, "Scanner '" + scannerstr + "' is not supported.");
		retval = EXIT_FAILURE;
		goto cleanup;
	}

	// check passive

	if (vm.count("passive") != 0 && !(scannerstr == "shodan" || scannerstr == "censys"))
	{
		log(ERR, "Scanner '" + scannerstr + "' is not passive.");
		retval = EXIT_FAILURE;
		goto cleanup;
	}

	// read ports

	if (vm.count("port") != 0)
	{
		portstr = boost::trim_copy(vm["port"].as<string>());
	}

	if (vm.count("udp-port") != 0)
	{
		udportstr = boost::trim_copy(vm["udp-port"].as<string>());
	}

	if (portstr.length() != 0 || (portstr.length() == 0 && udportstr.length() == 0))
	{
		ports = parse_ports(portstr, retval, false);

		if (retval == EXIT_FAILURE)
		{
			goto cleanup;
		}
	}

	if (udportstr.length() != 0)
	{
		udports = parse_ports(udportstr, retval, true);

		if (retval == EXIT_FAILURE)
		{
			goto cleanup;
		}
	}

	// read targets

	if (vm.count("target") != 0)
	{
		hoststrs = vm["target"].as<vector<string>>();
	}

	hosts = parse_hosts(hoststrs, scanner, retval);

	if (retval == EXIT_FAILURE)
	{
		goto cleanup;
	}

	// create the services for the host objects
	
	for (auto host : *hosts)
	{
		if (ports != nullptr)
		{
			host->AddServices(*ports, IPPROTO_TCP);
		}

		if (udports != nullptr)
		{
			host->AddServices(*udports, IPPROTO_UDP);
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

	if (ports != nullptr)
	{
		delete ports;
	}

	if (udports != nullptr)
	{
		delete udports;
	}
	
	return retval;
}

/*!
 * Main entry-point for this application.
 *
 * \param argc Number of command-line arguments.
 * \param argv Array of command-line argument strings.
 *
 * \return Exit-code for the process, 0 for success, else an error code.
 */
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
			"TCP ports to scan:\n"
			"  Can be a single port (80), a list (22,80) or a range (1-1024).\n"
			"  Range can be unbounded from either sides, simultaneously.\n"
			"  E.g. `1024-` will scan ports 1024-65535. `-` will scan all ports.\n"
			"  Specifying `top` or `t` will scan the top 100 most popular ports.")
		("udp-port,u", po::value<string>(),
			"UDP ports to scan:\n"
			"  Supports the same values as --port, with the difference that\n"
			"  specifying `top` will scan all of the ports with known payloads.")
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
