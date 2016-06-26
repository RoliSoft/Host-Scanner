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

#include "Stdafx.h"
#include "Utils.h"
#include "Format.h"
#include "HostScanner.h"
#include "InternalScanner.h"
#include "NmapScanner.h"
#include "UdpScanner.h"
#include "PassiveScanner.h"
#include "ShodanScanner.h"
#include "CensysScanner.h"
#include "LooquerScanner.h"
#include "OperatingSystemIdentifier.h"
#include "BannerProcessor.h"
#include "VulnerabilityLookup.h"
#include "VendorLookupFactory.h"
#include <iostream>
#include <fstream>
#include <string>
#include <tuple>
#include <vector>
#include <set>
#include <mutex>
#include <iomanip>
#include <unordered_set>
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/core/ignore_unused.hpp>
#include <boost/regex.hpp>

#if HAVE_CURL
	#include <curl/curl.h>
#endif

using namespace std;
using namespace boost;

namespace fs = boost::filesystem;
namespace po = boost::program_options;

/*!
 * The logging severity threshold.
 * Messages below this level will not be printed.
 */
int logging_level = MSG;

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
	if (level < logging_level)
	{
		return;
	}

	static mutex mtx;
	lock_guard<mutex> guard(mtx);

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
		cout << Format::Green << "[-] " << Format::Default;
		break;
	case DBG:
		os = &cout;
		cout << Format::Green << "[.] " << Format::Default;
		break;
	case INT:
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
		log(VRB, "Scanning all 65535 " + string(isudp ? "UDP" : "TCP") + " ports.");

		for (auto i = 0; i < 65535; i++)
		{
			ports->emplace(i);
		}

		return ports;
	}
	
	if (portstr.length() == 0 || iequals(portstr, "t") || iequals(portstr, "top"))
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
				log(VRB, "Scanning " + to_string(ports->size()) + " UDP ports with known payloads.");
			}
		}
		else
		{
			log(VRB, "Scanning the top 100 TCP ports.");

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

	try
	{
		split(portarr, portstr, is_any_of(","), token_compress_on);
	}
	catch (boost::exception&)
	{
		log(ERR, "Unable to parse port list '" + portstr + "'.");
		retval = EXIT_FAILURE;
		return ports;
	}

	for (auto& s_port : portarr)
	{
		// check if range

		if (s_port.find("-") != string::npos)
		{
			// check if unbounded

			int a, b;

			if (starts_with(s_port, "-"))
			{
				// from 1 to n	

				a = 1;
				b = stoi(s_port.substr(1));
			}
			else if (ends_with(s_port, "-"))
			{
				// from n to 65535

				a = stoi(s_port);
				b = 65535;
			}
			else
			{
				// range specified

				vector<string> s_range;
				split(s_range, s_port, is_any_of("-"), token_compress_on);

				if (s_range.size() < 2)
				{
					log(ERR, "Unable to parse '" + s_port + "' in port list.");
					retval = EXIT_FAILURE;
					return ports;
				}

				a = stoi(s_range[0]);
				b = stoi(s_range[1]);

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
			int port = stoi(s_port);

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
#if _MSC_VER
	// even though it's used later on, MSVC is issuing an 'unreferenced formal parameter' warning for `scanner`
	ignore_unused(scanner);
#endif

	unordered_set<string> hostarr;

	// merge targets specified via positional parameters and targets separated by comma

	for (auto& hoststr : hoststrs)
	{
		if (hoststr.find(",") != string::npos)
		{
			vector<string> host;
			split(host, hoststr, is_any_of(","));
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
			split(s_cidr, s_target, is_any_of("/"), token_compress_on);

			if (s_cidr.size() != 2)
			{
				log(ERR, "CIDR notation '" + s_target + "' is invalid.");
				retval = EXIT_FAILURE;
				return hosts;
			}

			string addr = s_cidr[0];
			int cidr = stoi(s_cidr[1]);

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
			split(s_range, s_target, is_any_of("-"), token_compress_on);

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

			if (s_target.find_first_not_of(".0123456789") == string::npos
			 || s_target.find_first_not_of(":0123456789abcdef") == string::npos)
			{
				// IPv4 or v6

				log(VRB, "Scanning host " + s_target + ".");

				hosts->push_back(new Host(s_target.c_str()));
			}
			else
			{
				// hostname

				struct addrinfo hint, *info = nullptr;
				memset(&hint, 0, sizeof(struct addrinfo));
				hint.ai_family = AF_UNSPEC; // allow both v4 and v6

				getaddrinfo(s_target.c_str(), 0, &hint, &info);

				if (info == nullptr)
				{
					log(ERR, "Failed to DNS resolve hostname '" + s_target + "'.");
					retval = EXIT_FAILURE;
					return hosts;
				}

				auto infoit = info;

				while (infoit != nullptr)
				{
					char infostr[INET6_ADDRSTRLEN];

					switch (infoit->ai_family)
					{
					case AF_INET:
						inet_ntop(AF_INET, &reinterpret_cast<struct sockaddr_in*>(infoit->ai_addr)->sin_addr, infostr, INET_ADDRSTRLEN);
						break;

					case AF_INET6:
						inet_ntop(AF_INET6, &reinterpret_cast<struct sockaddr_in6*>(infoit->ai_addr)->sin6_addr, infostr, INET6_ADDRSTRLEN);
						break;

					default:
						log(ERR, "Failed to DNS resolve hostname '" + s_target + "': unsupported address family of " + to_string(infoit->ai_family) + ".");
						retval = EXIT_FAILURE;
						freeaddrinfo(info);
						return hosts;
					}

					log(VRB, "Scanning host " + s_target + " at " + string(infostr) + ".");

					hosts->push_back(new Host(infostr));

					infoit = infoit->ai_next;
				}

				freeaddrinfo(info);
			}
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

	bool resolve;
	unordered_map<string, vector<CveEntry>> cpevulns;
	unordered_map<Host*, unordered_set<string>> hostpkgs;
	unordered_map<Service*, unordered_set<string>> servpkgs;
	unordered_map<char, int> stats;

	string latexOut, latexContent, latexTitle, latexAbstract;

	Services services;

	// get scanner

	if (vm.count("scanner") != 0)
	{
		try
		{
			scannerstr = vm["scanner"].as<string>();
			trim(scannerstr);
			to_lower(scannerstr);
		}
		catch (boost::exception&)
		{
			log(ERR, "Unable to parse scanner argument.");
			retval = EXIT_FAILURE;
			goto cleanup;
		}
	}
	else
	{
		scannerstr = vm.count("passive") != 0 ? "shosys" : "internal";
	}

	if (scannerstr == "internal" || scannerstr.length() == 0)
	{
		scanner = new InternalScanner();

		if (vm.count("delay") != 0)
		{
			auto delay   = min(max(0, vm["delay"].as<int>()), 6);
			auto delayms = 100ul;

			switch (delay)
			{
			case 0: delayms = 300000; break; // 5m
			case 1: delayms = 15000; break; // 15s
			case 2: delayms = 400; break;
			case 3: delayms = 100; break;
			case 4: delayms = 10; break;
			case 5: delayms = 5; break;
			case 6: delayms = 0; break;
			}

			reinterpret_cast<InternalScanner*>(scanner)->SetOption(OPT_DELAY, &delayms);
		}
	}
	else if (scannerstr == "nmap")
	{
		scanner = new NmapScanner();

		if (vm.count("delay") != 0)
		{
			auto delay = min(max(0, vm["delay"].as<int>()), 5);

			reinterpret_cast<NmapScanner*>(scanner)->SetOption(OPT_DELAY, &delay);
		}
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

		scanner = new ShodanScanner(key);

		if (vm.count("shodan-uri") != 0)
		{
			reinterpret_cast<ShodanScanner*>(scanner)->SetEndpoint(vm["shodan-uri"].as<string>());
		}
	}
	else if (scannerstr == "censys")
	{
		string auth;

		if (vm.count("censys-key") != 0)
		{
			auth = vm["censys-key"].as<string>();
		}

		if (auth.length() < 2 || auth.find(":") == string::npos)
		{
			log(ERR, "Censys requires token in `uid:secret` format via --censys-key from https://censys.io/account");
			retval = EXIT_FAILURE;
			goto cleanup;
		}

		scanner = new CensysScanner(auth);

		if (vm.count("censys-uri") != 0)
		{
			reinterpret_cast<CensysScanner*>(scanner)->SetEndpoint(vm["censys-uri"].as<string>());
		}
	}
	else if (scannerstr == "looquer")
	{
		string key;

		if (vm.count("looquer-key") != 0)
		{
			key = vm["looquer-key"].as<string>();
		}

		if (key.length() < 2)
		{
			log(ERR, "Mr Looquer requires an API key via --looquer-key from https://mrlooquer.com/manage");
			retval = EXIT_FAILURE;
			goto cleanup;
		}

		scanner = new LooquerScanner(key);

		if (vm.count("looquer-uri") != 0)
		{
			reinterpret_cast<LooquerScanner*>(scanner)->SetEndpoint(vm["looquer-uri"].as<string>());
		}
	}
	else if (scannerstr == "shosys" || scannerstr == "cendan")
	{
		string shodan_key, censys_auth, looquer_key;

		if (vm.count("shodan-key") != 0)
		{
			shodan_key = vm["shodan-key"].as<string>();
		}

		if (shodan_key.length() < 2)
		{
			log(WRN, "Shodan requires an API key via --shodan-key from https://account.shodan.io/");
			shodan_key.clear();
		}

		if (vm.count("censys-key") != 0)
		{
			censys_auth = vm["censys-key"].as<string>();
		}

		if (censys_auth.length() < 2 || censys_auth.find(":") == string::npos)
		{
			log(WRN, "Censys requires token in `uid:secret` format via --censys-key from https://censys.io/account");
			censys_auth.clear();
		}

		if (vm.count("looquer-key") != 0)
		{
			looquer_key = vm["looquer-key"].as<string>();
		}

		if (looquer_key.length() < 2)
		{
			log(WRN, "Mr Looquer requires an API key via --looquer-key from https://mrlooquer.com/manage");
			looquer_key.clear();
		}

		if (shodan_key.length() < 2 && censys_auth.length() < 2 && looquer_key.length() < 2)
		{
			log(ERR, "You need to specify at least one API key for this scanner.");
			retval = EXIT_FAILURE;
			goto cleanup;
		}

		scanner = new PassiveScanner(shodan_key, censys_auth, looquer_key);

		if (vm.count("shodan-uri") != 0)
		{
			reinterpret_cast<PassiveScanner*>(scanner)->SetShodanEndpoint(vm["shodan-uri"].as<string>());
		}

		if (vm.count("censys-uri") != 0)
		{
			reinterpret_cast<PassiveScanner*>(scanner)->SetCensysEndpoint(vm["censys-uri"].as<string>());
		}

		if (vm.count("looquer-uri") != 0)
		{
			reinterpret_cast<PassiveScanner*>(scanner)->SetLooquerEndpoint(vm["looquer-uri"].as<string>());
		}
	}
#else
	else if (scannerstr == "shodan" || scannerstr == "censys" || scannerstr == "looquer" || scannerstr == "shosys" || scannerstr == "cendan")
	{
		log(ERR, "Scanner '" + scannerstr + "' is not available as this version of the binary was compiled without libcurl.");
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

	// check if input file was provided

	if (vm.count("input-file") != 0)
	{
		if (scannerstr != "nmap")
		{
			log(ERR, "Only the nmap scanner supports input files at this time.");
			retval = EXIT_FAILURE;
			goto cleanup;
		}

		auto fname = vm["input-file"].as<string>();

		log(VRB, "Processing file '" + fs::path(fname).filename().string() + "'...");

		ifstream fs(fname);

		if (!fs.good())
		{
			log(ERR, "Failed to open the specified input file for reading.");
			retval = EXIT_FAILURE;
			goto cleanup;
		}
		
		stringstream buf;
		buf << fs.rdbuf();

		hosts = reinterpret_cast<NmapScanner*>(scanner)->Process(buf.str());
		goto postScan;
	}

	// check passive

	if (vm.count("passive") != 0 && !scanner->IsPassive())
	{
		log(ERR, "Scanner '" + scannerstr + "' is not passive.");
		retval = EXIT_FAILURE;
		goto cleanup;
	}

	// read ports

	if (vm.count("port") != 0)
	{
		portstr = trim_copy(vm["port"].as<string>());
	}

	if (vm.count("udp-port") != 0)
	{
		udportstr = trim_copy(vm["udp-port"].as<string>());
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

postScan:
	scanner->DumpResults(hosts);

	if (vm.count("output-latex") != 0)
	{
		latexOut = vm["output-latex"].as<string>();

		latexTitle = "Scan report for ";

		for (auto hoststr : hoststrs)
		{
			latexTitle += hoststr + ", ";
		}

		latexTitle = latexTitle.substr(0, latexTitle.size() - 2);
	}

	// start OS detection

	log("Initiating identification of " + pluralize(hosts->size(), "operating system") + "...");

	for (auto host : *hosts)
	{
		auto res = OperatingSystemIdentifier::AutoProcess(host);

		if (res)
		{
			log(MSG, host->address + " is running cpe:/" + host->cpe[0]);
		}

		for (auto service : *host->services)
		{
			if (service->banner.length() != 0)
			{
				services.push_back(service);
			}
		}
	}

	// start CPE detection

	resolve = vm.count("resolve") != 0;

	log("Initiating identification of " + pluralize(services.size(), "service banner") + "...");

	for (auto service : services)
	{
		auto cpes = BannerProcessor::AutoProcess(service->banner, true);

		if (cpes.size() != 0)
		{
			service->cpe.insert(service->cpe.end(), cpes.begin(), cpes.end());
			sort(service->cpe.begin(), service->cpe.end());
			service->cpe.erase(unique(service->cpe.begin(), service->cpe.end()), service->cpe.end());
		}

		// list detected CPE names

		if (service->cpe.size() != 0)
		{
			stats['i']++;

			string cpestr;

			for (auto it = service->cpe.begin(), end = service->cpe.end(); it != end; ++it)
			{
				cpestr += ", cpe:/" + *it;
			}

			log(MSG, service->address + ":" + to_string(service->port) + " is running " + cpestr.substr(2));
		}

		// perform vulnerability lookup for the names

		VulnerabilityLookup vl;

		auto vulns = vl.Scan(service->cpe);

		if (vulns.size() > 0)
		{
			for (auto vuln : vulns)
			{
				if (cpevulns[vuln.first].empty())
				{
					cpevulns[vuln.first].insert(cpevulns[vuln.first].end(), vuln.second.begin(), vuln.second.end());
				}

				string vulnstr;

				for (auto it = vuln.second.begin(), end = vuln.second.end(); it != end; ++it)
				{
					vulnstr += ", CVE-" + (*it).cve + " (" + trim_right_copy_if(to_string((*it).severity), [](char c) { return c == '0' || c == '.'; }) + ")";

					if ((*it).severity >= 9)
					{
						stats['c']++;
					}
					else if ((*it).severity >= 7)
					{
						stats['h']++;
					}
					else if ((*it).severity >= 4)
					{
						stats['m']++;
					}
					else
					{
						stats['l']++;
					}

					if ((*it).access == "n")
					{
						stats['r']++;
					}
				}

				log(WRN, "cpe:/" + vuln.first + " is vulnerable to " + vulnstr.substr(2));

				// resolve CPE name to OS package, if requested

				if (resolve && service->host->opSys != OpSys::Unidentified)
				{
					auto vpl = VendorLookupFactory::Get(service->host->opSys);

					if (vpl != nullptr)
					{
						auto pkgs = vpl->FindVulnerability("CVE-" + (*vuln.second.begin()).cve, service->host->opSys, service->host->osVer);

						if (pkgs.size() > 0)
						{
							servpkgs[service].insert(pkgs.begin(), pkgs.end());
							hostpkgs[service->host].insert(pkgs.begin(), pkgs.end());

							string pkgstr;

							for (auto it = pkgs.begin(), end = pkgs.end(); it != end; ++it)
							{
								pkgstr += ", " + *it;
							}

							log(MSG, service->address + " needs update for " + pkgstr.substr(2));
						}
					}
				}
			}
		}
	}

	// print final stats

	if (!stats.empty() || !latexOut.empty())
	{
		if (stats['r'] > 0)
		{
			log(MSG, pluralize(stats['r'], "service", true) + " remotely exploitable.");
		}

		log(MSG, to_string(stats['c']) + " critical, " + to_string(stats['h']) + " high, " + to_string(stats['m']) + " medium and " + to_string(stats['l']) + " low severity vulnerabilities across " + pluralize(services.size(), "service") + " and " + pluralize(hosts->size(), "server") + ".");

	}

	// generate latex report, if requested
	
	if (!latexOut.empty())
	{
		// generate abstract

		latexAbstract = pluralize(hosts->size(), "IP", true, true) + " scanned having " + pluralize(services.size(), "service") + " from which " + pluralize(stats['i'], "service", true, true) + " identified, having " + to_string(stats['c']) + " critical, " + to_string(stats['h']) + " high, " + to_string(stats['m']) + " medium and " + to_string(stats['l']) + " low severity vulnerabilities.";

		if (stats['r'] > 0)
		{
			latexAbstract += " " + to_string(stats['r']) + " service vulnerabilit" + (stats['r'] > 1 ? "ies were" : "y was") + " found to be remotely exploitable.";
		}
		else
		{
			latexAbstract += " No services were found to be remotely exploitable.";
		}

		// generate content
		
		for (auto host : *hosts)
		{
			auto section = "\n\\section{" + host->address + "}\n";
			auto any = false;

			if (!host->cpe.empty())
			{
				latexContent += section;
				any = true;

				string cpestr;

				for (auto it = host->cpe.begin(), end = host->cpe.end(); it != end; ++it)
				{
					cpestr += ", " + (*it).substr(2);
				}

				replace(cpestr.begin(), cpestr.end(), ':', ' ');
				replace(cpestr.begin(), cpestr.end(), '_', ' ');

				cpestr = regex_replace(cpestr, regex("\\b(\\w+)\\s+\\1\\b"), "\\1");

				latexContent += "\n\tThis host was identified to be running \\textbf{" + cpestr.substr(2) + "}.\n";
			}

			for (auto service : *host->services)
			{
				if (!service->alive || (service->cpe.empty() && service->banner.empty()))
				{
					continue;
				}

				if (!any)
				{
					latexContent += section;
					any = true;
				}

				latexContent += "\n\t\\subsection{Port " + to_string(service->port) + "}\n";

				if (!service->banner.empty())
				{
					// escape non-printable characters in service banner

					ostringstream banner;

					for (auto it = service->banner.begin(), end = service->banner.end(); it != end; ++it)
					{
						if (' ' <= *it && *it <= '~' || *it == '\r' || *it == '\n' || *it == '\t')
						{
							banner << *it;
						}
						else
						{
							banner << "\\x" << setw(2) << hex << setfill('0') << *it;
						}
					}

					latexContent += "\n\t\t\\begin{lstlisting}\n" + banner.str() + "\n\t\t\\end{lstlisting}\n";
				}

				if (!service->cpe.empty())
				{
					string cpestr;

					for (auto it = service->cpe.begin(), end = service->cpe.end(); it != end; ++it)
					{
						cpestr += ", " + (*it).substr(2);
					}

					replace(cpestr.begin(), cpestr.end(), ':', ' ');
					replace(cpestr.begin(), cpestr.end(), '_', ' ');

					cpestr = regex_replace(cpestr, regex("\\b(\\w+)\\s+\\1\\b"), "\\1");

					latexContent += "\n\t\tThis service was identified to be running \\textbf{" + cpestr.substr(2) + "}." + (!service->banner.empty() ? "\\\\" : "") + "\n";

					for (auto cpe : service->cpe)
					{
						if (cpevulns[cpe].empty())
						{
							continue;
						}

						for (auto cve : cpevulns[cpe])
						{
							string color;

							if (cve.severity >= 9)
							{
								color = "Red";
							}
							else if (cve.severity >= 7)
							{
								color = "Orange";
							}
							else if (cve.severity >= 4)
							{
								color = "Black";
							}
							else
							{
								color = "Green";
							}

							latexContent += "\n\t\t\\subsubsection{\\textcolor{" + color + "}{CVE-" + cve.cve + "}}\n";

							if (!cve.descr.empty())
							{
								auto descr = regex_replace(cve.descr, regex("\\\\"), "\\\\\\\\");
								     descr = regex_replace(descr, regex("([_#$])"), "\\\\\\1");

								latexContent += "\n\t\t\t" + descr + "\n";
							}

							string access;

							switch (cve.access[0])
							{
							case 'l':
								access = "requires local access to exploit";
								break;
							case 'a':
								access = "requires access to the adjacent network to exploit";
								break;
							case 'n':
								access = "is \\textbf{remotely exploitable}";
								break;
							default:
								access = "its access vector is unknown";
								break;
							}

							auto scpestr = cpe.substr(2);

							replace(scpestr.begin(), scpestr.end(), ':', ' ');
							replace(scpestr.begin(), scpestr.end(), '_', ' ');

							scpestr = regex_replace(scpestr, regex("\\b(\\w+)\\s+\\1\\b"), "\\1");

							latexContent += "\n\t\t\tThis vulnerability affects " + scpestr + ", it has a CVSS score of \\textbf{" + trim_right_copy_if(to_string(cve.severity), [](char c) { return c == '0' || c == '.'; }) + "} and " + access + ".\n";
							latexContent += "\n\t\t\t\\href{https://web.nvd.nist.gov/view/vuln/detail?vulnId=" + cve.cve + "}{Vulnerability Summary at NVD}\n";
						}
					}
				}
				else
				{
					latexContent += "\n\t\tThis port was open, but failed to be identified." + string(!service->banner.empty() ? "\\\\" : "") + "\n";
				}
			}
		}
	}

	if (resolve && !hostpkgs.empty())
	{
		if (!latexOut.empty())
		{
			latexContent += "\n\\section{Mitigation Recommendations}\n";
		}

		for (auto& pkgs : hostpkgs)
		{
			if (pkgs.second.empty())
			{
				continue;
			}

			auto vpl = VendorLookupFactory::Get(pkgs.first->opSys);

			if (vpl == nullptr)
			{
				continue;
			}

			auto cmd = vpl->GetUpgradeCommand(pkgs.second);

			log(MSG, pkgs.first->address + " -> " + cmd);

			if (!latexOut.empty())
			{
				auto texcmd = regex_replace(cmd, regex("_"), "\\_");

				latexContent += "\n\t\\subsection{" + pkgs.first->address + "}\n";
				latexContent += "\n\t\begin{lstlisting}\n" + texcmd + "\n\t\\end{lstlisting}\n";
			}
		}
	}

	// save latex report

	if (!latexOut.empty())
	{
		latexContent =
			string("\\documentclass[12pt,a4paper]{article}\n\n") +
			string("\\usepackage[a4paper,total={6.5in,9in}]{geometry}\n") +
			string("\\usepackage[usenames,dvipsnames]{color}\n") +
			string("\\usepackage[bookmarksdepth=3]{hyperref}\n") +
			string("\\usepackage{indentfirst}\n") +
			string("\\usepackage{listings}\n\n") +
			string("\\setlength{\\parskip}{0.25em}\n") +
			string("\\hypersetup{colorlinks=true,urlcolor=blue,linkcolor=black,pdfborder={0 0 0}}\n") +
			string("\\lstset{basicstyle=\\footnotesize\\ttfamily,numbers=left,numberstyle=\\scriptsize,numbersep=7pt,breaklines=true,breakatwhitespace=true,tabsize=4,backgroundcolor=\\color[rgb]{0.95,0.95,0.95}}\n\n") +
			string("\\title{" + latexTitle + "}\n") +
			string("\\author{\\href{https://github.com/RoliSoft/Host-Scanner}{Host Scanner}}\n\n") +
			string("\\begin{document}\n\n") +
			string("\\maketitle\n\n") +
			string("\\begin{abstract}\n") +
			string("	" + latexAbstract + "\n") +
			string("\\end{abstract}\n\n") +
			string("\\setcounter{tocdepth}{2}\n") +
			string("\\tableofcontents\n") +
			latexContent +
			string("\n\\end{document}");

		ofstream out(latexOut);

		if (out.good())
		{
			out << latexContent;
			out.close();

			log(MSG, "LaTeX report saved to file '" + latexOut + "'.");
		}
		else
		{
			log(ERR, "Failed to save LaTeX report to file '" + latexOut + "'.");
		}
	}

cleanup:

	delete scanner;
	delete hosts;
	delete ports;
	delete udports;
	
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
			"  censys   - Uses data from Censys. (passive; requires API key)\n"
			"  looquer  - Uses data from Mr Looquer. (passive; requires API key)\n"
			"  shosys   - Uses data from Shodan, Censys and Mr Looquer. (passive)")
		("shodan-key", po::value<string>(),
			"Specifies an API key for Shodan.")
		("shodan-uri", po::value<string>(),
			"Overrides the API endpoint used for Shodan. You may specify an URI starting with "
			"file:// pointing to a directory containing previously downloaded JSON responses.\n"
			"  Default: https://api.shodan.io/shodan")
		("censys-key", po::value<string>(),
			"Specifies an API key for Censys in the `uid:secret` format.")
		("censys-uri", po::value<string>(),
			"Overrides the API endpoint used for Censys. You may specify an URI starting with "
			"file:// pointing to a directory containing previously downloaded JSON responses.\n"
			"  Default: https://censys.io/api/v1")
		("looquer-key", po::value<string>(),
			"Specifies an API key for Mr Looquer.")
		("looquer-uri", po::value<string>(),
			"Overrides the API endpoint used for Mr Looquer. You may specify an URI starting with "
			"file:// pointing to a directory containing previously downloaded JSON responses.\n"
			"  Default: https://mrlooquer.com/api/v1")
		("input-file,f", po::value<string>(),
			"Process an input file with the selected scanner.\n"
			"  E.g. the nmap scanner can parse XML reports.")
		("delay,d", po::value<int>(),
			"Delay between packets sent to the same host. Default is 3 for 100ms. "
			"Possible values are 0..6, which have the same effect as nmap's -T:\n"
			"  0 - 5m, 1 - 15s, 2 - 400ms, 3 - 100ms, 4 - 10ms, 5 - 5ms, 6 - no delay")
		("resolve,r",
			"Resolves vulnerable CPE names to their actual package names depending "
			"on the automatically detected operating system of the host.")
		("output-latex,o", po::value<string>(),
			"Exports the scan results into a LaTeX file, with all the available information gathered during the scan.")
		("passive,x",
			"Globally disables active reconnaissance. Functionality using active "
			"scanning will break, but ensures no accidental active scans will be "
			"initiated, which might get construed as hostile.")
		("logging,l", po::value<string>(),
			"Logging level to use:\n"
			"  i, int - All messages.\n"
			"  d, dbg - All debug messages and up.\n"
			"  v, vrb - Enable verbosity, but don't overdo it.\n"
			"  m, msg - Print only regular messages. (default)\n"
			"  e, err - Print only error messages to stderr.")
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

	if (vm.count("logging") != 0)
	{
		auto logging = vm["logging"].as<string>();
		trim(logging);
		to_lower(logging);

		if (logging == "i" || logging == "int")
		{
			logging_level = INT;
		}
		else if (logging == "d" || logging == "dbg")
		{
			logging_level = DBG;
		}
		else if (logging == "v" || logging == "vrb")
		{
			logging_level = VRB;
		}
		else if (logging == "m" || logging == "msg")
		{
			logging_level = MSG;
		}
		else if (logging == "e" || logging == "err")
		{
			logging_level = ERR;
		}
	}

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

	if ((vm.count("target") != 0 || vm.count("input-file") != 0) && !(vm.count("version") != 0 || vm.count("help") != 0))
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
