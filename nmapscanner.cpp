#include "nmapscanner.h"
#include "utils.h"
#include <iostream>
#include <string>
#include <set>
#include <functional>
#include <boost/foreach.hpp>
#include <boost/property_tree/xml_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/exception/diagnostic_information.hpp>
#include <boost/lexical_cast.hpp>

using namespace std;
using namespace boost;

void NmapScanner::Scan(Service* service)
{
	Services services = { service };
	Scan(&services);
}

void NmapScanner::Scan(Services* services)
{
	// separate IPv4 and IPv6, since Nmap supports them, but can't dual-stack

	Services serv4, serv6;

	for (auto& service : *services)
	{
		struct addrinfo hint, *info = nullptr;
		memset(&hint, 0, sizeof(struct addrinfo));
		hint.ai_family = AF_UNSPEC; // allow both v4 and v6
		hint.ai_flags = AI_NUMERICHOST; // disable DNS lookups

		auto port = lexical_cast<string>(service->port);
		getaddrinfo(service->address, port.c_str(), &hint, &info);

		switch (info->ai_family)
		{
		case AF_INET:
			serv4.push_back(service);
			break;

		case AF_INET6:
			serv6.push_back(service);
			break;

		default:
			break;
		}

		freeaddrinfo(info);
	}

	// run the separated tests

	if (serv4.size() != 0)
	{
		auto xml = runNmap(&serv4);
		parseXml(xml, &serv4);
	}

	if (serv6.size() != 0)
	{
		auto xml = runNmap(&serv6, true);
		parseXml(xml, &serv6);
	}
}

string NmapScanner::runNmap(Services* services, bool v6)
{
	// -oX -	XML output to standard output
	// -Pn		Don't probe, assume host is alive
	// -sU		Scan UDP, when specified in port list
	// -sS		Scan TCP with SYN method, when requested
	// -sV		Run service detection function
	// -sc..er	Run service banner grabber NSE script
	// -6		Turn on IPv6 support, if v6 parameter is set
	// -p		Port list to scan
	string cmd = "nmap -oX - -Pn -sU -sS -sV --script=banner";

	if (v6)
	{
		cmd += " -6";
	}

	string ports = " -p ";
	string hosts = "";

	// collect all ports and hosts to be scanned

	set<unsigned short> tcps, udps;
	set<string> addrs;

	for (auto& service : *services)
	{
		switch (service->protocol)
		{
		case IPPROTO_TCP:
			tcps.emplace(service->port);
			break;
		case IPPROTO_UDP:
			udps.emplace(service->port);
			break;
		default:
			break;
		}

		addrs.emplace(service->address);
	}

	// write collection to command

	for (auto& addr : addrs)
	{
		hosts += addr + " ";
	}

	if (tcps.size() != 0)
	{
		ports += "T:";

		for (auto& tcp : tcps)
		{
			ports += to_string(tcp) + ",";
		}
	}

	if (udps.size() != 0)
	{
		ports += "U:";

		for (auto& udp : udps)
		{
			ports += to_string(udp) + ",";
		}
	}

	// concatenate the final command

	ports.pop_back(); // remove the last comma

	cmd += ports + " " + hosts;

	// silence errors as they interrupt the XML output, and
	// the XML output will contain the error message anyways

#if Windows
	cmd += "2>nul";
#elif Linux
	cmd += "2>/dev/null";
#endif

	// execute the command

	auto xml = execute(cmd.c_str());

	return xml;
}

void NmapScanner::parseXml(string xml, Services* services)
{
	using property_tree::ptree;

	// parse the XML output from Nmap

	istringstream xstr(xml);
	ptree pt;

	try
	{
		read_xml(xstr, pt);
	}
	catch (boost::exception const& ex)
	{
		cerr << "Failed to parse XML output: ";

		auto exst = dynamic_cast<const std::exception*>(&ex);
		if (NULL != exst)
		{
			cerr << exst->what() << endl;
		}
		else
		{
			cerr << diagnostic_information(ex);
		}

		return;
	}

	try
	{
		// check if the execution was successful

		string exit = pt.get<string>("nmaprun.runstats.finished.<xmlattr>.exit", "");
		string emsg = pt.get<string>("nmaprun.runstats.finished.<xmlattr>.errormsg", "");

		if (exit == "error")
		{
			cerr << "Nmap execution failed: " << emsg << endl;
			return;
		}

		// allocate fields to parse for

		string address, banner;
		int port;
		IPPROTO proto;
		bool open;
		AliveReason reason;

		// enumerate hosts

		for (auto& ptrun : pt.get_child("nmaprun"))
		{
			if (ptrun.first.data() != string("host"))
			{
				continue;
			}

			// clear fields from previous host

			address = "";

			// enumerate the attributes of this host

			for (auto& pthost : ptrun.second)
			{
				// read the address of the host

				if (pthost.first.data() == string("address"))
				{
					if (pthost.second.get<string>("<xmlattr>.addrtype", "") != string("mac"))
					{
						address = pthost.second.get<string>("<xmlattr>.addr", "");
					}
				}

				// enumerate the ports of this host

				if (pthost.first.data() == string("ports"))
				{
					for (auto& ptports : pthost.second)
					{
						if (ptports.first.data() != string("port"))
						{
							continue;
						}

						// clear fields from previous port

						port = 0;
						proto = IPPROTO_TCP;
						open = false;
						banner = "";
						reason = AR_NotScanned;

						// parse the attributes accessible from here

						port = ptports.second.get<int>("<xmlattr>.portid", 0);

						auto protox = ptports.second.get<string>("<xmlattr>.protocol", "tcp");
						if (protox == "tcp")
						{
							proto = IPPROTO_TCP;
						}
						else if (protox == "udp")
						{
							proto = IPPROTO_UDP;
						}

						// enumerate the children tags of this port

						for (auto& ptport : ptports.second)
						{
							// extract the state and convert it to AliveReason

							if (ptport.first.data() == string("state"))
							{
								open = ptport.second.get<string>("<xmlattr>.state", "") == string("open");
								string rsnx = ptport.second.get<string>("<xmlattr>.reason", "");

								if (rsnx == "reset" || rsnx == "port-unreach")
								{
									reason = AR_IcmpUnreachable;
								}
								else if (rsnx == "syn-ack" || rsnx == "udp-response")
								{
									reason = AR_ReplyReceived;
								}
								else
								{
									reason = AR_TimedOut;
								}
							}

							// extract the service banner, if the script returned with anything

							else if (ptport.first.data() == string("script"))
							{
								if (ptport.second.get<string>("<xmlattr>.id", "") == string("banner"))
								{
									banner = ptport.second.get<string>("<xmlattr>.output", "");
								}
							}
						}

						// new port info available at this phase, store it if relevant

						for (auto& service : *services)
						{
							if (service->address == address && service->port == port && service->protocol == proto)
							{
								service->alive = open;
								service->reason = reason;

								if (banner.length() != 0)
								{
									service->banlen = banner.length();
									service->banner = new char[service->banlen];

									memcpy(service->banner, banner.c_str(), service->banlen);
								}

								break;
							}
						}
					}
				}
			}
		}
	}
	catch (boost::exception const& ex)
	{
		cerr << "Failed to use XML output: ";

		auto exst = dynamic_cast<const std::exception*>(&ex);
		if (NULL != exst)
		{
			cerr << exst->what() << endl;
		}
		else
		{
			cerr << diagnostic_information(ex);
		}

		return;
	}
}

NmapScanner::~NmapScanner()
{
}
