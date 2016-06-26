#include "NmapScanner.h"
#include "Utils.h"
#include "ServiceScanner.h"
#include <iostream>
#include <string>
#include <set>
#include <functional>
#include <boost/foreach.hpp>
#include <boost/property_tree/xml_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/exception/diagnostic_information.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/regex.hpp>

using namespace std;
using namespace boost;

bool NmapScanner::GetOption(int option, void* value)
{
	switch (option)
	{
	case OPT_DELAY:
		*reinterpret_cast<int*>(value) = delay;
		return true;

	default:
		return false;
	}
}

bool NmapScanner::SetOption(int option, void* value)
{
	switch (option)
	{
	case OPT_DELAY:
		delay = *reinterpret_cast<int*>(value);
		return true;

	default:
		return false;
	}
}

bool NmapScanner::IsPassive()
{
	return false;
}

void NmapScanner::Scan(Host* host)
{
	Hosts hosts = { host };
	Scan(&hosts);
}

void NmapScanner::Scan(Hosts* hosts)
{
	// separate IPv4 and IPv6, since Nmap supports them, but can't dual-stack

	Hosts hostv4, hostv6;

	for (auto& host : *hosts)
	{
		struct addrinfo hint, *info = nullptr;
		memset(&hint, 0, sizeof(struct addrinfo));
		hint.ai_family = AF_UNSPEC; // allow both v4 and v6
		hint.ai_flags = AI_NUMERICHOST; // disable DNS lookups

		getaddrinfo(host->address.c_str(), 0, &hint, &info);

		switch (info->ai_family)
		{
		case AF_INET:
			hostv4.push_back(host);
			break;

		case AF_INET6:
			hostv6.push_back(host);
			break;

		default:
			break;
		}

		freeaddrinfo(info);
	}

	// run the separated tests

	if (hostv4.size() != 0)
	{
		auto xml = runNmap(&hostv4);
		parseXml(xml, &hostv4);
	}

	if (hostv6.size() != 0)
	{
		auto xml = runNmap(&hostv6, true);
		parseXml(xml, &hostv6);
	}
}

Hosts* NmapScanner::Process(const string& xml)
{
	auto hosts = new Hosts();

	parseXml(xml, hosts, true);

	return hosts;
}

string NmapScanner::GetVersion()
{
	auto ret = execute("nmap -V");

	smatch sm;
	regex rgx("nmap version (\\d.*?) \\(", regex::icase);

	if (regex_search(ret, sm, rgx))
	{
		return sm[1].str();
	}

	return "";
}

string NmapScanner::runNmap(Hosts* hosts, bool v6)
{
	// -oX -	XML output to standard output
	// -Pn		Don't probe, assume host is alive
	// -sU		Scan UDP, when specified in port list
	// -sS		Scan TCP with SYN method, when requested
	// -sV		Run service detection function [disabled]
	// -sc..er	Run service banner grabber NSE script
	// -sc..rs  Run the HTTP header grabber NSE script
	// -6		Turn on IPv6 support, if v6 parameter is set
	// -p		Port list to scan
	string cmd = "nmap -oX - -Pn -sU -sS --script=banner --script=http-headers";

	if (v6)
	{
		cmd += " -6";
	}

	if (delay != 3)
	{
		cmd += " -T" + to_string(min(max(0, delay), 5));
	}

	string ports = " -p ";
	string adrls = "";

	// collect all ports and hosts to be scanned

	set<unsigned short> tcps, udps;
	set<string> addrs;

	for (auto& host : *hosts)
	{
		for (auto& service : *host->services)
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
				log(ERR, "Unsupported protocol through nmap: " + to_string(service->protocol));
				break;
			}

			addrs.emplace(service->address);
		}
	}

	// write collection to command

	for (auto& addr : addrs)
	{
		adrls += addr + " ";
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

	cmd += ports + " " + adrls;

	log(VRB, "Executing " + cmd);

	// silence errors as they interrupt the XML output, and
	// the XML output will contain the error message anyways

#if Windows
	cmd += "2>nul";
#elif Unix
	cmd += "2>/dev/null";
#endif

	// execute the command

	auto xml = execute(cmd.c_str());

	log(VRB, "Execution finished, got XML output of " + pluralize(xml.size(), "byte") + ".");

	return xml;
}

void NmapScanner::parseXml(const string& xml, Hosts* hosts, bool append)
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
		string reason;

		auto exst = dynamic_cast<const std::exception*>(&ex);
		if (NULL != exst)
		{
			reason = exst->what();
		}
		else
		{
			reason = diagnostic_information(ex);
		}

		log(ERR, "Failed to parse XML output: " + reason);

		return;
	}

	try
	{
		// check if the execution was successful

		string exit = pt.get<string>("nmaprun.runstats.finished.<xmlattr>.exit", "");
		string emsg = pt.get<string>("nmaprun.runstats.finished.<xmlattr>.errormsg", "");

		if (exit == "error")
		{
			log(ERR, "Nmap execution failed: " + emsg);
			return;
		}

		// allocate fields to parse for

		string address, banner;
		int port;
		IPPROTO proto;
		bool open;
		AliveReason reason;
		vector<string> cpes;

		// enumerate hosts

		for (auto& ptrun : pt.get_child("nmaprun"))
		{
			if (ptrun.first.data() != string("host"))
			{
				continue;
			}

			// clear fields from previous host

			address.clear();

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

						proto  = IPPROTO_TCP;
						open   = false;
						reason = AR_NotScanned;
						banner.clear();
						cpes.clear();

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
								auto id = ptport.second.get<string>("<xmlattr>.id", "");

								// check the banner script

								if (id == string("banner"))
								{
									banner = ptport.second.get<string>("<xmlattr>.output", "") + "\r\n\r\n";
								}

								// reconstruct HTTP response if got http-headers

								else if (id == string("http-headers") && banner.empty())
								{
									banner = ptport.second.get<string>("<xmlattr>.output", "");
									banner = "HTTP/1.1 200 OK\r\n" + regex_replace(banner, regex("(^\\s*|\\(Request type:.*$)"), "") + "\r\n";
								}

								// reconstruct semi-fake HTTP response if got http-server-header

								else if (id == string("http-server-header") && banner.empty())
								{
									banner = "HTTP/1.1 200 OK\r\nServer: " + ptport.second.get<string>("<xmlattr>.output", "") + "\r\n\r\n";
								}
							}

							// extract any service information, if available, such as CPE names

							else if (ptport.first.data() == string("service"))
							{
								for (auto& ptserv : ptport.second)
								{
									if (ptserv.first.data() == string("cpe"))
									{
										auto cpe = ptserv.second.get<string>("");

										if (cpe.length() > 5)
										{
											cpes.push_back(cpe.substr(5));
										}
									}
								}
							}
						}

						// new port info available at this phase, store it if relevant

						if (append)
						{
							// a new service will be created for this extracted entry
							
							Host* host = nullptr;

							for (auto entry : *hosts)
							{
								if (entry->address == address)
								{
									host = entry;
									break;
								}
							}

							if (host == nullptr)
							{
								host = new Host(address);
								hosts->push_back(host);
							}

							auto service = new Service(address, static_cast<unsigned short>(port), proto);
							
							service->alive  = open;
							service->reason = reason;

							if (banner.length() != 0)
							{
								service->banner = banner;
							}

							if (cpes.size() != 0)
							{
								service->cpe.insert(service->cpe.end(), cpes.begin(), cpes.end());
							}

							if (!host->alive && service->alive)
							{
								host->alive  = open;
								host->reason = reason;
							}

							host->AddService(service);
						}
						else
						{
							// the host list will be searched, and if the service is found, its values modified

							for (auto host : *hosts)
							{
								for (auto service : *host->services)
								{
									if (service->address == address && service->port == port && service->protocol == proto)
									{
										service->alive  = open;
										service->reason = reason;

										if (banner.length() != 0)
										{
											service->banner = banner;
										}

										if (cpes.size() != 0)
										{
											service->cpe.insert(service->cpe.end(), cpes.begin(), cpes.end());
										}

										if (!host->alive && service->alive)
										{
											host->alive  = open;
											host->reason = reason;
										}

										break;
									}
								}
							}
						}
					}
				}
			}
		}
	}
	catch (boost::exception const& ex)
	{
		string reason;

		auto exst = dynamic_cast<const std::exception*>(&ex);
		if (NULL != exst)
		{
			reason = exst->what();
		}
		else
		{
			reason = diagnostic_information(ex);
		}

		log(ERR, "Failed to process XML output: " + reason);

		return;
	}
}

NmapScanner::~NmapScanner()
{
}
