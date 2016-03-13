#include "ShodanScanner.h"
#include "Utils.h"
#include <tuple>
#include <iostream>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/exception/diagnostic_information.hpp>

using namespace std;
using namespace boost;

void ShodanScanner::Scan(Host* host)
{
	getHostInfo(host);
}

void ShodanScanner::Scan(Hosts* hosts)
{
	for (auto host : *hosts)
	{
		getHostInfo(host);
	}
}

void ShodanScanner::getHostInfo(Host* host)
{
	using property_tree::write_json;
	using property_tree::ptree;

	auto json = getURL("https://" + endpoint + "/host/" + host->address + "?key=" + key);

	if (get<2>(json) != 200)
	{
		if (get<2>(json) == -1)
		{
			log(ERR, "Failed to send HTTP request: " + get<1>(json));
		}
		else
		{
			log(ERR, "Failed to get JSON reply: HTTP response code was " + to_string(get<2>(json)) + ".");
		}

		return;
	}

	// parse the JSON response from Shodan

	istringstream jstr(get<0>(json));
	ptree pt;

	try
	{
		read_json(jstr, pt);
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

		log(ERR, "Failed to parse JSON response: " + reason);

		return;
	}

	try
	{
		// enumerate ports

		for (auto& ptrun : pt.get_child("data"))
		{
			// get basic info of port

			auto jproto = ptrun.second.get<string>("transport", "");
			auto jport  = ptrun.second.get<string>("port", "");

			if (jproto.length() == 0)
			{
				continue;
			}

			unsigned short port = static_cast<unsigned short>(atoi(jport.c_str()));
			IPPROTO proto = IPPROTO_NONE;

			if (jproto == string("tcp"))
			{
				proto = IPPROTO_TCP;
			}
			else if (jproto == string("udp"))
			{
				proto = IPPROTO_UDP;
			}

			auto service = new Service(host->address, port, proto);
			host->services->push_back(service);

			service->alive  = host->alive  = true;
			service->reason = host->reason = AR_ReplyReceived;

			// get service banner, if any

			auto jdata = ptrun.second.get<string>("data", "");
			
			if (jdata.length() != 0)
			{
				service->banner = jdata;
			}

			// get HTML body, if any

			auto jhtml = ptrun.second.get<string>("html", "");

			if (jhtml.length() != 0)
			{
				service->banner += jhtml;
			}

			// get CPEs, if any

			auto jcpes = ptrun.second.get_child_optional("cpe");

			if (jcpes.is_initialized() && jcpes->size() != 0)
			{
				for (auto& jcpe : *jcpes)
				{
					auto cpe = jcpe.second.get_value<string>();

					if (cpe.length() != 0)
					{
						service->cpe.push_back(cpe);
					}
				}
			}

			// save extended port data

			stringstream ss;
			write_json(ss, ptrun.second, false);
			service->data = reinterpret_cast<void*>(new string(ss.str()));
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

		log(ERR, "Failed to process JSON response: " + reason);

		return;
	}
}

ShodanScanner::~ShodanScanner()
{
}
