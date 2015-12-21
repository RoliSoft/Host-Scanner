#include "CensysScanner.h"
#include "Utils.h"
#include <tuple>
#include <iostream>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/exception/diagnostic_information.hpp>

#if HAVE_CURL
	#include <curl/curl.h>
#endif

using namespace std;
using namespace boost;

void CensysScanner::Scan(Host* host)
{
	getHostInfo(host);
}

void CensysScanner::Scan(Hosts* hosts)
{
	for (auto host : *hosts)
	{
		getHostInfo(host);
	}
}

void CensysScanner::getHostInfo(Host* host)
{
	using property_tree::write_json;
	using property_tree::ptree;

	auto json = getURL("https://" + endpoint + "/view/ipv4/" + host->address
#if HAVE_CURL
		, [this](CURL* curl)
		{
			curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
			curl_easy_setopt(curl, CURLOPT_USERPWD, auth.c_str());
		}
#endif
	);

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

	// parse the JSON response from Censys

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

		for (auto& ptrun : pt)
		{
			unsigned short port = static_cast<unsigned short>(atoi(ptrun.first.data()));

			if (port == 0)
			{
				continue;
			}

			// create service for port

			auto service = new Service(host->address, port, IPPROTO_TCP);
			host->services->push_back(service);

			service->alive  = host->alive  = true;
			service->reason = host->reason = AR_ReplyReceived;

			// get service banner, if any

			auto jdata = findServiceBanner(ptrun.second);

			if (jdata.length() != 0)
			{
				service->banlen = jdata.length();
				service->banner = new char[jdata.length()];

				memcpy(service->banner, jdata.c_str(), jdata.length());
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

CensysScanner::~CensysScanner()
{
}

string CensysScanner::findServiceBanner(property_tree::ptree pt)
{
	try
	{
		for (auto& ptrun : pt)
		{
			auto key = ptrun.first.data();

			// for HTTP, recreate response from the various fields

			if (key == string("http"))
			{
				auto status = ptrun.second.get<string>("get.status_line");
				auto body   = ptrun.second.get<string>("get.body");

				string headers;
				for (auto& pthead : ptrun.second.get_child("get.headers"))
				{
					headers += pthead.first.data() + string(": ") + pthead.second.data() + "\r\n";
				}

				if (status.length() != 0 || body.length() != 0)
				{
					return status + "\r\n" + headers + "\r\n" + body;
				}
			}

			// otherwise, recursively try to find any fields containing service banners

			if (key == string("banner") || key == string("raw_banner") || key == string("ehlo") || key == string("body"))
			{
				auto res = ptrun.second.get_value<string>();

				if (res.length() != 0)
				{
					return res;
				}
			}

			auto res = findServiceBanner(ptrun.second);

			if (res.length() != 0)
			{
				return res;
			}
		}
	}
	catch (boost::exception const&)
	{
	}

	return "";
}
