#include "LooquerScanner.h"
#include "Utils.h"
#include <tuple>
#include <iostream>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/exception/diagnostic_information.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/filesystem.hpp>

using namespace std;
using namespace boost;

namespace fs = boost::filesystem;

LooquerScanner::LooquerScanner(const string& key)
	: key(key)
{
}

void LooquerScanner::SetKey(const string& key)
{
	this->key = key;
}

bool LooquerScanner::HasKey()
{
	return !key.empty();
}

void LooquerScanner::SetEndpoint(const string& uri)
{
	endpoint = uri;
}

bool LooquerScanner::IsPassive()
{
	return true;
}

void LooquerScanner::Scan(Host* host)
{
	getHostInfo(host);
}

void LooquerScanner::Scan(Hosts* hosts)
{
	for (auto host : *hosts)
	{
		getHostInfo(host);
	}
}

void LooquerScanner::getHostInfo(Host* host)
{
	using property_tree::write_json;
	using property_tree::ptree;

	if (key.length() == 0)
	{
		return;
	}

	string json;

	if (starts_with(endpoint, "file://"))
	{
		auto path = fs::path(endpoint.substr(7)) / fs::path(host->address);

		log(VRB, "Reading " + path.string() + "...");

		ifstream fs(path.string());

		if (!fs.good())
		{
			log(ERR, "Failed to open JSON file for reading: " + path.string());
			return;
		}

		stringstream buf;
		buf << fs.rdbuf();

		json = buf.str();
	}
	else
	{
		auto url = endpoint + "/search?token=" + key + "&q=ip" + (host->address.find(':') == string::npos ? "v4" : "") + ":%22" + host->address + "%22";

		log(VRB, "Downloading " + url + "...");

		auto req = getURL(url);

		if (get<2>(req) != 200)
		{
			if (get<2>(req) == -1)
			{
				log(ERR, "Failed to send HTTP request to Mr Looquer for " + host->address + ": " + get<1>(req));
			}
			else
			{
				log(ERR, "Failed to get JSON reply from Mr Looquer for " + host->address + ": HTTP response code was " + to_string(get<2>(req)) + ".");
			}

			return;
		}

		json = get<0>(req);
	}

	// parse the JSON response from Looquer

	istringstream jstr(json);
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
		// enumerate results

		for (auto& ptrun : pt.get_child("hits"))
		{
			// get basic info of port

			auto jproto = ptrun.second.get<string>("protocol", "");
			auto jport  = ptrun.second.get<string>("port", "");

			if (jproto.length() == 0)
			{
				continue;
			}

			unsigned short port = static_cast<unsigned short>(stoi(jport));
			IPPROTO proto = IPPROTO_NONE;

			if (jproto == string("tcp"))
			{
				proto = IPPROTO_TCP;
			}
			else if (jproto == string("udp"))
			{
				proto = IPPROTO_UDP;
			}

			// see if service already exists

			Service* service = nullptr;

			for (auto& serv : *host->services)
			{
				if (serv->port == port && serv->protocol == proto)
				{
					service = serv;
					break;
				}
			}

			if (service == nullptr)
			{
				service = new Service(host->address, port, proto);
				host->services->push_back(service);

				service->alive = host->alive = true;
				service->reason = host->reason = AR_ReplyReceived;
			}

			// get service banner, if any

			auto jdata = ptrun.second.get<string>("banner", "");

			if (jdata.length() != 0 && service->banner.length() < jdata.length())
			{
				service->banner = jdata;
			}

			// get CPEs, if any

			auto jcpe = ptrun.second.get<string>("cpe", "");

			if (jcpe.length() != 0)
			{
				service->cpe.push_back(jcpe.substr(5));
			}

			// save extended port data

			if (service->data == nullptr)
			{
				stringstream ss;
				write_json(ss, ptrun.second, false);
				service->data = reinterpret_cast<void*>(new string(ss.str()));
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

		log(ERR, "Failed to process JSON response: " + reason);

		return;
	}
}

LooquerScanner::~LooquerScanner()
{
}
