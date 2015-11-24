#include "censysscanner.h"
#include "utils.h"
#include <tuple>
#include <curl/curl.h>

using namespace std;

void CensysScanner::Scan(Service* service)
{
	getHostInfo(service);
}

void CensysScanner::Scan(Services* services)
{
	for (auto service : *services)
	{
		getHostInfo(service);
	}
}

void CensysScanner::getHostInfo(Service* service)
{
	auto json = getURL("https://" + endpoint + "/view/ipv4/" + service->address, [this](CURL* curl)
		{
			curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
			curl_easy_setopt(curl, CURLOPT_USERPWD, (get<0>(auth) + ":" + get<1>(auth)).c_str());
		});

	// TODO parse JSON
}

CensysScanner::~CensysScanner()
{
}
