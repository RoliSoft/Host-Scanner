#include "EnterpriseLinuxIdentifier.h"
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/optional.hpp>
#include <boost/regex.hpp>

using namespace std;
using namespace boost;

// compiled from various sources, may be incomplete
const unordered_map<string, int> EnterpriseLinuxIdentifier::BundledVersions = unordered_map<string, int> {
	{ "6.6.1p1", 7 },
	{ "6.6p1",   6 },
	{ "5.3",     6 },
	{ "5.2p1",   6 },
	{ "4.3",     5 },
	{ "3.9",     4 },
};

bool EnterpriseLinuxIdentifier::Scan(Host* host)
{
	auto isEL = false, isCO = false;
	string sshVer;
	optional<int> elVer, secUpd;

	// check if any SSH services are available

	// ver -> OpenSSH version
	// tag -> any EL tag, if not present, below groups will not match
	// elver -> version number of RHEL/CentOS
	// secver -> if elver also matched, the installed security patch
	static regex sshbnr("OpenSSH_(?<ver>[^\\s\\-_$]+)(?:[\\s\\-_](?<tag>CentOS|RHEL|Red.?Hat)[\\s\\-_]?(?<elver>\\d+)(?:.*\\-(?<secver>\\d+)))?", regex::icase);
	
	// match any EL tag
	static regex enttag("\\b(centos|red.?hat|rhel)\\b", regex::icase);

	// replace "7.2p1" to "7.2:p1" in the CPE
	static regex cpever("(\\d)p(\\d+)", regex::icase);
	static string cpepatch = "\\1:p\\2";

	for (auto service : *host->services)
	{
		if (service->banner.empty())
		{
			continue;
		}

		smatch sm;

		// if the service is not SSH, just check if there is an EL tag in it anywhere

		if (!starts_with(service->banner, "SSH-2.0-OpenSSH_"))
		{
			if (regex_search(service->banner, sm, enttag))
			{
				isEL = true;

				auto c = sm[1].str()[0];
				  isCO = c == 'C' || c == 'c';
			}

			continue;
		}

		// if the service is SSH, special handling follows

		if (!regex_search(service->banner, sm, sshbnr))
		{
			continue;
		}

		// while we're at it, append the CPE name

		sshVer = sm["ver"].str();

		service->cpe.push_back("a:openbsd:openssh:" + regex_replace(sshVer, cpever, cpepatch));

		// if there is an EL tag in the banner, this host runs EL for sure
		
		if (sm["tag"].matched)
		{
			isEL = true;
			
			auto c = sm["tag"].str()[0];
			  isCO = c == 'C' || c == 'c';
		}

		// check if release version is present

		if (sm["elver"].matched)
		{
			elVer = stoi(sm["elver"].str());

			if (sm["secver"].matched)
			{
				secUpd = stoi(sm["secver"].str());
			}
		}
	}

	// if we are certain the host is running EL, we have OpenSSH version,
	// but no EL distribution version, try to deduce it
	
	if (isEL && !sshVer.empty() && !elVer.is_initialized())
	{
		auto ver = sshVer;

		trim(ver);
		to_lower(ver);

		auto bver = BundledVersions.find(ver);

		if (bver != BundledVersions.end())
		{
			elVer = (*bver).second;
		}
	}

	// save information

	if (isEL)
	{
		auto cpe = "o:" + string(isCO ? "centos:centos" : "redhat:enterprise_linux");

		host->opSys = OpSys::EnterpriseLinux;

		if (elVer.is_initialized())
		{
			cpe += ":" + to_string(elVer.get());

			host->osVer = elVer.get();
		}

		host->cpe.push_back(cpe);
	}

	return isEL;
}

EnterpriseLinuxIdentifier::~EnterpriseLinuxIdentifier()
{
}
