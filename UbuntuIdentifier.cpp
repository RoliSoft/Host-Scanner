#include "UbuntuIdentifier.h"
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/optional.hpp>
#include <boost/regex.hpp>

using namespace std;
using namespace boost;

// https://wiki.ubuntu.com/Releases
const unordered_map<string, double> UbuntuIdentifier::VersionNames = unordered_map<string, double> {
	{ "xenial",   16.04 }, // lts
	{ "wily",     15.10 },
	{ "vivid",    15.04 },
	{ "utpic",    14.10 },
	{ "trusty",   14.04 }, // lts
	{ "saucy",    13.10 },
	{ "raring",   13.04 },
	{ "quantal",  12.10 },
	{ "precise",  12.04 }, // lts
	{ "oneiric",  11.10 },
	{ "natty",    11.04 },
	{ "maverick", 10.10 },
	{ "lucid",    10.04 }, // lts
	{ "karmik",   9.10 },
	{ "jaunty",   9.04 },
	{ "intrepid", 8.10 },
	{ "hardy",    8.04 }, // lts
	{ "dapper",   6.06 }, // lts
};

// compiled by browsing changelogs at https://launchpad.net/ubuntu/+source/openssh
const unordered_map<string, double> UbuntuIdentifier::BundledVersions = unordered_map<string, double> {
	{ "7.2p2",   16.04 },
	{ "6.9p1",   15.10 },
	{ "6.7p1",   15.04 },
	{ "6.6p1",   14.10 },
	{ "6.6.1p1", 14.04 }, // .4
	{ "5.9p1",   14.04 },
	{ "5.3p1",   10.04 },
	{ "4.7p1",   8.04 },
	{ "4.2p1",   6.06 },
};

const unordered_set<double> UbuntuIdentifier::LtsVersions = unordered_set<double>{
	16.04, 14.04, 12.04, 10.04, 8.04, 6.06
};

bool UbuntuIdentifier::Scan(Host* host)
{
	auto isDeb = false;
	string sshVer;
	optional<double> debVer, secUpd;

	// check if any SSH services are available

	// ver -> OpenSSH version
	// deb -> "Debian/Ubuntu" tag, if not present, below groups will not match
	// ver2 -> patch number
	// tag -> "ubuntu" tag in the version number
	// debsec -> if tag also matched, the installed security patch
	// tag2 -> "ubuntu" tag when the verbosity is turned off
	static regex sshbnr("OpenSSH_(?<ver>[^\\s$]+)(?:\\s*(?:Debian|Ubuntu)\\-(?<ver2>\\d+)(?<tag>ubuntu)(?<debsec>\\d+(?:\\.\\d+)?)|\\s*(?<tag2>Ubuntu))?", regex::icase);
	
	// match any "ubuntu" tag
	static regex debtag("\\bubuntu\\b", regex::icase);

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

		// if the service is not SSH, just check if there is an "Ubuntu" tag in it anywhere

		if (!starts_with(service->banner, "SSH-2.0-OpenSSH_"))
		{
			if (regex_search(service->banner, sm, debtag))
			{
				isDeb = true;
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

		// if there is an "Ubuntu" tag in the banner, this host runs Ubuntu for sure
		
		if (sm["tag"].matched || sm["tag2"].matched)
		{
			isDeb = true;
		}

		// check if security version is present

		if (sm["debsec"].matched)
		{
			secUpd = stod(sm["debsec"].str());
		}

		// try to deduce Ubuntu distribution based on the OpenSSH version

		if (!sshVer.empty() && !debVer.is_initialized())
		{
			auto ver = sshVer;

			trim(ver);
			to_lower(ver);

			auto bver = BundledVersions.find(ver);

			if (bver != BundledVersions.end())
			{
				debVer = (*bver).second;
			}
		}
	}

	// save information
	
	if (isDeb)
	{
		string cpe = "o:canonical:ubuntu_linux";

		host->opSys = OpSys::Ubuntu;
		
		if (debVer.is_initialized())
		{
			cpe += ":" + to_string(debVer.get());

			host->osVer = debVer.get();

			if (LtsVersions.find(debVer.get()) != LtsVersions.end())
			{
				cpe += "-:lts";
			}
		}

		host->cpe.push_back(cpe);
	}

	return isDeb;
}

UbuntuIdentifier::~UbuntuIdentifier()
{
}
