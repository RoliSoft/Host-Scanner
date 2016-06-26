#include "DebianIdentifier.h"
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/optional.hpp>
#include <boost/regex.hpp>

using namespace std;
using namespace boost;

// https://www.debian.org/releases/
const unordered_map<string, int> DebianIdentifier::VersionNames = unordered_map<string, int> {
	{ "buster",  10 },
	{ "stretch", 9 },
	{ "jessie",  8 },
	{ "wheezy",  7 },
	{ "squeeze", 6 },
	{ "lenny",   5 },
	{ "etch",    4 },
	{ "sarge",   3 }, // technically 3.1
	{ "woody",   3 },
};

// compiled by browsing changelogs at https://packages.debian.org/ and https://archive.debian.net/
const unordered_map<string, int> DebianIdentifier::BundledVersions = unordered_map<string, int> {
	{ "7.2p2",   9 },
	{ "6.7p1",   8 },
	{ "6.6p1",   7 }, // backport
	{ "6.1p1",   7 }, // backport
	{ "6.0p1",   7 },
	{ "5.5p1",   6 },
	{ "5.1p1",   5 },
	{ "4.3p2",   4 },
	{ "3.8.1p1", 3 }, // technically 3.1
	{ "3.4p1",   3 },
};

bool DebianIdentifier::Scan(Host* host)
{
	auto isDeb = false;
	string sshVer;
	optional<int> debVer, secUpd;

	// check if any SSH services are available

	// ver -> OpenSSH version
	// deb -> "Debian" tag, if not present, below groups will not match
	// ver2 -> patch number
	// debrel -> name of the Debian version, mostly for 'squeeze' and older
	// debver -> version number of Debian, mostly for 'wheezy' and newer
	// debsec -> if debver also matched, the installed security patch
	static regex sshbnr("OpenSSH_(?<ver>[^\\s$]+)(?:\\s*(?<deb>Debian)\\-(?<ver2>\\d+)(?:[\\.\\+~](?:(?<debrel>buster|stretch|jessie|wheezy|squeeze|lenny|etch|sarge|woody)|deb(?<debver>\\d+)u?(?<debsec>\\d+)?))?)?", regex::icase);
	
	// match any "debian" tag
	static regex debtag("\\bdebian\\b", regex::icase);

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

		// if the service is not SSH, just check if there is a "Debian" tag in it anywhere

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

		// if there is a "Debian" tag in the banner, this host runs Debian for sure
		
		if (sm["deb"].matched)
		{
			isDeb = true;
		}

		// check if release name is present
		
		if (sm["debrel"].matched)
		{
			auto rel = sm["debrel"].str();

			trim(rel);
			to_lower(rel);

			auto rnum = VersionNames.find(rel);

			if (rnum != VersionNames.end())
			{
				debVer = (*rnum).second;
			}
		}

		// check if release version is present

		if (sm["debver"].matched)
		{
			debVer = stoi(sm["debver"].str());

			if (sm["debsec"].matched)
			{
				secUpd = stoi(sm["debsec"].str());
			}
		}

		// try to deduce Debian distribution based on the OpenSSH version

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
		string cpe = "o:debian:debian_linux";

		host->opSys = OpSys::Debian;

		if (debVer.is_initialized())
		{
			cpe += ":" + to_string(debVer.get());

			host->osVer = debVer.get();
		}

		host->cpe.push_back(cpe);
	}

	return isDeb;
}

DebianIdentifier::~DebianIdentifier()
{
}
