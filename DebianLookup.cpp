#include "DebianLookup.h"
#include "DebianIdentifier.h"
#include "Utils.h"
#include <string>
#include <sstream>
#include <boost/regex.hpp>
#include <boost/core/ignore_unused.hpp>

using namespace std;
using namespace boost;

unordered_map<string, string> DebianLookup::FindVulnerability(const string& cve, OpSys distrib, double ver)
{
	unordered_map<string, string> vuln;

	if (!ValidateCVE(cve))
	{
		log(ERR, "Specified CVE identifier '" + cve + "' is not syntactically valid.");
		return vuln;
	}

	if (distrib != Debian)
	{
		log(ERR, "Specified distribution is not supported by this instance.");
		return vuln;
	}

	auto resp = getURL("https://security-tracker.debian.org/tracker/" + cve);

	if (get<2>(resp) != 200)
	{
		if (get<2>(resp) == -1)
		{
			log(ERR, "Failed to send HTTP request: " + get<1>(resp));
		}
		else
		{
			log(ERR, "Failed to get reply: HTTP response code was " + to_string(get<2>(resp)) + ".");
		}

		return vuln;
	}

	auto html = get<0>(resp);

	// pkg -> name of the package
	// dist -> distribution (stable, unstable, etc)
	// ver -> version which fixes the vulnerability
	static regex tblrgx("href=\"\\/tracker\\/source-package\\/[^\"]+\">(?<pkg>[^<]+)<\\/a><\\/td><td>[^<]*<\\/td><td>\\(?(?<dist>[^<\\)]+)\\)?<\\/td><td>(?:\\d:)?(?<ver>[^<]+)<\\/td>", regex::icase);

	sregex_iterator srit(html.begin(), html.end(), tblrgx);
	sregex_iterator end;

	string pkgfx;

	for (; srit != end; ++srit)
	{
		auto m = *srit;

		auto pkg  = m["pkg"].str();
		auto dist = m["dist"].str();
		auto vers = m["ver"].str();

		auto dver = DebianIdentifier::VersionNames.find(dist);

		if (ver == 0 || (dver != DebianIdentifier::VersionNames.end() && (*dver).second == ver))
		{
			vuln.emplace(pkg, vers);
		}

		pkgfx = pkg;
	}

	if (!pkgfx.empty() && vuln.empty())
	{
		// vulnerability is known, but no resolution for distribution

		vuln.emplace(pkgfx, "");
	}

	return vuln;
}

vector<pair<string, long>> DebianLookup::GetChangelog(const string& pkg, OpSys distrib, double ver)
{
	vector<pair<string, long>> updates;

	if (distrib != Debian)
	{
		log(ERR, "Specified distribution is not supported by this instance.");
		return updates;
	}

	string dver = "stable";

	if (ver != 0)
	{
		for (auto& name : DebianIdentifier::VersionNames)
		{
			if (name.second == ver)
			{
				dver = name.first;
				break;
			}
		}
	}

	auto dpkg = pkg;

	if (dpkg == "openssh")
	{
		dpkg = "openssh-server";
	}

	auto resp = getURL("https://packages.debian.org/" + dver + "/" + dpkg);

	if (get<2>(resp) != 200)
	{
		if (get<2>(resp) == -1)
		{
			log(ERR, "Failed to send HTTP request: " + get<1>(resp));
		}
		else
		{
			log(ERR, "Failed to get reply: HTTP response code was " + to_string(get<2>(resp)) + ".");
		}

		return updates;
	}

	// url -> location of the latest package changelog
	static regex chlrgx("href=\"(?<url>[^\"]*_changelog)\">Debian Changelog<\\/a>", regex::icase);

	smatch chlurl;

	if (!regex_search(get<0>(resp), chlurl, chlrgx))
	{
		log(ERR, "Failed get changelog location for the package " + dpkg + ".");
		return updates;
	}

	resp = getURL(chlurl["url"].str());

	if (get<2>(resp) != 200)
	{
		if (get<2>(resp) == -1)
		{
			log(ERR, "Failed to send HTTP request: " + get<1>(resp));
		}
		else
		{
			log(ERR, "Failed to get reply: HTTP response code was " + to_string(get<2>(resp)) + ".");
		}

		return updates;
	}

	// pkg -> name of the package
	// ver -> version number of the package
	static regex verrgx("^(?<pkg>[a-z0-9\\-\\._]+)\\s+\\((?:\\d:)?(?<ver>[^\\)]+)\\)", regex::icase);

	// date -> publication date of the package
	static regex datrgx("^ -- .*?(?<date>(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),\\s+\\d+.+)", regex::icase);

	string pver;
	istringstream iss(get<0>(resp));

	for (string line; getline(iss, line); )
	{
		smatch verm, datm;

		if (regex_search(line, verm, verrgx))
		{
			pver = verm["ver"].str();
		}
		else if (regex_search(line, datm, datrgx) && !pver.empty())
		{
			updates.push_back(make_pair(pver, dateToUnix(datm["date"].str())));
		}
	}

	return updates;
}

string DebianLookup::GetUpgradeCommand(const unordered_set<string>& pkgs, OpSys distrib, double ver)
{
	ignore_unused(distrib);
	ignore_unused(ver);

	if (pkgs.empty())
	{
		return "";
	}

	string cmd = "sudo apt-get install --only-upgrade";

	for (auto& pkg : pkgs)
	{
		cmd += " " + pkg;
	}

	return cmd;
}

DebianLookup::~DebianLookup()
{
}
