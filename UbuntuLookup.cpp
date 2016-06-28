#include "UbuntuLookup.h"
#include "UbuntuIdentifier.h"
#include "Utils.h"
#include <string>
#include <sstream>
#include <boost/regex.hpp>
#include <boost/core/ignore_unused.hpp>

using namespace std;
using namespace boost;

unordered_map<string, string> UbuntuLookup::FindVulnerability(const string& cve, OpSys distrib, double ver)
{
	unordered_map<string, string> vuln;

	if (!ValidateCVE(cve))
	{
		log(ERR, "Specified CVE identifier '" + cve + "' is not syntactically valid.");
		return vuln;
	}

	if (distrib != Ubuntu)
	{
		log(ERR, "Specified distribution is not supported by this instance.");
		return vuln;
	}

	auto resp = getURL("https://people.canonical.com/~ubuntu-security/cve/" + cve.substr(4, 4) + "/" + cve + ".html");

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
	// dist -> distribution (xenial, trusty, etc)
	// status -> vulnerability status (safe, vuln)
	// ver -> if fixed, version which fixes the vulnerability
	static regex tblrgx("href=\"[^l]+launchpad\\.net\\/ubuntu\\/(?<dist>[^\\/]+)\\/[^\\/]+\\/(?<pkg>[^\"]+)\">[^<]+<\\/a>[^<]*<\\/td><td><span class=\"(?<status>[^\"]+)\">[^<]+<\\/span>(?:\\s*\\((?:\\d:)?(?<ver>[^\\)]+))?", regex::icase);

	sregex_iterator srit(html.begin(), html.end(), tblrgx);
	sregex_iterator end;

	for (; srit != end; ++srit)
	{
		auto m = *srit;

		auto pkg  = m["pkg"].str();
		auto dist = m["dist"].str();
		auto sts  = m["status"].str();
		auto vers = m["ver"].str();

		auto dver = UbuntuIdentifier::VersionNames.find(dist);

		if (ver == 0 || (dver != UbuntuIdentifier::VersionNames.end() && (*dver).second == ver))
		{
			vuln.emplace(pkg, sts == "safe" ? vers : "");
		}
	}

	return vuln;
}

vector<pair<string, long>> UbuntuLookup::GetChangelog(const string& pkg, OpSys distrib, double ver)
{
	vector<pair<string, long>> updates;

	if (distrib != Ubuntu)
	{
		log(ERR, "Specified distribution is not supported by this instance.");
		return updates;
	}

	string dver = "xenial";

	if (ver != 0)
	{
		for (auto& name : UbuntuIdentifier::VersionNames)
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

	auto resp = getURL("http://packages.ubuntu.com/" + dver + "/" + dpkg);

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
	static regex chlrgx("href=\"(?<url>[^\"]*\\/changelog)\">Ubuntu Changelog<\\/a>", regex::icase);

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

string UbuntuLookup::GetUpgradeCommand(const unordered_set<string>& pkgs, OpSys distrib, double ver)
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

UbuntuLookup::~UbuntuLookup()
{
}
