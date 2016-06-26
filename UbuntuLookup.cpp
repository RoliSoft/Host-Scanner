#include "UbuntuLookup.h"
#include "UbuntuIdentifier.h"
#include "Utils.h"
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
	static regex tblrgx("href=\"[^l]+launchpad\\.net\\/ubuntu\\/(?<dist>[^\\/]+)\\/[^\\/]+\\/(?<pkg>[^\"]+)\">[^<]+<\\/a>[^<]*<\\/td><td><span class=\"(?<status>[^\"]+)\">[^<]+<\\/span>(?:\\s*\\((?<ver>[^\\)]+))?", regex::icase);

	sregex_iterator srit(html.begin(), html.end(), tblrgx);
	sregex_iterator end;

	for (; srit != end; ++srit)
	{
		auto m = *srit;

		auto pkg  = m["pkg"].str();
		auto dist = m["dist"].str();
		auto sts  = m["status"].str();
		auto vers = m["ver"].str();

		if (ver == 0 || UbuntuIdentifier::VersionNames.at(dist) == ver)
		{
			vuln.emplace(pkg, sts == "safe" ? vers : "");
		}
	}

	return vuln;
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
