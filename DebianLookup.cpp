#include "DebianLookup.h"
#include "DebianIdentifier.h"
#include "Utils.h"
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
	static regex tblrgx("href=\"\\/tracker\\/source-package\\/[^\"]+\">(?<pkg>[^<]+)<\\/a><\\/td><td>[^<]*<\\/td><td>\\(?(?<dist>[^<\\)]+)\\)?<\\/td><td>(?<ver>[^<]+)<\\/td>", regex::icase);

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
