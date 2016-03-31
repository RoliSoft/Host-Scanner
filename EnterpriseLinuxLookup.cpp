#include "EnterpriseLinuxLookup.h"
#include "Utils.h"
#include <boost/algorithm/string.hpp>
#include <boost/regex.hpp>

using namespace std;
using namespace boost;

void EnterpriseLinuxLookup::FindVulnerability(const string& cve)
{
	if (!ValidateCVE(cve))
	{
		log(ERR, "Specified CVE identifier '" + cve + "' is not syntactically valid.");
		return;
	}

	auto resp = getURL("https://bugzilla.redhat.com/show_bug.cgi?ctype=xml&id=" + cve);

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

		return;
	}

	auto html = get<0>(resp);

	// pkg -> name of the package
	// dist -> distribution (rhel-7, rhscl-1, fedora-all, etc)
	// status -> vulnerability status (affected, notaffected)
	static regex tblrgx("(?<dist>(?:rhel|rhscl|fedora)-(?:\\d+|all))\\/(?<pkg>[^=]+)=(?<status>[^,]+)", regex::icase);

	// res -> resolution (NOTABUG, ERRATA)
	static regex stsrgx("<resolution>(?<res>[^<]+)<\\/resolution>", regex::icase);

	// lst -> if res is ERRATA, comma-separated list of version numbers which fix the vulnerability
	static regex cfirgx("<cf_fixed_in>(?<lst>[^<]+)<\\/cf_fixed_in>", regex::icase);

	sregex_iterator srit(html.begin(), html.end(), tblrgx);
	sregex_iterator end;

	for (; srit != end; ++srit)
	{
		auto m = *srit;

		auto pkg  = m["pkg"].str();
		auto dist = m["dist"].str();
		auto sts  = m["status"].str();

		log(pkg + " " + dist + " " + sts);
	}

	smatch cfism;

	if (regex_search(html, cfism, cfirgx))
	{
		auto lst = cfism["lst"].str();

		vector<string> strs;
		split(strs, lst, is_any_of(","));

		for (auto& str : strs)
		{
			trim(str);
			log(str);
		}
	}
}

EnterpriseLinuxLookup::~EnterpriseLinuxLookup()
{
}
