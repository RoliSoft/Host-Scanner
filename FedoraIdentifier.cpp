#include "FedoraIdentifier.h"
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/optional.hpp>
#include <boost/regex.hpp>

using namespace std;
using namespace boost;

// compiled by going through build logs at https://admin.fedoraproject.org/pkgdb/package/rpms/openssh/
const unordered_map<string, int> FedoraIdentifier::BundledVersions = unordered_map<string, int> {
	{ "7.2p2",   25 },
	{ "7.2p1",   25 },
	{ "7.1p2",   25 },
	{ "7.1p1",   24 },
	{ "7.0p1",   24 },
	{ "6.9p1",   24 },
	{ "6.8p1",   23 },
	{ "6.7p1",   23 },
	{ "6.6.1p1", 22 },
	{ "6.4p1",   21 },
	{ "6.3p1",   21 },
	{ "6.2p2",   21 },
	{ "6.2p1",   20 },
	{ "6.1p1",   19 },
	{ "6.0p1",   18 },
	{ "5.9p1",   18 },
	{ "5.8p2",   17 },
	{ "5.8p1",   16 },
	{ "5.7p1",   15 },
	{ "5.6p1",   15 },
	{ "5.5p1",   14 },
	{ "5.4p1",   14 },
	{ "5.3p1",   13 },
	{ "5.2p1",   13 },
};

bool FedoraIdentifier::Scan(Host* host)
{
	auto isFed = false;
	string sshVer;
	optional<int> fedVer, secUpd;

	// check if any SSH services are available

	// ver -> OpenSSH version
	static regex sshbnr("OpenSSH_(?<ver>[^\\s\\-_$]+)", regex::icase);
	
	// match any "fedora" tag
	static regex fedtag("\\bfedora\\b", regex::icase);

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

		// if the service is not SSH, just check if there is a "Fedora" tag in it anywhere

		if (!starts_with(service->banner, "SSH-2.0-OpenSSH_"))
		{
			if (regex_search(service->banner, sm, fedtag))
			{
				isFed = true;
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
	}

	// if we are certain the host is running Fedora, we have OpenSSH version,
	// but no Fedora distribution version, try to deduce it
	
	if (isFed && !sshVer.empty() && !fedVer.is_initialized())
	{
		auto ver = sshVer;

		trim(ver);
		to_lower(ver);

		auto bver = BundledVersions.find(ver);

		if (bver != BundledVersions.end())
		{
			fedVer = (*bver).second;
		}
	}

	// save information

	if (isFed)
	{
		string cpe = "o:redhat:fedora";

		host->opSys = OpSys::Fedora;

		if (fedVer.is_initialized())
		{
			cpe += ":" + to_string(fedVer.get());

			host->osVer = fedVer.get();
		}

		host->cpe.push_back(cpe);
	}

	return isFed;
}

FedoraIdentifier::~FedoraIdentifier()
{
}
