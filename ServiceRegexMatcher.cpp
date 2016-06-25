#include "ServiceRegexMatcher.h"
#include "DataReader.h"
#include <boost/algorithm/string/replace.hpp>
#include <mutex>

using namespace std;
using namespace boost;

vector<ServiceRegex> ServiceRegexMatcher::regexes = vector<ServiceRegex>();

vector<string> ServiceRegexMatcher::Scan(const string& banner, bool processVendor)
{
	if (regexes.size() == 0)
	{
		loadRegexes();
	}

	vector<string> matches;

	if (banner.length() == 0)
	{
		return matches;
	}

	static regex bsrgx("\\$(\\d+)", regex::perl);
	static regex vtrgx("^v(?:er(?:sion)?)? *(?=\\d)", regex::perl | regex::icase);

	for (auto& rgx : regexes)
	{
		match_results<string::const_iterator> match;

		auto found = false;

		try
		{
			found = regex_search(banner, match, rgx.regex, match_single_line);
		}
		catch (boost::exception const&)
		{
			continue;
		}

		if (!found)
		{
			continue;
		}

		auto cpe = rgx.cpe;

		auto cpeHasRgx = cpe.find('$') != string::npos;
		auto verHasRgx = rgx.version.length() > 0 && rgx.version.find('$') != string::npos;

		if (verHasRgx && !cpeHasRgx)
		{
			cpe += ":" + rgx.version;
			cpeHasRgx = true;
		}

		// replace regular expression groups to their captured values in the version field

		if (cpeHasRgx)
		{
			sregex_iterator bsit(cpe.begin(), cpe.end(), bsrgx);
			sregex_iterator end;

			string cpe2(cpe);

			for (; bsit != end; ++bsit)
			{
				auto nums = (*bsit)[1].str();
				auto numi = stoi(nums);
				auto vals = regex_replace(match[numi].str(), vtrgx, "");

				replace_first(cpe2, "$" + nums, vals);
			}

			cpe = cpe2;
		}

		// find vendor patch level, if any and asked

		string patch;

		if (processVendor)
		{
			smatch what;
			regex verfind("^(?:[^:]+:){3}.*?(?<sep>[-+~_])(?<tag>[^:$;\\s\\)\\/]+)");

			if (regex_search(cpe, what, verfind))
			{
				// remove vendor patch level from CPE version

				patch = what["tag"].str();
				cpe   = cpe.substr(0, distance(cpe.cbegin(), what["sep"].first));
			}
		}

		// strip any irrelevant data

		auto fs = cpe.find(' ');

		if (fs != string::npos)
		{
			cpe = cpe.substr(0, fs);
		}

		// append vendor patch level separately, if any

		if (processVendor && !patch.empty())
		{
			cpe += ";" + patch;
		}

		matches.push_back(cpe);
	}

	return matches;
}

vector<ServiceRegex> ServiceRegexMatcher::GetRegexes()
{
	if (regexes.size() == 0)
	{
		loadRegexes();
	}

	return regexes;
}

void ServiceRegexMatcher::loadRegexes()
{
	static mutex mtx;
	auto locked = mtx.try_lock();
	if (!locked)
	{
		// wait until running parser finishes before returning
		lock_guard<mutex> guard(mtx);
		return;
	}

	// open regexes file

	DataReader dr;

	if (!dr.OpenEnv("cpe-regex"))
	{
		log(WRN, "Regexes database was not found!");

		mtx.unlock();
		return;
	}

	unsigned short ptype, pver;

	dr.Read(ptype);
	dr.Read(pver);

	if (ptype != 15)
	{
		log(WRN, "Regexes database type is incorrect.");

		mtx.unlock();
		return;
	}

	if (pver != 1)
	{
		log(WRN, "Regexes database version is not supported.");

		mtx.unlock();
		return;
	}

	unsigned int pnum;
	dr.Read(pnum);

	for (auto i = 0u; i < pnum; i++)
	{
		ServiceRegex rgx;

		auto rgex   = dr.ReadString();
		rgx.cpe     = dr.ReadString();
		rgx.product = dr.ReadString();
		rgx.version = dr.ReadString();

		if (rgx.cpe.length() == 0)
		{
			continue;
		}

		try
		{
			rgx.regex = move(regex(rgex, regex::perl));
		}
		catch (runtime_error&)
		{
			continue;
		}

		regexes.push_back(rgx);
	}

	// clean up

	mtx.unlock();
}

ServiceRegexMatcher::~ServiceRegexMatcher()
{
}
