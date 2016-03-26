#include "ServiceRegexMatcher.h"
#include "DataReader.h"
#include <boost/algorithm/string/replace.hpp>
#include <mutex>

using namespace std;
using namespace boost;

vector<ServiceRegex> ServiceRegexMatcher::regexes = vector<ServiceRegex>();

vector<string> ServiceRegexMatcher::Scan(const string& banner)
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

		if (regex_search(banner, match, rgx.regex, match_single_line))
		{
			auto cpe = rgx.cpe;

			auto cpeHasRgx = cpe.find('$') != string::npos;
			auto verHasRgx = rgx.version.length() > 0 && rgx.version.find('$') != string::npos;

			if (verHasRgx && !cpeHasRgx)
			{
				// TODO check whether CPE already has a version field or not

				cpe += ":" + rgx.version;
				cpeHasRgx = true;
			}

			if (cpeHasRgx)
			{
				sregex_token_iterator bsit(cpe.begin(), cpe.end(), bsrgx, 1);
				sregex_token_iterator end;

				for (; bsit != end; ++bsit)
				{
					auto nums = (*bsit).str();
					auto numi = atoi(nums.c_str());
					auto vals = regex_replace(match[numi].str(), vtrgx, "");

					replace_first(cpe, "$" + nums, vals);
				}
			}

			matches.push_back(cpe);
		}
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
