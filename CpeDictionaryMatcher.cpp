#include "CpeDictionaryMatcher.h"
#include "DataReader.h"
#include "Utils.h"
#include <mutex>

using namespace std;
using namespace boost;

vector<CpeEntry> CpeDictionaryMatcher::entries = vector<CpeEntry>();
unordered_map<string, vector<string>> CpeDictionaryMatcher::aliases = unordered_map<string, vector<string>>();

vector<string> CpeDictionaryMatcher::Scan(const string& banner, bool processVendor)
{
	if (entries.size() == 0)
	{
		loadEntries();
	}

	vector<string> matches;

	if (banner.length() == 0)
	{
		return matches;
	}

	for (auto& ent : entries)
	{
		vector<int> namepos;

		// check if all the tokens from the name are in the input

		auto nametok = true;

		for (auto& token : ent.tokens)
		{
			smatch what;

			if (!regex_search(banner, what, token))
			{
				nametok = false;
				break;
			}

			namepos.push_back(what.position());
		}

		if (!nametok)
		{
			continue;
		}

		string bestcpe, bestver;

		auto bestdist   = UINT_MAX;
		auto besttokens = 0u;
		
		// if so, check if any associated versions are also in the input

		for (auto& version : ent.versions)
		{
			auto verpos = banner.find(version.version);

			if (verpos == string::npos)
			{
				continue;
			}

			// if the version number was found, check if the tokens associated
			// to this version are also present

			auto dist = 0u;
			auto vertok = true;

			for (auto& token : version.tokens)
			{
				smatch what;

				if (!regex_search(banner, what, token))
				{
					vertok = false;
					break;
				}

				dist += abs(int(what.position()) - int(verpos));
			}

			if (!vertok)
			{
				continue;
			}

			// if so, calculate distance from version to the tokens in the name
			
			for (auto npos : namepos)
			{
				dist += abs(npos - int(verpos));
			}

			// check against current best

			if (version.tokens.size() > besttokens || (version.tokens.size() == besttokens && dist <= bestdist))
			{
				bestdist   = dist;
				besttokens = version.tokens.size();
				bestcpe    = ent.cpe + ":" + version.cpe;
				bestver    = version.version;
			}
		}

		if (bestcpe.length() == 0)
		{
			continue;
		}

		// find vendor patch level, if any and asked
		
		if (processVendor)
		{
			smatch what;
			regex verfind(escapeRegex(bestver) + "(?<sep>[-+~_])(?<tag>[^$;\\s\\)\\/]+)");

			if (regex_search(banner, what, verfind))
			{
				// append vendor patch level to the CPE into a separate field

				bestcpe += ";" + what["tag"].str();
			}
		}

		// save matching CPE

		matches.push_back(bestcpe);
	}

	return matches;
}

vector<CpeEntry> CpeDictionaryMatcher::GetEntries()
{
	if (entries.size() == 0)
	{
		loadEntries();
	}

	return entries;
}

unordered_map<string, vector<string>> CpeDictionaryMatcher::GetAliases()
{
	if (aliases.size() == 0)
	{
		loadEntries();
	}

	return aliases;
}

void CpeDictionaryMatcher::loadEntries()
{
	static mutex mtx;
	auto locked = mtx.try_lock();
	if (!locked)
	{
		// wait until running parser finishes before returning
		lock_guard<mutex> guard(mtx);
		return;
	}

	// open entries file

	DataReader dr;

	if (!dr.OpenEnv("cpe-list"))
	{
		log(WRN, "CPE database was not found!");

		mtx.unlock();
		return;
	}

	unsigned short ptype, pver;

	dr.Read(ptype);
	dr.Read(pver);

	if (ptype != 1)
	{
		log(WRN, "CPE database type is incorrect.");

		mtx.unlock();
		return;
	}

	if (pver != 1)
	{
		log(WRN, "CPE database version is not supported.");

		mtx.unlock();
		return;
	}

	unsigned int pnum;
	dr.Read(pnum);

	for (auto i = 0u; i < pnum; i++)
	{
		CpeEntry ent;

		ent.cpe = dr.ReadString();
		
		unsigned char tnum;
		dr.Read(tnum);

		ent.tokens = vector<regex>();

		for (auto j = 0u; j < tnum; j++)
		{
			ent.tokens.push_back(std::move(regex("\\b(" + dr.ReadString() + ")\\b", regex::icase)));
		}

		unsigned int vnum;
		dr.Read(vnum);

		ent.versions = vector<CpeVersionEntry>();

		for (auto j = 0u; j < vnum; j++)
		{
			CpeVersionEntry ver;

			ver.cpe     = dr.ReadString();
			ver.version = dr.ReadString();

			unsigned char vtnum;
			dr.Read(vtnum);

			ver.tokens = vector<regex>();

			for (auto k = 0u; k < vtnum; k++)
			{
				ver.tokens.push_back(std::move(regex("\\b(" + dr.ReadString() + ")\\b", regex::icase)));
			}

			ent.versions.push_back(ver);
		}

		entries.push_back(ent);
	}
	
	// open aliases file

	if (!dr.OpenEnv("cpe-aliases"))
	{
		log(WRN, "CPE aliases database was not found!");

		mtx.unlock();
		return;
	}

	dr.Read(ptype);
	dr.Read(pver);

	if (ptype != 2)
	{
		log(WRN, "CPE aliases database type is incorrect.");

		mtx.unlock();
		return;
	}

	if (pver != 1)
	{
		log(WRN, "CPE aliases database version is not supported.");

		mtx.unlock();
		return;
	}

	dr.Read(pnum);

	for (auto i = 0u; i < pnum; i++)
	{
		unsigned short anum;
		dr.Read(anum);

		vector<string> list;

		for (auto j = 0u; j < anum; j++)
		{
			auto alias = dr.ReadString();
			
			list.push_back(alias);

			aliases.emplace(alias, list);
		}
	}

	// clean up

	mtx.unlock();
}

CpeDictionaryMatcher::~CpeDictionaryMatcher()
{
}
