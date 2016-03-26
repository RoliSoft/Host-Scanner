#include "CpeDictionaryMatcher.h"
#include "DataReader.h"
#include <mutex>
#include <unordered_set>

using namespace std;
using namespace boost;

vector<CpeEntry> CpeDictionaryMatcher::entries = vector<CpeEntry>();
unordered_map<string, vector<string>> CpeDictionaryMatcher::aliases = unordered_map<string, vector<string>>();

vector<string> CpeDictionaryMatcher::Scan(const string& banner)
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

		sregex_iterator srit(banner.begin(), banner.end(), ent.tokens);
		sregex_iterator srend;

		unordered_set<int> mcs;

		for (; srit != srend; ++srit)
		{
			for (int i = 1; i <= ent.size; i++)
			{
				if ((*srit)[i].matched)
				{
					mcs.emplace(i);
					namepos.push_back((*srit).position());
				}
			}
		}

		if (ent.size != mcs.size())
		{
			continue;
		}

		auto bestdist   = UINT_MAX;
		auto besttokens = 0u;
		auto bestcpe    = string();

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

			sregex_iterator vrit(banner.begin(), banner.end(), ent.tokens);
			sregex_iterator vrend;

			unordered_set<int> vmcs;

			for (; vrit != vrend; ++vrit)
			{
				for (int i = 1; i <= version.size; i++)
				{
					if ((*vrit)[i].matched)
					{
						vmcs.emplace(i);
						dist += abs(int((*vrit).position()) - int(verpos));
					}
				}
			}

			if (version.size != vmcs.size())
			{
				continue;
			}

			// if so, calculate distance from version to the tokens in the name
			
			for (auto npos : namepos)
			{
				dist += abs(npos - int(verpos));
			}

			// check against current best

			if (version.size > besttokens || (version.size == besttokens && dist <= bestdist))
			{
				bestdist   = dist;
				besttokens = version.size;
				bestcpe    = ent.cpe + ":" + version.cpe;
			}
		}

		if (bestcpe.length() != 0)
		{
			matches.push_back(bestcpe);
		}
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

		ent.size = tnum;

		string tokens;

		for (auto j = 0u; j < tnum; j++)
		{
			if (tokens.empty())
			{
				tokens += "\\b(?:(";
			}

			tokens += dr.ReadString();

			if (j < tnum - 1)
			{
				tokens += ")|(";
			}
			else
			{
				tokens += "))\\b";
			}
		}

		ent.tokens = move(regex(tokens, regex::icase));

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

			ver.size = vtnum;

			string vtokens;

			for (auto k = 0u; k < vtnum; k++)
			{
				if (vtokens.empty())
				{
					vtokens += "\\b(?:(";
				}

				vtokens += dr.ReadString();

				if (k < vtnum - 1)
				{
					vtokens += ")|(";
				}
				else
				{
					vtokens += "))\\b";
				}
			}

			ver.tokens = move(regex(vtokens, regex::icase));

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
