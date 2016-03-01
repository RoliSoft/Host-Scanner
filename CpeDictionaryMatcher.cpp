#include "CpeDictionaryMatcher.h"
#include "DataReader.h"
#include <mutex>

using namespace std;
using namespace boost;

vector<struct CpeEntry*> CpeDictionaryMatcher::entries = vector<struct CpeEntry*>();
unordered_map<string, vector<string>*> CpeDictionaryMatcher::aliases = unordered_map<string, vector<string>*>();

void CpeDictionaryMatcher::Scan(Service* service)
{
	if (service->banner == nullptr)
	{
		return;
	}

	auto matches = Scan(string(service->banner, service->banlen));

	service->cpe.insert(service->cpe.end(), matches.begin(), matches.end());
}

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

	auto tokens = 0;

	for (auto ent : entries)
	{
		auto ctokens   = 0;
		auto verfound  = false;
		string bestver = "";
		
		for (auto token : ent->tokens)
		{
			smatch what;
			if (regex_search(banner, what, token))
			{
				ctokens++;
			}
		}

		if (ctokens < ent->tokens.size())
		{
			continue;
		}

		for (auto version : ent->versions)
		{
			if (banner.find(version->version) == string::npos)
			{
				continue;
			}

			verfound = true;

			int vtokens = ctokens;

			for (auto token : version->tokens)
			{
				smatch what;
				if (regex_search(banner, what, token))
				{
					vtokens++;
				}
			}

			if (bestver == "" || vtokens > tokens)
			{
				ctokens = vtokens;
				bestver = version->cpe;
			}
		}

		if (verfound)
		{
			tokens = ctokens;
			
			matches.push_back(ent->cpe + ":" + bestver);
		}
	}

	return matches;
}

vector<CpeEntry*> CpeDictionaryMatcher::GetEntries()
{
	if (entries.size() == 0)
	{
		loadEntries();
	}

	return entries;
}

unordered_map<string, vector<string>*> CpeDictionaryMatcher::GetAliases()
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

	regex esc("[.^$|()\\[\\]{}*+?\\\\]");
	string rep("\\\\&");

	unsigned int pnum;
	dr.Read(pnum);

	for (auto i = 0u; i < pnum; i++)
	{
		auto ent = new CpeEntry();

		ent->cpe = dr.ReadString();
		
		unsigned char tnum;
		dr.Read(tnum);

		ent->tokens = vector<regex>();

		for (auto j = 0u; j < tnum; j++)
		{
			auto asd = regex_replace(dr.ReadString(), esc, rep, match_default | format_sed);
			ent->tokens.push_back(regex("\\b(" + asd + ")\\b", regex::icase));
		}

		unsigned int vnum;
		dr.Read(vnum);

		ent->versions = vector<CpeVersionEntry*>();

		for (auto j = 0u; j < vnum; j++)
		{
			auto ver = new CpeVersionEntry();

			ver->cpe     = dr.ReadString();
			ver->version = dr.ReadString();

			unsigned char vtnum;
			dr.Read(vtnum);

			ver->tokens = vector<regex>();

			for (auto k = 0u; k < vtnum; k++)
			{
				auto asd = regex_replace(dr.ReadString(), esc, rep, match_default | format_sed);
				ver->tokens.push_back(regex("\\b(" + asd + ")\\b", regex::icase));
			}

			ent->versions.push_back(ver);
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

		auto list = new vector<string>();

		for (auto j = 0u; j < anum; j++)
		{
			auto alias = dr.ReadString();
			
			list->push_back(alias);

			aliases.emplace(alias, list);
		}
	}

	// clean up

	mtx.unlock();
}

CpeDictionaryMatcher::~CpeDictionaryMatcher()
{
}
