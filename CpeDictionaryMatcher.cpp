#include "CpeDictionaryMatcher.h"
#include "DataReader.h"
#include <mutex>

using namespace std;

vector<struct CpeEntry*> CpeDictionaryMatcher::entries = vector<struct CpeEntry*>();
unordered_map<string, vector<string>*> CpeDictionaryMatcher::aliases = unordered_map<string, vector<string>*>();

void CpeDictionaryMatcher::Scan(Service* service)
{
	if (service->banlen == 0 || service->banner == nullptr)
	{
		return;
	}

	if (entries.size() == 0)
	{
		loadEntries();
	}

	string banner(service->banner, service->banlen);

	int tokens = 0;
	int matchlen = 0;
	string best = "";

	for (auto ent : entries)
	{
		int ctokens = 0;
		int cmatchlen = 0;
		bool verfound = false;
		string bestver = "";
		
		for (auto token : ent->tokens)
		{
			if (banner.find(token) != string::npos)
			{
				ctokens++;
				cmatchlen += token.length();
			}
		}

		for (auto version : ent->versions)
		{
			if (banner.find(version->version) == string::npos)
			{
				continue;
			}

			verfound = true;

			int vtokens = ctokens;
			int vmatchlen = cmatchlen;

			for (auto token : version->tokens)
			{
				if (banner.find(token) != string::npos)
				{
					vtokens++;
					vmatchlen += token.length();
				}
			}

			if (vmatchlen > cmatchlen)
			{
				ctokens = vtokens;
				cmatchlen = vmatchlen;
				bestver = version->cpe;
			}
		}

		if (verfound && cmatchlen > matchlen)
		{
			tokens = ctokens;
			matchlen = cmatchlen;
			best = ent->cpe + ":" + bestver;
			log(DBG, best);
		}
	}

	service->cpe = best;
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

	unsigned int pnum;
	dr.Read(pnum);

	for (auto i = 0u; i < pnum; i++)
	{
		auto ent = new CpeEntry();

		ent->cpe = dr.ReadString();
		
		unsigned char tnum;
		dr.Read(tnum);

		ent->tokens = vector<string>();

		for (auto j = 0u; j < tnum; j++)
		{
			ent->tokens.push_back(dr.ReadString());
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

			ver->tokens = vector<string>();

			for (auto k = 0u; k < vtnum; k++)
			{
				ver->tokens.push_back(dr.ReadString());
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
