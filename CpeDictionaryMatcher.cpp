#include "CpeDictionaryMatcher.h"
#include "DataReader.h"
#include <mutex>

using namespace std;

vector<struct CpeEntry*> CpeDictionaryMatcher::entries = vector<struct CpeEntry*>();
unordered_map<string, vector<string>*> CpeDictionaryMatcher::aliases = unordered_map<string, vector<string>*>();

void CpeDictionaryMatcher::Scan(Service* service)
{
	// TODO: implement
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

		ent->cpe     = dr.ReadString();
		ent->vendor  = dr.ReadString();
		ent->product = dr.ReadString();
		ent->name    = dr.ReadString();

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
