#include "ServiceRegexMatcher.h"
#include <mutex>
#include "DataReader.h"

using namespace std;

vector<struct ServiceRegex*> ServiceRegexMatcher::regexes = vector<struct ServiceRegex*>();

void ServiceRegexMatcher::Scan(Service* service)
{
	// TODO: implement
}

vector<ServiceRegex*> ServiceRegexMatcher::GetRegexes()
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
		auto rgx = new ServiceRegex();

		rgx->regex   = regex(dr.ReadString());
		rgx->cpe     = dr.ReadString();
		rgx->vendor  = dr.ReadString();
		rgx->product = dr.ReadString();
		rgx->version = dr.ReadString();

		regexes.push_back(rgx);
	}

	// clean up

	mtx.unlock();
}

ServiceRegexMatcher::~ServiceRegexMatcher()
{
}
