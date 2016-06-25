#include "BannerProcessor.h"
#include "ServiceRegexMatcher.h"
#include "CpeDictionaryMatcher.h"
#include "ProtocolTokenizer.h"

using namespace std;

void BannerProcessor::Scan(Service* service)
{
	auto matches = Scan(service->banner);

	if (matches.size() > 0)
	{
		service->cpe.insert(service->cpe.end(), matches.begin(), matches.end());
	}
}

vector<string> BannerProcessor::AutoProcess(const string& banner, bool processVendor)
{
	vector<string> cpes;

	// the regular expression pattern matcher implementation generally matches
	// against full service banners and as a result it is much more accurate

	static ServiceRegexMatcher srm;

	auto rmlst = srm.Scan(banner, processVendor);

	if (rmlst.size() > 0)
	{
		cpes.insert(cpes.end(), rmlst.begin(), rmlst.end());
	}

	// the CPE dictionary entry matcher requires tokenization in order to be
	// more precise

	static CpeDictionaryMatcher cdm;
	
	auto tokens = ProtocolTokenizer::AutoTokenize(banner);

	for (auto token : tokens)
	{
		auto cdlst = cdm.Scan(token, processVendor);

		if (cdlst.size() > 0)
		{
			cpes.insert(cpes.end(), cdlst.begin(), cdlst.end());
		}
	}

	// if neither methods matched, re-try matching the full service banner
	// with the CPE dictionary matcher as a last resort

	if (cpes.size() == 0)
	{
		auto cdlst = cdm.Scan(banner, processVendor);

		if (cdlst.size() > 0)
		{
			cpes.insert(cpes.end(), cdlst.begin(), cdlst.end());
		}
	}

	// remove duplicates
	
	if (cpes.size() > 1)
	{
		sort(cpes.begin(), cpes.end());
		cpes.erase(unique(cpes.begin(), cpes.end()), cpes.end());
	}

	return cpes;
}

BannerProcessor::~BannerProcessor()
{
}
