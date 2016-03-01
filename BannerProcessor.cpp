#include "BannerProcessor.h"

using namespace std;

void BannerProcessor::Scan(Service* service)
{
	auto matches = Scan(service->banner);

	if (matches.size() > 0)
	{
		service->cpe.insert(service->cpe.end(), matches.begin(), matches.end());
	}
}

BannerProcessor::~BannerProcessor()
{
}
