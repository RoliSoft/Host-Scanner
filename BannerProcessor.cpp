#include "BannerProcessor.h"

using namespace std;

void BannerProcessor::Scan(Service* service)
{
	if (service->banner == nullptr)
	{
		return;
	}

	auto matches = Scan(string(service->banner, service->banlen));

	service->cpe.insert(service->cpe.end(), matches.begin(), matches.end());
}

BannerProcessor::~BannerProcessor()
{
}
