#include "service.h"

Service::Service(char * address, unsigned short port)
	: address(address), port(port)
{
}

Service::~Service()
{
	if (data != nullptr)
	{
		delete data;
	}
}