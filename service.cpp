#include "service.h"

Service::Service(char * address, unsigned short port, IPPROTO protocol)
	: address(address), port(port), protocol(protocol)
{
}

Service::~Service()
{
	delete banner;
}
