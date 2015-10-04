#include "stdafx.h"
#include "portscannerfactory.h"
#include "tcpscanner.h"
#include "udpscanner.h"

PortScanner* PortScannerFactory::Get(IPPROTO protocol)
{
	// TODO over-engineer this part with templates and auto-registering classes

	switch (protocol)
	{
	case IPPROTO_TCP:
		return new TcpScanner();

	case IPPROTO_UDP:
		return new UdpScanner();

	default:
		return nullptr;
	}
}
