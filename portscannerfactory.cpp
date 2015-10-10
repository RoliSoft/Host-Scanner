#include "stdafx.h"
#include "portscannerfactory.h"
#include "tcpscanner.h"
#include "udpscanner.h"
#include "icmppinger.h"
#include "nmapscanner.h"

PortScanner* PortScannerFactory::Get(IPPROTO protocol, bool external)
{
	if (external)
	{
		return new NmapScanner();
	}

	switch (protocol)
	{
	case IPPROTO_TCP:
		return new TcpScanner();

	case IPPROTO_UDP:
		return new UdpScanner();

	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		return new IcmpPinger();

	default:
		return nullptr;
	}
}
