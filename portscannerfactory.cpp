#include "Stdafx.h"
#include "PortScannerFactory.h"
#include "TcpScanner.h"
#include "UdpScanner.h"
#include "IcmpPinger.h"
#include "ArpPinger.h"
#include "NmapScanner.h"

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

	case IPPROTO_NONE:
		return new ArpPinger();

	default:
		return nullptr;
	}
}
