#include "Stdafx.h"
#include "ServiceScannerFactory.h"
#include "TcpScanner.h"
#include "UdpScanner.h"
#include "IcmpPinger.h"

ServiceScanner* ServiceScannerFactory::Get(IPPROTO protocol)
{
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
