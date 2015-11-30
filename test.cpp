/*

	Host Scanner
	Copyright (C) 2015 RoliSoft <root@rolisoft.net>

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU Affero General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU Affero General Public License for more details.

	You should have received a copy of the GNU Affero General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

#define BOOST_TEST_MODULE TestScanner

#include "Stdafx.h"
#include "Service.h"
#include "ServiceScannerFactory.h"
#include "TcpScanner.h"
#include "UdpScanner.h"
#include "IcmpPinger.h"
#include "ArpPinger.h"
#include "NmapScanner.h"
#include <boost/test/unit_test.hpp>

#ifndef BOOST_TEST_WARN
#define BOOST_TEST_WARN(a,m) BOOST_CHECK(a)
#endif
#ifndef BOOST_TEST_CHECK
#define BOOST_TEST_CHECK(a,m) BOOST_CHECK(a)
#endif
#ifndef BOOST_TEST_REQUIRE
#define BOOST_TEST_REQUIRE(a,m) BOOST_CHECK(a)
#endif

using namespace std;
using namespace boost;

/*
	WARNING:

	Since this is a network scanner, testing it is rather difficult
	without a consistent target to point it at.

	This test relies on the facts that:
		- it can connect to port 25,
		- it has IPv6 access,
		- services on the tested IP addresses haven't changed.
*/

struct TestSetup
{
	TestSetup()
	{
		unit_test::unit_test_log_t::instance().set_threshold_level(unit_test::log_test_units);

#if Windows
		WSADATA wsaData;
		if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
		{
			BOOST_FAIL("Failed to initialize WinSock.");
		}
#endif
	}

	~TestSetup()
	{
#if Windows
		WSACleanup();
#endif
	}
};

BOOST_GLOBAL_FIXTURE(TestSetup);

BOOST_AUTO_TEST_CASE(PortScanFactory)
{
	auto tcp = ServiceScannerFactory::Get(IPPROTO_TCP);
	BOOST_TEST_CHECK((typeid(*tcp) == typeid(TcpScanner)), "Factory should have spawned TcpScanner for IPPROTO_TCP.");
	delete tcp;

	auto udp = ServiceScannerFactory::Get(IPPROTO_UDP);
	BOOST_TEST_CHECK((typeid(*udp) == typeid(UdpScanner)), "Factory should have spawned UdpScanner for IPPROTO_UDP.");
	delete udp;

	auto arp = ServiceScannerFactory::Get(IPPROTO_NONE);
	BOOST_TEST_CHECK((typeid(*arp) == typeid(ArpPinger)), "Factory should have spawned ArpPinger for IPPROTO_NONE.");
	delete arp;

	auto icmp = ServiceScannerFactory::Get(IPPROTO_ICMP);
	BOOST_TEST_CHECK((typeid(*icmp) == typeid(IcmpPinger)), "Factory should have spawned IcmpPinger for IPPROTO_ICMP.");
	delete icmp;

	auto icmp6 = ServiceScannerFactory::Get(IPPROTO_ICMPV6);
	BOOST_TEST_CHECK((typeid(*icmp6) == typeid(IcmpPinger)), "Factory should have spawned IcmpPinger for IPPROTO_ICMPV6.");
	delete icmp6;

	auto nmap = ServiceScannerFactory::Get(IPPROTO_NONE, true);
	BOOST_TEST_CHECK((typeid(*nmap) == typeid(NmapScanner)), "Factory should have spawned NmapScanner for <IPPROTO_NONE,external>.");
	delete nmap;
}

BOOST_AUTO_TEST_CASE(TcpIpv4PortScan)
{
	Services servs = {
		new Service("178.62.249.168", 20),
		new Service("178.62.249.168", 25)
	};

	TcpScanner scan;
	scan.Scan(&servs);

	BOOST_TEST_CHECK(!servs[0]->alive, "Port 20 should not be alive.");
	BOOST_TEST_CHECK( servs[1]->alive, "Port 25 should be alive.");

	BOOST_TEST_CHECK(servs[1]->banlen > 0, "Failed to grab service banner.");

	BOOST_TEST_CHECK((servs[0]->reason == AR_TimedOut || servs[0]->reason == AR_IcmpUnreachable), "Port 20 reason should either be TimedOut or IcmpUnreachable.");
	BOOST_TEST_CHECK( servs[1]->reason == AR_ReplyReceived, "Port 25 reason should be ReplyReceived.");

	freeServices(servs);
}

BOOST_AUTO_TEST_CASE(TcpIpv6PortScan)
{
	Services servs = {
		new Service("2a03:b0c0:2:d0::19:6001", 20),
		new Service("2a03:b0c0:2:d0::19:6001", 25)
	};

	TcpScanner scan;
	scan.Scan(&servs);

	BOOST_TEST_CHECK(!servs[0]->alive, "Port 20 should not be alive.");
	BOOST_TEST_CHECK( servs[1]->alive, "Port 25 should be alive.");

	BOOST_TEST_CHECK(servs[1]->banlen > 0, "Failed to grab service banner.");

	BOOST_TEST_CHECK((servs[0]->reason == AR_TimedOut || servs[0]->reason == AR_IcmpUnreachable), "Port 20 reason should either be TimedOut or IcmpUnreachable.");
	BOOST_TEST_CHECK( servs[1]->reason == AR_ReplyReceived, "Port 25 reason should be ReplyReceived.");

	freeServices(servs);
}

BOOST_AUTO_TEST_CASE(UdpPayloadLoader)
{
	UdpScanner udp;

	auto payloads = udp.GetPayloads();

	BOOST_TEST_CHECK((payloads.size() >= 2), "Payloads list should contain at least two entries.");

	BOOST_TEST_CHECK((payloads.find(0)  != payloads.end()), "Payloads list should contain generic payload.");
	BOOST_TEST_CHECK((payloads.find(53) != payloads.end()), "Payloads list should contain DNS payload.");
}

BOOST_AUTO_TEST_CASE(UdpIpv4PortScan)
{
	Services servs = {
		new Service("178.62.249.168", 53, IPPROTO_UDP),
		new Service("208.67.222.222", 53, IPPROTO_UDP)
	};

	UdpScanner scan;
	scan.Scan(&servs);

	BOOST_TEST_CHECK(!servs[0]->alive, "Port 53 on 178.* should not answer.");
	BOOST_TEST_CHECK( servs[1]->alive, "Port 53 on 208.* should answer.");

	BOOST_TEST_CHECK(servs[1]->banlen > 0, "Failed to grab service banner.");

	BOOST_TEST_CHECK((servs[0]->reason == AR_TimedOut || servs[0]->reason == AR_IcmpUnreachable), "Port 53 on 178.* reason should either be TimedOut or IcmpUnreachable.");
	BOOST_TEST_CHECK( servs[1]->reason == AR_ReplyReceived, "Port 53 on 208.* reason should be ReplyReceived.");

	freeServices(servs);
}

BOOST_AUTO_TEST_CASE(UdpIpv6PortScan)
{
	Services servs = {
		new Service("2a03:b0c0:2:d0::19:6001", 53, IPPROTO_UDP),
		new Service("2620:0:ccc::2", 53, IPPROTO_UDP)
	};

	UdpScanner scan;
	scan.Scan(&servs);

	BOOST_TEST_CHECK(!servs[0]->alive, "Port 53 on 2a03.* should not answer.");
	BOOST_TEST_CHECK( servs[1]->alive, "Port 53 on 2620.* should answer.");

	BOOST_TEST_CHECK(servs[1]->banlen > 0, "Failed to grab service banner.");

	BOOST_TEST_CHECK((servs[0]->reason == AR_TimedOut || servs[0]->reason == AR_IcmpUnreachable), "Port 53 on 2a03.* reason should either be TimedOut or IcmpUnreachable.");
	BOOST_TEST_CHECK( servs[1]->reason == AR_ReplyReceived, "Port 53 on 2620.* reason should be ReplyReceived.");

	freeServices(servs);
}

BOOST_AUTO_TEST_CASE(IcmpIpv4Ping)
{
	Services servs = {
		new Service("178.62.249.168", 0, IPPROTO_ICMP),
		new Service("0.0.1.0", 0, IPPROTO_ICMP)
	};

	IcmpPinger scan;
	scan.Scan(&servs);

	BOOST_TEST_CHECK( servs[0]->alive, "178.* should answer.");
	BOOST_TEST_CHECK(!servs[1]->alive, "0.* should not answer.");
	
	BOOST_TEST_CHECK( servs[0]->reason == AR_ReplyReceived, "178.* reason should be ReplyReceived.");
	BOOST_TEST_CHECK((servs[1]->reason == AR_TimedOut || servs[1]->reason == AR_IcmpUnreachable), "0.* reason should either be TimedOut or IcmpUnreachable.");

	freeServices(servs);
}

BOOST_AUTO_TEST_CASE(IcmpIpv6Ping)
{
	Services servs = {
		new Service("2a03:b0c0:2:d0::19:6001", 0, IPPROTO_ICMPV6),
		new Service("0100::", 0, IPPROTO_ICMPV6)
	};

	IcmpPinger scan;
	scan.Scan(&servs);

	BOOST_TEST_CHECK( servs[0]->alive, "2a03.* should answer.");
	BOOST_TEST_CHECK(!servs[1]->alive, "0100.* should not answer.");
	
	BOOST_TEST_CHECK( servs[0]->reason == AR_ReplyReceived, "2a03.* reason should be ReplyReceived.");
	BOOST_TEST_CHECK((servs[1]->reason == AR_TimedOut || servs[1]->reason == AR_IcmpUnreachable), "0100.* reason should either be TimedOut or IcmpUnreachable.");

	freeServices(servs);
}

BOOST_AUTO_TEST_CASE(ArpPing)
{
	Services servs = {
		new Service("192.168.1.1", 0, IPPROTO_NONE),
		new Service("192.168.1.2", 0, IPPROTO_NONE),
		new Service("178.62.249.168", 0, IPPROTO_NONE),
	};

	ArpPinger scan;
	scan.Scan(&servs);

	BOOST_TEST_CHECK( servs[0]->alive, "*.1 should answer.");
	BOOST_TEST_CHECK(!servs[1]->alive, "*.2 should not answer.");
	BOOST_TEST_CHECK(!servs[2]->alive, "178.* should not answer.");

	BOOST_TEST_CHECK(servs[0]->reason == AR_ReplyReceived, "*.1 reason should be ReplyReceived.");
	BOOST_TEST_CHECK(servs[1]->reason == AR_TimedOut, "*.2 reason should be TimedOut.");
	BOOST_TEST_CHECK(servs[2]->reason == AR_ScanFailed, "178.* reason should be ScanFailed.");

	freeServices(servs);
}

BOOST_AUTO_TEST_CASE(NmapIpv4PortScan)
{
	Services servs = {
		new Service("178.62.249.168", 25)
	};

	NmapScanner scan;
	scan.Scan(&servs);

	BOOST_TEST_CHECK(servs[0]->alive, "Port 25 should be alive.");

	BOOST_TEST_CHECK(servs[0]->banlen > 0, "Failed to grab service banner.");

	BOOST_TEST_CHECK(servs[0]->reason == AR_ReplyReceived, "Port 25 reason should be ReplyReceived.");

	freeServices(servs);
}

BOOST_AUTO_TEST_CASE(NmapIpv6PortScan)
{
	Services servs = {
		new Service("2a03:b0c0:2:d0::19:6001", 25)
	};

	NmapScanner scan;
	scan.Scan(&servs);

	BOOST_TEST_CHECK(servs[0]->alive, "Port 25 should be alive.");

	BOOST_TEST_CHECK(servs[0]->banlen > 0, "Failed to grab service banner.");

	BOOST_TEST_CHECK(servs[0]->reason == AR_ReplyReceived, "Port 25 reason should be ReplyReceived.");

	freeServices(servs);
}
