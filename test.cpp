#define BOOST_TEST_MODULE TestScanner
#include "stdafx.h"
#include "service.h"
#include "portscannerfactory.h"
#include "tcpscanner.h"
#include "nmapscanner.h"
#include "udpscanner.h"
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
	auto tcp = PortScannerFactory::Get(IPPROTO_TCP);
	BOOST_TEST_CHECK((typeid(*tcp) == typeid(TcpScanner)), "Factory should have spawned TcpScanner.");
	delete tcp;

	auto udp = PortScannerFactory::Get(IPPROTO_UDP);
	BOOST_TEST_CHECK((typeid(*udp) == typeid(UdpScanner)), "Factory should have spawned UdpScanner.");
	delete udp;

	auto nmp = PortScannerFactory::Get(IPPROTO_NONE, true);
	BOOST_TEST_CHECK((typeid(*nmp) == typeid(NmapScanner)), "Factory should have spawned NmapScanner.");
	delete nmp;
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
}

BOOST_AUTO_TEST_CASE(UdpPayloadLoader)
{
	UdpScanner udp;

	auto payloads = udp.GetPayloads();

	BOOST_TEST_CHECK((payloads.size() >= 2), "Payloads list should contain at least two entries.");

	BOOST_TEST_CHECK((payloads.find(0) != payloads.end()), "Payloads list should contain generic payload.");
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
}
