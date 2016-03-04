/*

	Host Scanner
	Copyright (C) 2016 RoliSoft <root@rolisoft.net>

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
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
#include "HttpTokenizer.h"
#include "ThreeDigitTokenizer.h"
#include "ServiceRegexMatcher.h"
#include "CpeDictionaryMatcher.h"
#include <boost/test/unit_test.hpp>
#include <boost/algorithm/string.hpp>
#include <iostream>

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

void log(int level, const string& msg)
{
	if (level < WRN)
	{
		return;
	}

	cerr << msg << endl;
}

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

//---------------------------------------------------------------------------------------------------------------------
// Tokenizer Tests
//---------------------------------------------------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TokenizeAuto)
{
	string http_bnr = "HTTP/1.1 200 OK\r\nServer: tokenizer-test\r\n\r\n42";
	string smtp_bnr = "220 127.0.0.1 Tokenizer ESMTP Test ready";
	string fake_bnr = "Quidquid latine dictum sit altum videtur.";

	auto http_tok = ProtocolTokenizer::AutoTokenize(http_bnr);
	auto smtp_tok = ProtocolTokenizer::AutoTokenize(smtp_bnr);
	auto fake_tok = ProtocolTokenizer::AutoTokenize(fake_bnr);

	BOOST_TEST_CHECK(http_tok.size() > 0, "Failed to extract any tokens from HTTP header.");
	BOOST_TEST_CHECK(smtp_tok.size() > 0, "Failed to extract any tokens from SMTP header.");
	BOOST_TEST_CHECK(fake_tok.size() > 0, "Failed to extract any tokens from fake header.");

	trim(http_tok[0]);
	trim(smtp_tok[0]);
	trim(fake_tok[0]);

	BOOST_TEST_CHECK(http_tok[0] == "tokenizer-test",       "Erroneous server name extracted from HTTP header. Expected `tokenizer-test`, got `" + http_tok[0] + "`.");
	BOOST_TEST_CHECK(smtp_tok[0] == "Tokenizer ESMTP Test", "Erroneous server name extracted from SMTP header. Expected `Tokenizer ESMTP Test`, got `" + smtp_tok[0] + "`.");
	BOOST_TEST_CHECK(fake_tok[0] == fake_bnr,               "Erroneous token returned for fake header. Expected `" + fake_bnr + "`, got `" + fake_tok[0] + "`.");
}

BOOST_AUTO_TEST_CASE(TokenizeHttp)
{
	HttpTokenizer tk;

	// banner compiled from various header lines seen in the wild via shodan

	string banner = "HTTP/1.1 200 OK\r\nDate: Mon, 29 Feb 2016 21:24:21 GMT\r\nServer: nginx/1.4.6 (Ubuntu)\r\nServer: Apache-Coyote/1.1\r\nServer: Apache/2.2.15 (CentOS)\r\nServer: Apache/2.2.8 (Ubuntu) PHP/5.2.4-2ubuntu5.17 with Suhosin-Patch mod_ssl/2.2.8 OpenSSL/0.9.8g\r\nServer: Apache/2.0.46 (Red Hat) mod_perl/1.99_09 Perl/v5.8.0 mod_python/3.0.3 Python/2.2.3 mod_ssl/2.0.46 OpenSSL/0.9.7a DAV/2 FrontPage/5.0.2.2635 PHP/4.4.0 JRun/4.0 mod_jk/1.2.3-dev Sun-ONE-ASP/4.0.2\r\nServer: Apache/2.2.29 (Unix) mod_ssl/2.2.29 OpenSSL/1.0.1e-fips mod_jk/1.2.37 mod_bwlimited/1.4\r\nServer: Apache/1.3.27 (Unix)  (Red-Hat/Linux) mod_jk mod_ssl/2.8.12 OpenSSL/0.9.6m\r\nServer: Apache/2.2.3 (Debian) mod_jk/1.2.18 PHP/4.4.4-8+etch6 mod_ssl/2.2.3 OpenSSL/0.9.8c\r\nServer: Microsoft-IIS/7.5\r\nServer: cloudflare-nginx\r\nX-Powered-By: PHP/5.6.10\r\nX-Powered-By: PHP/5.3.9-ZS5.6.0 ZendServer/5.0\r\nX-Powered-By: PHP/5.3.3-7+squeeze14\r\nX-Powered-By: PHP/5.3.22-1~dotdeb.0\r\nX-Powered-By: Servlet 2.5; JBoss-5.0/JBossWeb-2.1\r\nX-Powered-By: Servlet 2.4; JBoss-4.2.3.GA (build: SVNTag=JBoss_4_2_3_GA date=201001210934)/JBossWeb-2.0\r\nX-AspNetMvc-Version: 4.0\r\nX-AspNet-Version: 4.0.30319\r\nX-Powered-By: ASP.NET\r\nX-Page-Speed: 1.9.32.3-4448\r\nSet-Cookie: OJSSID=xxxxxxxxxxxxxxxxxxxxxxxxxx; path=/\r\nSet-Cookie: ASP.NET_SessionId=xxxxxxxxxxxxxxxxxxxxxxxx; path=/; HttpOnly\r\nCache-Control: public\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\nwhatever";

	BOOST_TEST_CHECK(tk.CanTokenize(banner), "Valid HTTP header reported as unsupported.");

	auto tokens = tk.Tokenize(banner);

	BOOST_TEST_CHECK(tokens.size() > 0, "Failed to extract any tokens from HTTP header.");

	vector<string> reference = {
		"nginx/1.4.6", "Ubuntu", "Apache-Coyote/1.1", "Apache/2.2.15", "CentOS", "Apache/2.2.8",
		"Ubuntu", "PHP/5.2.4-2ubuntu5.17", "with", "Suhosin-Patch", "mod_ssl/2.2.8", "OpenSSL/0.9.8g",
		"Apache/2.0.46", "Red", "Hat", "mod_perl/1.99_09", "Perl", "v5.8.0", "mod_python/3.0.3",
		"Python/2.2.3", "mod_ssl/2.0.46", "OpenSSL/0.9.7a", "DAV/2", "FrontPage/5.0.2.2635",
		"PHP/4.4.0", "JRun/4.0", "mod_jk/1.2.3-dev", "Sun-ONE-ASP/4.0.2", "Apache/2.2.29", "Unix",
		"mod_ssl/2.2.29", "OpenSSL/1.0.1e-fips", "mod_jk/1.2.37", "mod_bwlimited/1.4", "Apache/1.3.27",
		"Unix", "Red-Hat", "Linux", "mod_jk", "mod_ssl/2.8.12", "OpenSSL/0.9.6m", "Apache/2.2.3",
		"Debian", "mod_jk/1.2.18", "PHP/4.4.4-8+etch6", "mod_ssl/2.2.3", "OpenSSL/0.9.8c",
		"Microsoft-IIS/7.5", "cloudflare-nginx", "PHP/5.6.10", "PHP/5.3.9-ZS5.6.0", "ZendServer/5.0",
		"PHP/5.3.3-7+squeeze14", "PHP/5.3.22-1~dotdeb.0", "Servlet/2.5;", "JBoss-5.0", "JBossWeb-2.1",
		"Servlet/2.4;", "JBoss-4.2.3.GA", "build", "SVNTag", "JBoss_4_2_3_GA", "date", "201001210934",
		"JBossWeb-2.0", "AspNetMvc-Version/4.0", "AspNet-Version/4.0.30319", "ASP.NET", "Page-Speed/1.9.32.3-4448"
	};

	BOOST_TEST_CHECK(tokens.size() == reference.size(), "Size mismatch between extracted and reference tokens array. Expected " + to_string(reference.size()) + " items, got " + to_string(tokens.size()) + " items.");

	for (auto i = 0u; i < min(tokens.size(), reference.size()); i++)
	{
		trim(tokens[i]);
		BOOST_TEST_CHECK(tokens[i] == reference[i], "Value mismatch between extracted and reference token. Expected `" + reference[i] + "`, got `" + tokens[i] + "`.");
	}
}

BOOST_AUTO_TEST_CASE(TokenizeThreeDigit)
{
	ThreeDigitTokenizer tk;

	// banner compiled from various server responses seen in the wild via shodan

	string banner = "220-xxx.xxx.xxx.xxx ESMTP Exim 4.86 #2 Tue, 01 Mar 2016 15:29:04 +0800 \r\n220-We do not authorize the use of this system to transport unsolicited, \r\n220 and/or bulk e-mail.\r\n250-xxx.xxx.xxx.xxxHello xxx.xxx.xxx.xxx [xxx.xxx.xxx.xxx]\r\n250-SIZE 52428800\r\n250-8BITMIME\r\n200 Kerio Connect 9.0.0 NNTP server ready\r\n200 NNTP Service 6.0.3790.3959 Version: 6.0.3790.3959 Posting Allowed \r\n220 Welcome to Xxxx Xxxx Xxxx, SNPP Gateway Ready\r\n220 xxx.xxx.xxx.xxx ESMTP Sendmail Ready; Tue, 1 Mar 2016 16:30:15 +0900\r\n250-xxx.xxx.xxx.xxx Hello xxx.xxx.xxx.xxx [xxx.xxx.xxx.xxx], pleased to meet you\r\n250-ENHANCEDSTATUSCODES\r\n250-PIPELINING\r\n250-8BITMIME\r\n250-SIZE 52428800\r\n220 xxx.xxx.xxx.xxx ESMTP Postfix (Debian/GNU)\r\n250-xxx.xxx.xxx.xxx\r\n250-SIZE 10240000\r\n220 xxx.xxx.xxx.xxx ESMTP Postfix\r\n220 mail.server.server ESMTP MailEnable Service, Version: 8.04-- ready at 03/01/16 09:28:32\r\n250-server.server [xxx.xxx.xxx.xxx], this server offers 4 extensions\r\n250-AUTH LOGIN\r\n250-SIZE 5120000\r\n250-HELP\r\n250 AUTH=LOGIN\r\n220 xxx.xxx.xxx.xxx Microsoft ESMTP MAIL Service ready at Tue, 1 Mar 2016 15:31:23 +0800\r\n250-xxx.xxx.xxx.xxx Hello [xxx.xxx.xxx.xxx]\r\n250-SIZE 31457280\r\n250-PIPELINING\r\n250-DSN\r\n250-ENHANCEDSTATUSCODES\r\n250-STARTTLS\r\n220 xxx.xxx.xxx.xxx ESMTP IdeaSmtpServer v0.80.1 ready.\r\n250-xxx.xxx.xxx.xxx Hello xxx.xxx.xxx.xxx [xxx.xxx.xxx.xxx], pleased to meet you\r\n250-PIPELINING\r\n250-ENHANCEDSTATUSCODES\r\n250-SIZE\r\n250-8BITMIME\r\n250-AUTH PLAIN LOGIN\r\n250-AUTH=PLAIN LOGIN\r\n220 xxx.xxx.xxx.xxx Microsoft ESMTP MAIL Service, Version: 7.0.6002.18264 ready at  Tue, 1 Mar 2016 00:32:39 -0700 \r\n250-xxx.xxx.xxx.xxx Hello [xxx.xxx.xxx.xxx]\r\n250-TURN\r\n250-SIZE 2097152\r\n250-ETRN\r\n250-PIPELINING\r\n250-DSN\r\n220 xxx.xxx.xxx.xxx Kerio Connect 8.5.2 patch 1 ESMTP ready\r\n250-xxx.xxx.xxx.xxx\r\n250-AUTH CRAM-MD5 PLAIN LOGIN DIGEST-MD5\r\n250-SIZE 20971520\r\n250-ENHANCEDSTATUSCODES\r\n250-8BITMIME\r\n250-PIPELINING";

	BOOST_TEST_CHECK(tk.CanTokenize(banner), "Valid SMTP banner reported as unsupported.");

	auto tokens = tk.Tokenize(banner);

	BOOST_TEST_CHECK(tokens.size() > 0, "Failed to extract any tokens from SMTP banner.");

	vector<string> reference = {
		"ESMTP Exim 4.86 #2",
		"ESMTP Sendmail",
		"ESMTP Postfix",
		"ESMTP Postfix",
		"ESMTP MailEnable Service, Version: 8.04--",
		"Microsoft ESMTP MAIL Service",
		"ESMTP IdeaSmtpServer v0.80.1",
		"Microsoft ESMTP MAIL Service, Version: 7.0.6002.18264",
		"Kerio Connect 8.5.2 patch 1 ESMTP"
	};

	BOOST_TEST_CHECK(tokens.size() == reference.size(), "Size mismatch between extracted and reference tokens array. Expected " + to_string(reference.size()) + " items, got " + to_string(tokens.size()) + " items.");

	for (auto i = 0u; i < min(tokens.size(), reference.size()); i++)
	{
		trim(tokens[i]);
		BOOST_TEST_CHECK(tokens[i] == reference[i], "Value mismatch between extracted and reference token. Expected `" + reference[i] + "`, got `" + tokens[i] + "`.");
	}
}

//---------------------------------------------------------------------------------------------------------------------
// Matcher Tests
//---------------------------------------------------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(MatchServiceRegex)
{
	ServiceRegexMatcher sm;

	// banners contain inexistent version numbers in order to test pattern-based version extraction

	vector<string> banners = {
		"SSH-2.0-OpenSSH_13.37\r\nProtocol mismatch.\r\n",
		"220-xxx.xxx.xxx.xxx ESMTP Exim 13.37 #2 Wed, 02 Mar 2016 06:44:36 -0700 \r\n220-We do not authorize the use of this system to transport unsolicited, \r\n220 and/or bulk e-mail.\r\n250-xxx.xxx.xxx.xxx Hello xxx.xxx.xxx.xxx [xxx.xxx.xxx.xxx]\r\n250-SIZE 52428800\r\n250-8BITMIME\r\n250-PIPELINING",
		"HTTP/1.1 400 Bad Request\r\nServer: nginx/13.37\r\nDate: Wed, 02 Mar 2016 13:47:28 GMT\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 166\r\nConnection: close\r\n\r\n<html>\r\n<head><title>400 Bad Request</title></head>\r\n<body bgcolor=\"white\">\r\n<center><h1>400 Bad Request</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>",
		"* OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE NAMESPACE AUTH=PLAIN AUTH=LOGIN] Dovecot ready.\r\n* CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE NAMESPACE AUTH=PLAIN AUTH=LOGIN\r\nA001 OK Pre-login capabilities listed, post-login capabilities have more.\r\n* ID (\"name\" \"Dovecot\")\r\nA002 OK ID completed.\r\nA003 BAD Error in IMAP command received by server.\r\n* BYE Logging out\r\nA004 OK Logout completed."
	};

	vector<string> reference = {
		"a:openbsd:openssh:13.37",
		"a:exim:exim:13.37",
		"a:igor_sysoev:nginx:13.37",
		"a:dovecot:dovecot",
	};

	for (auto i = 0u; i < banners.size(); i++)
	{
		auto cpes = sm.Scan(banners[i]);

		BOOST_TEST_CHECK(cpes.size() > 0, "Failed to extract any CPEs from banner " + to_string(i) + ".");
		BOOST_TEST_CHECK(cpes.size() < 2, "Multiple CPEs extracted from banner " + to_string(i) + ": `" + algorithm::join(cpes, "`") + "`");
		BOOST_TEST_CHECK(cpes[0] == reference[i], "Value mismatch between extracted and reference CPE. Expected `" + reference[i] + "`, got `" + cpes[0] + "`.");
	}
}

BOOST_AUTO_TEST_CASE(MatchCpeDictionary)
{
	CpeDictionaryMatcher cm;

	// banners contain version numbers listed within the CPE dictionary as they serve as a crucial token

	vector<string> banners = {
		"Cisco IOS Software, ME340x Software (ME340x-METROIPACCESS-M), Version 12.2(53)SE, RELEASE SOFTWARE (fc2)\r\nTechnical Support: http://www.cisco.com/techsupport\r\nCopyright (c) 1986-2009 by Cisco Systems, Inc.\r\nCompiled Sun 13-Dec-09 17:46 by prod_rel_team",
		"220-xxx.xxx.xxx.xxx 2.12 ESMTP Exim 3.14 #2 Wed, 02 Mar 2016 06:44:36 -0700 \r\n220-We do not authorize the use of this system to transport unsolicited, \r\n220 and/or bulk e-mail.\r\n250-xxx.xxx.xxx.xxx Hello xxx.xxx.xxx.xxx [xxx.xxx.xxx.xxx]\r\n250-SIZE 52428800\r\n250-8BITMIME\r\n250-PIPELINING",
		"HTTP/1.1 400 Bad Request\r\nServer: nginx/1.1.2 PHP/5.2.4-2ubuntu5.1.1 with Suhosin-Patch\r\nDate: Wed, 02 Mar 2016 13:47:28 GMT\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 166\r\nConnection: close\r\n\r\n<html>\r\n<head><title>400 Bad Request</title></head>\r\n<body bgcolor=\"white\">\r\n<center><h1>400 Bad Request</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>"
	};

	vector<vector<string>> reference = {
		{ "o:cisco:ios:12.2se" },
		{ "a:exim:exim:3.14" },
		{ "a:nginx:nginx:1.1.2", "a:php:php:5.2.4" }
	};

	for (auto i = 0u; i < banners.size(); i++)
	{
		auto cpes = cm.Scan(banners[i]);

		BOOST_TEST_CHECK(cpes.size() > 0, "Failed to extract any CPEs from banner " + to_string(i) + ".");
		BOOST_TEST_CHECK(cpes.size() == reference[i].size(), "Size mismatch between extracted and reference CPEs array. Expected " + to_string(reference[i].size()) + " items, got " + to_string(cpes.size()) + " items.");
		
		for (auto j = 0u; j < min(cpes.size(), reference[i].size()); j++)
		{
			BOOST_TEST_CHECK(cpes[j] == reference[i][j], "Value mismatch between extracted and reference CPE. Expected `" + reference[i][j] + "`, got `" + cpes[j] + "`.");
		}
	}
}

//---------------------------------------------------------------------------------------------------------------------
// Factory Tests
//---------------------------------------------------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(PortScanFactory)
{
	auto tcp = ServiceScannerFactory::Get(IPPROTO_TCP);
	BOOST_TEST_CHECK((typeid(*tcp) == typeid(TcpScanner)), "Factory should have spawned TcpScanner for IPPROTO_TCP, but instead spawned `" + string(typeid(*tcp).name()) + "`.");
	delete tcp;

	auto udp = ServiceScannerFactory::Get(IPPROTO_UDP);
	BOOST_TEST_CHECK((typeid(*udp) == typeid(UdpScanner)), "Factory should have spawned UdpScanner for IPPROTO_UDP, but instead spawned `" + string(typeid(*udp).name()) + "`.");
	delete udp;

	auto arp = ServiceScannerFactory::Get(IPPROTO_NONE);
	BOOST_TEST_CHECK((typeid(*arp) == typeid(ArpPinger)), "Factory should have spawned ArpPinger for IPPROTO_NONE, but instead spawned `" + string(typeid(*arp).name()) + "`.");
	delete arp;

	auto icmp = ServiceScannerFactory::Get(IPPROTO_ICMP);
	BOOST_TEST_CHECK((typeid(*icmp) == typeid(IcmpPinger)), "Factory should have spawned IcmpPinger for IPPROTO_ICMP, but instead spawned `" + string(typeid(*icmp).name()) + "`.");
	delete icmp;

	auto icmp6 = ServiceScannerFactory::Get(IPPROTO_ICMPV6);
	BOOST_TEST_CHECK((typeid(*icmp6) == typeid(IcmpPinger)), "Factory should have spawned IcmpPinger for IPPROTO_ICMPV6, but instead spawned `" + string(typeid(*icmp6).name()) + "`.");
	delete icmp6;

	auto nmap = ServiceScannerFactory::Get(IPPROTO_NONE, true);
	BOOST_TEST_CHECK((typeid(*nmap) == typeid(NmapScanner)), "Factory should have spawned NmapScanner for <IPPROTO_NONE,external>, but instead spawned `" + string(typeid(*nmap).name()) + "`.");
	delete nmap;
}

//---------------------------------------------------------------------------------------------------------------------
// Internal Port Scanner Tests
//---------------------------------------------------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TcpIpv4PortScan)
{
	Services servs = {
		new Service("178.62.249.168", 20), // euvps.rolisoft.net
		new Service("178.62.249.168", 25)  // euvps.rolisoft.net
	};

	TcpScanner scan;
	scan.Scan(&servs);

	BOOST_TEST_CHECK(!servs[0]->alive, "Port 20 should not be alive.");
	BOOST_TEST_CHECK( servs[1]->alive, "Port 25 should be alive.");

	BOOST_TEST_CHECK(servs[1]->banner.length() > 0, "Failed to grab service banner.");

	BOOST_TEST_CHECK((servs[0]->reason == AR_TimedOut || servs[0]->reason == AR_IcmpUnreachable), "Port 20 reason should either be TimedOut or IcmpUnreachable, it is instead " + Service::ReasonString(servs[0]->reason) + ".");
	BOOST_TEST_CHECK( servs[1]->reason == AR_ReplyReceived, "Port 25 reason should be ReplyReceived, it is instead " + Service::ReasonString(servs[1]->reason) + ".");

	freeServices(servs);
}

BOOST_AUTO_TEST_CASE(TcpIpv6PortScan)
{
	Services servs = {
		new Service("2a03:b0c0:2:d0::19:6001", 20), // euvps.rolisoft.net
		new Service("2a03:b0c0:2:d0::19:6001", 25)  // euvps.rolisoft.net
	};

	TcpScanner scan;
	scan.Scan(&servs);

	BOOST_TEST_CHECK(!servs[0]->alive, "Port 20 should not be alive.");
	BOOST_TEST_CHECK( servs[1]->alive, "Port 25 should be alive.");

	BOOST_TEST_CHECK(servs[1]->banner.length() > 0, "Failed to grab service banner.");

	BOOST_TEST_CHECK((servs[0]->reason == AR_TimedOut || servs[0]->reason == AR_IcmpUnreachable), "Port 20 reason should either be TimedOut or IcmpUnreachable, it is instead " + Service::ReasonString(servs[0]->reason) + ".");
	BOOST_TEST_CHECK( servs[1]->reason == AR_ReplyReceived, "Port 25 reason should be ReplyReceived, it is instead " + Service::ReasonString(servs[1]->reason) + ".");

	freeServices(servs);
}

BOOST_AUTO_TEST_CASE(UdpPayloadLoader)
{
	UdpScanner udp;

	auto payloads = udp.GetPayloads();

	BOOST_TEST_CHECK((payloads.size() >= 2), "Payloads list should contain at least two entries instead of " + to_string(payloads.size()) + ".");

	BOOST_TEST_CHECK((payloads.find(0)  != payloads.end()), "Payloads list should contain generic payload.");
	BOOST_TEST_CHECK((payloads.find(53) != payloads.end()), "Payloads list should contain DNS payload.");
}

BOOST_AUTO_TEST_CASE(UdpIpv4PortScan)
{
	Services servs = {
		new Service("178.62.249.168", 53, IPPROTO_UDP), // euvps.rolisoft.net
		new Service("208.67.222.222", 53, IPPROTO_UDP)  // OpenDNS
	};

	UdpScanner scan;
	scan.Scan(&servs);

	BOOST_TEST_CHECK(!servs[0]->alive, "Port 53 on 178.* should not answer.");
	BOOST_TEST_CHECK( servs[1]->alive, "Port 53 on 208.* should answer.");

	BOOST_TEST_CHECK(servs[1]->banner.length() > 0, "Failed to grab service banner.");

	BOOST_TEST_CHECK((servs[0]->reason == AR_TimedOut || servs[0]->reason == AR_IcmpUnreachable), "Port 53 on 178.* reason should either be TimedOut or IcmpUnreachable, it is instead " + Service::ReasonString(servs[0]->reason) + ".");
	BOOST_TEST_CHECK( servs[1]->reason == AR_ReplyReceived, "Port 53 on 208.* reason should be ReplyReceived, it is instead " + Service::ReasonString(servs[1]->reason) + ".");

	freeServices(servs);
}

BOOST_AUTO_TEST_CASE(UdpIpv6PortScan)
{
	Services servs = {
		new Service("2a03:b0c0:2:d0::19:6001", 53, IPPROTO_UDP), // euvps.rolisoft.net
		new Service("2620:0:ccc::2", 53, IPPROTO_UDP) // OpenDNS
	};

	UdpScanner scan;
	scan.Scan(&servs);

	BOOST_TEST_CHECK(!servs[0]->alive, "Port 53 on 2a03.* should not answer.");
	BOOST_TEST_CHECK( servs[1]->alive, "Port 53 on 2620.* should answer.");

	BOOST_TEST_CHECK(servs[1]->banner.length() > 0, "Failed to grab service banner.");

	BOOST_TEST_CHECK((servs[0]->reason == AR_TimedOut || servs[0]->reason == AR_IcmpUnreachable), "Port 53 on 2a03.* reason should either be TimedOut or IcmpUnreachable, it is instead " + Service::ReasonString(servs[0]->reason) + ".");
	BOOST_TEST_CHECK( servs[1]->reason == AR_ReplyReceived, "Port 53 on 2620.* reason should be ReplyReceived, it is instead " + Service::ReasonString(servs[1]->reason) + ".");

	freeServices(servs);
}

BOOST_AUTO_TEST_CASE(IcmpIpv4Ping)
{
	Services servs = {
		new Service("178.62.249.168", 0, IPPROTO_ICMP), // euvps.rolisoft.net
		new Service("0.0.1.0", 0, IPPROTO_ICMP) // bogon
	};

	IcmpPinger scan;
	scan.Scan(&servs);

	BOOST_TEST_CHECK( servs[0]->alive, "178.* should answer.");
	BOOST_TEST_CHECK(!servs[1]->alive, "0.* should not answer.");
	
	BOOST_TEST_CHECK( servs[0]->reason == AR_ReplyReceived, "178.* reason should be ReplyReceived, it is instead " + Service::ReasonString(servs[0]->reason) + ".");
	BOOST_TEST_CHECK((servs[1]->reason == AR_TimedOut || servs[1]->reason == AR_IcmpUnreachable), "0.* reason should either be TimedOut or IcmpUnreachable, it is instead " + Service::ReasonString(servs[1]->reason) + ".");

	freeServices(servs);
}

BOOST_AUTO_TEST_CASE(IcmpIpv6Ping)
{
	Services servs = {
		new Service("2a03:b0c0:2:d0::19:6001", 0, IPPROTO_ICMPV6), // euvps.rolisoft.net
		new Service("0100::", 0, IPPROTO_ICMPV6) // bogon
	};

	IcmpPinger scan;
	scan.Scan(&servs);

	BOOST_TEST_CHECK( servs[0]->alive, "2a03.* should answer.");
	BOOST_TEST_CHECK(!servs[1]->alive, "0100.* should not answer.");
	
	BOOST_TEST_CHECK( servs[0]->reason == AR_ReplyReceived, "2a03.* reason should be ReplyReceived, it is instead " + Service::ReasonString(servs[0]->reason) + ".");
	BOOST_TEST_CHECK((servs[1]->reason == AR_TimedOut || servs[1]->reason == AR_IcmpUnreachable), "0100.* reason should either be TimedOut or IcmpUnreachable, it is instead " + Service::ReasonString(servs[1]->reason) + ".");

	freeServices(servs);
}

BOOST_AUTO_TEST_CASE(ArpPing)
{
	Services servs = {
		new Service("192.168.1.1", 0, IPPROTO_NONE), // bogon
		new Service("192.168.1.2", 0, IPPROTO_NONE), // bogon
		new Service("178.62.249.168", 0, IPPROTO_NONE), // euvps.rolisoft.net
	};

	ArpPinger scan;
	scan.Scan(&servs);

	BOOST_TEST_CHECK( servs[0]->alive, "*.1 should answer.");
	BOOST_TEST_CHECK(!servs[1]->alive, "*.2 should not answer.");
	BOOST_TEST_CHECK(!servs[2]->alive, "178.* should not answer.");

	BOOST_TEST_CHECK(servs[0]->reason == AR_ReplyReceived, "*.1 reason should be ReplyReceived, it is instead " + Service::ReasonString(servs[0]->reason) + ".");
	BOOST_TEST_CHECK(servs[1]->reason == AR_TimedOut,      "*.2 reason should be TimedOut, it is instead " + Service::ReasonString(servs[1]->reason) + ".");
	BOOST_TEST_CHECK(servs[2]->reason == AR_ScanFailed,    "178.* reason should be ScanFailed, it is instead " + Service::ReasonString(servs[2]->reason) + ".");

	freeServices(servs);
}

//---------------------------------------------------------------------------------------------------------------------
// External Port Scanner Tests
//---------------------------------------------------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(NmapIpv4PortScan)
{
	Services servs = {
		new Service("178.62.249.168", 25) // euvps.rolisoft.net
	};

	NmapScanner scan;
	scan.Scan(&servs);

	BOOST_TEST_CHECK(servs[0]->alive, "Port 25 should be alive.");

	BOOST_TEST_CHECK(servs[0]->banner.length() > 0, "Failed to grab service banner.");

	BOOST_TEST_CHECK(servs[0]->reason == AR_ReplyReceived, "Port 25 reason should be ReplyReceived, it is instead " + Service::ReasonString(servs[0]->reason) + ".");

	freeServices(servs);
}

BOOST_AUTO_TEST_CASE(NmapIpv6PortScan)
{
	Services servs = {
		new Service("2a03:b0c0:2:d0::19:6001", 25) // euvps.rolisoft.net
	};

	NmapScanner scan;
	scan.Scan(&servs);

	BOOST_TEST_CHECK(servs[0]->alive, "Port 25 should be alive.");

	BOOST_TEST_CHECK(servs[0]->banner.length() > 0, "Failed to grab service banner.");

	BOOST_TEST_CHECK(servs[0]->reason == AR_ReplyReceived, "Port 25 reason should be ReplyReceived, it is instead " + Service::ReasonString(servs[0]->reason) + ".");

	freeServices(servs);
}
