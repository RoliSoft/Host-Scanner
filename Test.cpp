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
#include "Utils.h"
#include "ServiceScannerFactory.h"
#include "HostScannerFactory.h"
#include "TaskQueueRunner.h"
#include "TcpScanner.h"
#include "UdpScanner.h"
#include "IcmpPinger.h"
#include "ArpPinger.h"
#include "NmapScanner.h"
#include "InternalScanner.h"
#include "ShodanScanner.h"
#include "CensysScanner.h"
#include "LooquerScanner.h"
#include "PassiveScanner.h"
#include "HttpTokenizer.h"
#include "ThreeDigitTokenizer.h"
#include "ServiceRegexMatcher.h"
#include "CpeDictionaryMatcher.h"
#include "VulnerabilityLookup.h"
#include "OperatingSystemIdentifier.h"
#include "UbuntuIdentifier.h"
#include "DebianIdentifier.h"
#include "EnterpriseLinuxIdentifier.h"
#include "FedoraIdentifier.h"
#include "WindowsIdentifier.h"
#include "DebianLookup.h"
#include "UbuntuLookup.h"
#include "EnterpriseLinuxLookup.h"
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/core/ignore_unused.hpp>
#include <boost/algorithm/string.hpp>
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

#if BOOST_VERSION >= 105900
	#define BOOST_AUTO_TEST_CASE_DISABLED(name) BOOST_AUTO_TEST_CASE(name, *boost::unit_test::disabled())
#else
	#define BOOST_AUTO_TEST_CASE_DISABLED(name) BOOST_AUTO_TEST_CASE(name)
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

/*!
 * Logs the specified message.
 * 
 * For the unit test, messages below the warning level will be ignored,
 * and messages at that or above level will be sent as a warning through
 * boost's own `BOOST_TEST_WARN` macro, which will show up as a warning
 * on the unit test output.
 *
 * \param level The message's severity level.
 * \param msg The message's content.
 * \param format Value indicating whether to enable formatting.
 */
void log(int level, const string& msg, bool format)
{
	if (level < WRN)
	{
		return;
	}

#if BOOST_VERSION < 105900
	ignore_unused(msg);
#endif

	ignore_unused(format);

	BOOST_TEST_WARN(false, msg);
}

/*!
 * Reads a key value from the global persistent configuration store.
 * 
 * This is not efficient, however it is supposed to be only used by the tests
 * requiring a single API key to be specified, which means it will be called
 * once per such case.
 * 
 * \param key Key to read.
 *
 * \return Value of the key, or empty string if key not found or read failed.
*/
string readKey(const string& key)
{
	namespace po = boost::program_options;
	namespace fs = boost::filesystem;

	po::options_description desc("arguments", 100);
	desc.add_options()
		(key.c_str(), po::value<string>(), "");

	po::variables_map vm;

	vector<string> paths = {
#if Windows
		get<0>(splitPath(getAppPath())) + "\\HostScanner.ini",
		getEnvVar("APPDATA") + "\\RoliSoft\\Host Scanner\\HostScanner.ini"
#else
		get<0>(splitPath(getAppPath())) + "/HostScanner.ini",
		getEnvVar("HOME") + "/.HostScanner.conf",
		"/etc/HostScanner/HostScanner.conf"
#endif
	};

	for (auto path : paths)
	{
		fs::path fp(path);

		if (fs::exists(fp) && fs::is_regular_file(fp))
		{
			po::store(po::parse_config_file<char>(path.c_str(), desc, true), vm);
		}
	}

	po::notify(vm);

	if (vm.count(key) != 0)
	{
		return vm[key].as<string>();
	}

	return "";
}

/*!
 * Fixture for the Boost unit testing framework to set up and tear down accordingly.
 */
struct TestSetup
{
	/*!
	 * Initializes a new instance of the unit test by initializing WinSock on Windows.
	 */
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

	/*!
	 * Finalizes an instance of unit test by deinitializing WinSock on Windows.
	 */
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

/*!
 * Tests automatic tokenization.
 * 
 * The automatic tokenizer calls each supported protocol's tokenizer in order of the protocol's popularity.
 * These implementations have a `CanTokenize()` function and are expected to gracefully reject unsupported banners.
 */
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

/*!
 * Tests the HTTP tokenizer.
 * 
 * The HTTP tokenizer will try to extract product names and version numbers from the appropriate places,
 * e.g. the `Server` and `X-Powered-By` fields. Since these fields generally have multiple products listed  
 * without any standardized separator, the tokenizer should make sure to extract all the product names
 * including any associated version numbers in separate tokens.
 * 
 * The banner being tested against was compiled from various header lines seen in the wild via Shodan,
 * and represents a worst-case scenario of edge-cases.
 */
BOOST_AUTO_TEST_CASE(TokenizeHttp)
{
	HttpTokenizer tk;

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

/*!
 * Tests the "three-digit" tokenizer.
 * 
 * The "three-digit" tokenizer is a general purpose solution for parsing protocols which use a three-digit
 * response to indicate message type. Such protocols include SMTP, NNTP, FTP and probably many more.
 * Unfortunately there is no standardized way to announce server name and version for such protocols
 * (like the `Server` header in HTTP) and as such server name is generally casually announced in the
 * informational level welcome message part of the service banner. The informational messages are generally
 * within the range of 200-299, however this might vary depending on the actual protocol.
 * 
 * The banner being tested against was compiled from various server responses seen in the wild via Shodan,
 * against which the tokenizer will make some educated guesses based on the most popular responses for
 * similar services on Shodan. See source code for actual guesses, as this might change in the future.
 */
BOOST_AUTO_TEST_CASE(TokenizeThreeDigit)
{
	ThreeDigitTokenizer tk;

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

/*!
 * Tests automatic service matching.
 * 
 * The automatic matcher calls each supported matcher and merges the results.
 * 
 * The banner being tested against contains a product with an inexistent version numbers in order to test
 * pattern-based version extraction, and another product whose version number is listed within the CPE
 * dictionary but has no regular expression defined in the pattern matcher's database.
 */
BOOST_AUTO_TEST_CASE(MatchAuto)
{
	string banner = "HTTP/1.1 200 OK\r\nServer: Apache/31.33.7 PHP/5.2.4-2ubuntu5.2.5\r\n\r\n2600";

	auto cpes = BannerProcessor::AutoProcess(banner, false);

	vector<string> reference = {
		"a:apache:http_server:31.33.7",
		"a:php:php:5.2.4"
	};

	BOOST_TEST_CHECK(cpes.size() == reference.size(), "Size mismatch between extracted and reference CPEs array. Expected " + to_string(reference.size()) + " items, got " + to_string(cpes.size()) + " items.");

	sort(cpes.begin(), cpes.end());

	for (auto i = 0u; i < min(cpes.size(), reference.size()); i++)
	{
		BOOST_TEST_CHECK(cpes[i] == reference[i], "Value mismatch between extracted and reference CPE. Expected `" + reference[i] + "`, got `" + cpes[i] + "`.");
	}
}

/*!
 * Tests automatic service matching with vendor-level patch handling.
 * 
 * The automatic matcher calls each supported matcher with vendor-level patch handling requested,
 * and merges the results. The vendor-level patches extracted should not differ between matchers.
 * 
 * The banner being tested against contains a product with an inexistent version numbers in order to test
 * pattern-based version extraction, and another product whose version number is listed within the CPE
 * dictionary but has no regular expression defined in the pattern matcher's database.
 */
BOOST_AUTO_TEST_CASE(MatchAutoVendorPatch)
{
	string banner = "HTTP/1.1 200 OK\r\nServer: Apache/31.33.7 PHP/5.2.4-2ubuntu5.2.5\r\n\r\n2600";

	auto cpes = BannerProcessor::AutoProcess(banner, true);

	vector<string> reference = {
		"a:apache:http_server:31.33.7",
		"a:php:php:5.2.4;2ubuntu5.2.5"
	};

	BOOST_TEST_CHECK(cpes.size() == reference.size(), "Size mismatch between extracted and reference CPEs array. Expected " + to_string(reference.size()) + " items, got " + to_string(cpes.size()) + " items.");

	sort(cpes.begin(), cpes.end());

	for (auto i = 0u; i < min(cpes.size(), reference.size()); i++)
	{
		BOOST_TEST_CHECK(cpes[i] == reference[i], "Value mismatch between extracted and reference CPE. Expected `" + reference[i] + "`, got `" + cpes[i] + "`.");
	}
}

/*!
 * Tests the service banner pattern matcher.
 * 
 * This test requires a "cpe-regex" data file to be present in order to run. The purpose of this matcher is to
 * test the service banner against all the regular expressions in the database, and extract products without
 * a prior version number list, thus allowing to extract future versions. Use of the pattern matcher also allows
 * the identification of services which do not implicitly announce a product name and number, by looking at how
 * the server deviates from the standard through its service banner or miscellaneous responses. E.g. SMTP servers
 * will all reply with the same error code to a faulty action, but with different error messages after the code,
 * which allows the pattern matcher to identify the actual daemon.
 * 
 * The banners being tested against contain inexistent version numbers in order to test pattern-based version extraction.
 */
BOOST_AUTO_TEST_CASE(MatchServiceRegex)
{
	ServiceRegexMatcher sm;

	vector<string> banners = {
		"SSH-2.0-OpenSSH_13.37\r\nProtocol mismatch.\r\n",
		"220-xxx.xxx.xxx.xxx ESMTP Exim 13.37~RC6-2 #2 Wed, 02 Mar 2016 06:44:36 -0700 \r\n220-We do not authorize the use of this system to transport unsolicited, \r\n220 and/or bulk e-mail.\r\n250-xxx.xxx.xxx.xxx Hello xxx.xxx.xxx.xxx [xxx.xxx.xxx.xxx]\r\n250-SIZE 52428800\r\n250-8BITMIME\r\n250-PIPELINING",
		"HTTP/1.1 400 Bad Request\r\nServer: nginx/13.37\r\nDate: Wed, 02 Mar 2016 13:47:28 GMT\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 166\r\nConnection: close\r\n\r\n<html>\r\n<head><title>400 Bad Request</title></head>\r\n<body bgcolor=\"white\">\r\n<center><h1>400 Bad Request</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>",
		"* OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE NAMESPACE AUTH=PLAIN AUTH=LOGIN] Dovecot ready.\r\n* CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE NAMESPACE AUTH=PLAIN AUTH=LOGIN\r\nA001 OK Pre-login capabilities listed, post-login capabilities have more.\r\n* ID (\"name\" \"Dovecot\")\r\nA002 OK ID completed.\r\nA003 BAD Error in IMAP command received by server.\r\n* BYE Logging out\r\nA004 OK Logout completed."
	};

	vector<string> reference = {
		"a:openbsd:openssh:13.37",
		"a:exim:exim:13.37~RC6-2", // patch should not be handled and removed
		"a:igor_sysoev:nginx:13.37",
		"a:dovecot:dovecot"
	};

	for (auto i = 0u; i < banners.size(); i++)
	{
		auto cpes = sm.Scan(banners[i], false);

		BOOST_TEST_CHECK(cpes.size() > 0, "Failed to extract any CPEs from banner " + to_string(i) + ".");
		BOOST_TEST_CHECK(cpes.size() < 2, "Multiple CPEs extracted from banner " + to_string(i) + ": `" + algorithm::join(cpes, "`") + "`");
		BOOST_TEST_CHECK(cpes[0] == reference[i], "Value mismatch between extracted and reference CPE. Expected `" + reference[i] + "`, got `" + cpes[0] + "`.");
	}
}

/*!
 * Tests the service banner pattern matcher with vendor-level patch handling.
 * 
 * This case tests against the same service banners as the `MatchServiceRegex` one, and therefore has the same requirements,
 * but expects proper handling of the vendor-level patch version numbers.
 * 
 * The banners being tested against contain inexistent version numbers in order to test pattern-based version extraction.
 */
BOOST_AUTO_TEST_CASE(MatchServiceRegexVendorPatch)
{
	ServiceRegexMatcher sm;

	vector<string> banners = {
		"SSH-2.0-OpenSSH_13.37\r\nProtocol mismatch.\r\n",
		"220-xxx.xxx.xxx.xxx ESMTP Exim 13.37~RC6-2 #2 Wed, 02 Mar 2016 06:44:36 -0700 \r\n220-We do not authorize the use of this system to transport unsolicited, \r\n220 and/or bulk e-mail.\r\n250-xxx.xxx.xxx.xxx Hello xxx.xxx.xxx.xxx [xxx.xxx.xxx.xxx]\r\n250-SIZE 52428800\r\n250-8BITMIME\r\n250-PIPELINING",
		"HTTP/1.1 400 Bad Request\r\nServer: nginx/13.37\r\nDate: Wed, 02 Mar 2016 13:47:28 GMT\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 166\r\nConnection: close\r\n\r\n<html>\r\n<head><title>400 Bad Request</title></head>\r\n<body bgcolor=\"white\">\r\n<center><h1>400 Bad Request</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>",
		"* OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE NAMESPACE AUTH=PLAIN AUTH=LOGIN] Dovecot ready.\r\n* CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE NAMESPACE AUTH=PLAIN AUTH=LOGIN\r\nA001 OK Pre-login capabilities listed, post-login capabilities have more.\r\n* ID (\"name\" \"Dovecot\")\r\nA002 OK ID completed.\r\nA003 BAD Error in IMAP command received by server.\r\n* BYE Logging out\r\nA004 OK Logout completed."
	};

	vector<string> reference = {
		"a:openbsd:openssh:13.37",
		"a:exim:exim:13.37;RC6-2",
		"a:igor_sysoev:nginx:13.37",
		"a:dovecot:dovecot"
	};

	for (auto i = 0u; i < banners.size(); i++)
	{
		auto cpes = sm.Scan(banners[i], true);

		BOOST_TEST_CHECK(cpes.size() > 0, "Failed to extract any CPEs from banner " + to_string(i) + ".");
		BOOST_TEST_CHECK(cpes.size() < 2, "Multiple CPEs extracted from banner " + to_string(i) + ": `" + algorithm::join(cpes, "`") + "`");
		BOOST_TEST_CHECK(cpes[0] == reference[i], "Value mismatch between extracted and reference CPE. Expected `" + reference[i] + "`, got `" + cpes[0] + "`.");
	}
}

/*!
 * Tests the CPE dictionary matcher.
 * 
 * This test requires the "cpe-list" data file to be present in order to run. The purpose of this matcher is to
 * use NIST's National Vulnerability Database entries to match the product names and associated version numbers
 * within to the specified service banner. Such matching has its pros and cons, and this unit test evaluates
 * the edge-cases met during the development of the dictionary matcher.
 * 
 * The banners being tested against contain version numbers listed within the CPE dictionary as they serve a
 * crucial two-fold purpose during the recognition phase.
 */
BOOST_AUTO_TEST_CASE(MatchCpeDictionary)
{
	CpeDictionaryMatcher cm;

	vector<string> banners = {
		"Cisco IOS Software, ME340x Software (ME340x-METROIPACCESS-M), Version 12.2(53)SE, RELEASE SOFTWARE (fc2)\r\nTechnical Support: http://www.cisco.com/techsupport\r\nCopyright (c) 1986-2009 by Cisco Systems, Inc.\r\nCompiled Sun 13-Dec-09 17:46 by prod_rel_team",
		"220-xxx.xxx.xxx.xxx 2.12 ESMTP Exim 3.14~RC6-2 #2 Wed, 02 Mar 2016 06:44:36 -0700 \r\n220-We do not authorize the use of this system to transport unsolicited, \r\n220 and/or bulk e-mail.\r\n250-xxx.xxx.xxx.xxx Hello xxx.xxx.xxx.xxx [xxx.xxx.xxx.xxx]\r\n250-SIZE 52428800\r\n250-8BITMIME\r\n250-PIPELINING",
		"HTTP/1.1 400 Bad Request\r\nServer: nginx/1.1.2 PHP/5.2.4-2ubuntu5.1.1 with Suhosin-Patch\r\nDate: Wed, 02 Mar 2016 13:47:28 GMT\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 166\r\nConnection: close\r\n\r\n<html>\r\n<head><title>400 Bad Request</title></head>\r\n<body bgcolor=\"white\">\r\n<center><h1>400 Bad Request</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>"
	};

	vector<vector<string>> reference = {
		{ "o:cisco:ios:12.2se" },
		{ "a:exim:exim:3.14" },
		{ "a:nginx:nginx:1.1.2", "a:php:php:5.2.4" }
	};

	for (auto i = 0u; i < banners.size(); i++)
	{
		auto cpes = cm.Scan(banners[i], false);

		BOOST_TEST_CHECK(cpes.size() > 0, "Failed to extract any CPEs from banner " + to_string(i) + ".");
		BOOST_TEST_CHECK(cpes.size() == reference[i].size(), "Size mismatch between extracted and reference CPEs array. Expected " + to_string(reference[i].size()) + " items, got " + to_string(cpes.size()) + " items.");
		
		sort(cpes.begin(), cpes.end());

		for (auto j = 0u; j < min(cpes.size(), reference[i].size()); j++)
		{
			BOOST_TEST_CHECK(cpes[j] == reference[i][j], "Value mismatch between extracted and reference CPE. Expected `" + reference[i][j] + "`, got `" + cpes[j] + "`.");
		}
	}
}

/*!
 * Tests the CPE dictionary matcher with vendor-level patch handling.
 * 
 * This case tests against the same service banners as the `MatchCpeDictionary` one, and therefore has the same requirements,
 * but expects proper handling of the vendor-level patch version numbers.
 * 
 * The banners being tested against contain version numbers listed within the CPE dictionary as they serve a
 * crucial two-fold purpose during the recognition phase, however the vendor-level patch numbers are not part of
 * the CPE dictionary, and as such are handled separately.
 */
BOOST_AUTO_TEST_CASE(MatchCpeDictionaryVendorPatch)
{
	CpeDictionaryMatcher cm;

	vector<string> banners = {
		"Cisco IOS Software, ME340x Software (ME340x-METROIPACCESS-M), Version 12.2(53)SE, RELEASE SOFTWARE (fc2)\r\nTechnical Support: http://www.cisco.com/techsupport\r\nCopyright (c) 1986-2009 by Cisco Systems, Inc.\r\nCompiled Sun 13-Dec-09 17:46 by prod_rel_team",
		"220-xxx.xxx.xxx.xxx 2.12 ESMTP Exim 3.14~RC6-2 #2 Wed, 02 Mar 2016 06:44:36 -0700 \r\n220-We do not authorize the use of this system to transport unsolicited, \r\n220 and/or bulk e-mail.\r\n250-xxx.xxx.xxx.xxx Hello xxx.xxx.xxx.xxx [xxx.xxx.xxx.xxx]\r\n250-SIZE 52428800\r\n250-8BITMIME\r\n250-PIPELINING",
		"HTTP/1.1 400 Bad Request\r\nServer: nginx/1.1.2 PHP/5.2.4-2ubuntu5.1.1 with Suhosin-Patch\r\nDate: Wed, 02 Mar 2016 13:47:28 GMT\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 166\r\nConnection: close\r\n\r\n<html>\r\n<head><title>400 Bad Request</title></head>\r\n<body bgcolor=\"white\">\r\n<center><h1>400 Bad Request</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>"
	};

	vector<vector<string>> reference = {
		{ "o:cisco:ios:12.2se" },
		{ "a:exim:exim:3.14;RC6-2" },
		{ "a:nginx:nginx:1.1.2", "a:php:php:5.2.4;2ubuntu5.1.1" }
	};

	for (auto i = 0u; i < banners.size(); i++)
	{
		auto cpes = cm.Scan(banners[i], true);

		BOOST_TEST_CHECK(cpes.size() > 0, "Failed to extract any CPEs from banner " + to_string(i) + ".");
		BOOST_TEST_CHECK(cpes.size() == reference[i].size(), "Size mismatch between extracted and reference CPEs array. Expected " + to_string(reference[i].size()) + " items, got " + to_string(cpes.size()) + " items.");
		
		sort(cpes.begin(), cpes.end());

		for (auto j = 0u; j < min(cpes.size(), reference[i].size()); j++)
		{
			BOOST_TEST_CHECK(cpes[j] == reference[i][j], "Value mismatch between extracted and reference CPE. Expected `" + reference[i][j] + "`, got `" + cpes[j] + "`.");
		}
	}
}

//---------------------------------------------------------------------------------------------------------------------
// Vulnerability Lookup Tests
//---------------------------------------------------------------------------------------------------------------------

/*!
 * Tests the vulnerability lookup mechanism.
 * 
 * Since vendor-level patches are not present in the CVE database, those should be discarded.
 * There are tests inside the case to make sure this is properly handled.
 */
BOOST_AUTO_TEST_CASE(LookupVulnerabilities)
{
	VulnerabilityLookup vl;

	vector<string> cpes = {
		"a:apache:http_server:2.2.22",
		"a:php:php:5.5.5;dfsg-0+deb8u1",
		"a:php:php:5.5.5~dfsg-0+deb8u1"
	};

	unordered_map<string, vector<string>> reference = {
		{ "a:apache:http_server:2.2.22", {
			"2012-2687", "2014-0231"
		}},
		{ "a:php:php:5.5.5;dfsg-0+deb8u1", { // when vendoring is properly discarded
			"2013-6712", "2015-6836"
		}},
		{ "a:php:php:5.5.5~dfsg-0+deb8u1", { } } // when vendoring is not handled properly
	};

	auto cves = vl.Scan(cpes);

	BOOST_TEST_CHECK(cves.size() > 0, "Failed to find any vulnerabilities for the specified CPEs.");

	for (auto& entry : reference)
	{
		auto cveit = cves.find(entry.first);

		BOOST_TEST_CHECK((cveit != cves.end() || entry.second.size() == 0), "Failed to find any vulnerabilities for the CPE `" + entry.first + "`.");

		if (cveit == cves.end())
		{
			continue;
		}

		auto ccves = (*cveit).second;

		for (auto& cve : entry.second)
		{
			auto found = false;

			for (auto& dcve : ccves)
			{
				if (cve == dcve.cve)
				{
					found = true;
					break;
				}
			}

			BOOST_TEST_CHECK(found, "Failed to find vulnerability `" + cve + "` for the CPE `" + entry.first + "`.");
		}
	}
}

/*!
 * Tests the vendor package lookup mechanism.
 * 
 * This test case queries the package manager of Debian Jessie for various vulnerability
 * information, and compares it to hardcoded historical data, which shouldn't change.
 */
BOOST_AUTO_TEST_CASE(LookupDebianVulnerabilities)
{
	DebianLookup vl;

	vector<tuple<string, string, string>> refs = {
		{ "CVE-2016-3142", "php5", "5.6.19+dfsg-0+deb8u1" },
		{ "CVE-2015-3185", "apache2", "2.4.10-10+deb8u1" },
		{ "CVE-2014-9583", "", "" } // should not be affected
	};

	for (auto& ref : refs)
	{
		auto vuln = vl.FindVulnerability(get<0>(ref), Debian, 8);

		if (get<1>(ref).empty())
		{
			BOOST_TEST_CHECK(vuln.size() == 0, "Found vulnerability `" + get<0>(ref) + "` at the vendor, but should not have.");

			continue;
		}

		BOOST_TEST_CHECK(vuln.size() > 0, "Failed to find vulnerability `" + get<0>(ref) + "` at the vendor.");

		if (vuln.empty())
		{
			continue;
		}

		auto pkgs = *vuln.begin();

		BOOST_TEST_CHECK((get<1>(ref) == pkgs.first),  "Incorrect package name identified for `" + get<0>(ref) + "`: expected `" + get<1>(ref) + "`, got `" + pkgs.first + "`.");
		BOOST_TEST_CHECK((get<2>(ref) == pkgs.second), "Incorrect package version identified for `" + get<0>(ref) + "`: expected `" + get<2>(ref) + "`, got `" + pkgs.second + "`.");
	}
}

/*!
 * Tests the vendor package lookup mechanism.
 * 
 * This test case queries the package manager of Ubuntu 14.04 for various vulnerability
 * information, and compares it to hardcoded historical data, which shouldn't change.
 */
BOOST_AUTO_TEST_CASE(LookupUbuntuVulnerabilities)
{
	UbuntuLookup vl;

	vector<tuple<string, string, string>> refs = {
		{ "CVE-2016-3142", "php5", "5.5.9+dfsg-1ubuntu4.16" },
		{ "CVE-2015-3185", "apache2", "2.4.7-1ubuntu4.5" },
		{ "CVE-2014-9583", "", "" } // should not be affected
	};

	for (auto& ref : refs)
	{
		auto vuln = vl.FindVulnerability(get<0>(ref), Ubuntu, 14.04);

		if (get<1>(ref).empty())
		{
			BOOST_TEST_CHECK(vuln.size() == 0, "Found vulnerability `" + get<0>(ref) + "` at the vendor, but should not have.");

			continue;
		}

		BOOST_TEST_CHECK(vuln.size() > 0, "Failed to find vulnerability `" + get<0>(ref) + "` at the vendor.");

		if (vuln.empty())
		{
			continue;
		}

		auto pkgs = *vuln.begin();

		BOOST_TEST_CHECK((get<1>(ref) == pkgs.first),  "Incorrect package name identified for `" + get<0>(ref) + "`: expected `" + get<1>(ref) + "`, got `" + pkgs.first + "`.");
		BOOST_TEST_CHECK((get<2>(ref) == pkgs.second), "Incorrect package version identified for `" + get<0>(ref) + "`: expected `" + get<2>(ref) + "`, got `" + pkgs.second + "`.");
	}
}

/*!
 * Tests the vendor package lookup mechanism.
 * 
 * This test case queries the package manager of Fedora 23 for various vulnerability
 * information, and compares it to hardcoded historical data, which shouldn't change.
 */
BOOST_AUTO_TEST_CASE(LookupEnterpriseLinuxVulnerabilities)
{
	EnterpriseLinuxLookup vl;

	vector<tuple<string, string, string>> refs = {
		{ "CVE-2016-3142", "php", "5.5.33" },
		{ "CVE-2015-3185", "httpd", "2.4.16" },
		{ "CVE-2014-9583", "", "" } // should not be affected
	};

	for (auto& ref : refs)
	{
		auto vuln = vl.FindVulnerability(get<0>(ref), Fedora, 23);

		if (get<1>(ref).empty())
		{
			BOOST_TEST_CHECK(vuln.size() == 0, "Found vulnerability `" + get<0>(ref) + "` at the vendor, but should not have.");

			continue;
		}

		BOOST_TEST_CHECK(vuln.size() > 0, "Failed to find vulnerability `" + get<0>(ref) + "` at the vendor.");

		if (vuln.empty())
		{
			continue;
		}

		auto pkgs = *vuln.begin();

		BOOST_TEST_CHECK((get<1>(ref) == pkgs.first),  "Incorrect package name identified for `" + get<0>(ref) + "`: expected `" + get<1>(ref) + "`, got `" + pkgs.first + "`.");
		BOOST_TEST_CHECK((get<2>(ref) == pkgs.second), "Incorrect package version identified for `" + get<0>(ref) + "`: expected `" + get<2>(ref) + "`, got `" + pkgs.second + "`.");
	}
}

/*!
 * Tests the vendor package changelog parser mechanism.
 * 
 * This test queries the package manager of Debian Jessie for a package's
 * full changelog and tries to find a hardcoded historical entry in it.
 */
BOOST_AUTO_TEST_CASE(LookupDebianChangelogs)
{
	DebianLookup vl;

	string pkgnam = "openssh-server";
	string pkgver = "6.7p1-5+deb8u1";
	string pkgdat = "Wed, 13 Jan 2016 22:08:52 +0100";

	auto vers = vl.GetChangelog(pkgnam, Debian, 8);

	BOOST_TEST_CHECK(vers.size() > 0, "Failed to fetch changelog for `" + pkgnam + "` from the vendor.");

	auto found = false;

	for (auto& ver : vers)
	{
		if (ver.first == pkgver)
		{
			found = true;
			auto refdat = dateToUnix(pkgdat);

			BOOST_TEST_CHECK((ver.second == refdat), "Found package `" + pkgnam + " " + pkgver + "`, but publish date is off by " + to_string(refdat - ver.second) + " seconds.");

			break;
		}
	}

	BOOST_TEST_CHECK(found, "Failed to find `" + pkgnam + " " + pkgver + "` in fetched changelog.");
}

/*!
 * Tests the vendor package changelog parser mechanism.
 * 
 * This test queries the package manager of Ubuntu 16.04 for a package's
 * full changelog and tries to find a hardcoded historical entry in it.
 */
BOOST_AUTO_TEST_CASE(LookupUbuntuChangelogs)
{
	UbuntuLookup vl;

	string pkgnam = "openssh-server";
	string pkgver = "7.2p2-3";
	string pkgdat = "Wed, 13 Apr 2016 16:42:28 +0100";

	auto vers = vl.GetChangelog(pkgnam, Ubuntu, 16.04);

	BOOST_TEST_CHECK(vers.size() > 0, "Failed to fetch changelog for `" + pkgnam + "` from the vendor.");

	auto found = false;

	for (auto& ver : vers)
	{
		if (ver.first == pkgver)
		{
			found = true;
			auto refdat = dateToUnix(pkgdat);

			BOOST_TEST_CHECK((ver.second == refdat), "Found package `" + pkgnam + " " + pkgver + "`, but publish date is off by " + to_string(refdat - ver.second) + " seconds.");

			break;
		}
	}

	BOOST_TEST_CHECK(found, "Failed to find `" + pkgnam + " " + pkgver + "` in fetched changelog.");
}

/*!
 * Tests the vendor package changelog parser mechanism.
 * 
 * This test queries the package manager of Fedora 24 for a package's
 * full changelog and tries to find a hardcoded historical entry in it.
 */
BOOST_AUTO_TEST_CASE(LookupEnterpriseLinuxChangelogs)
{
	EnterpriseLinuxLookup vl;

	string pkgnam = "openssh-server";
	string pkgver = "7.2p2-6";
	string pkgdat = "Fri, 29 Apr 2016";

	auto vers = vl.GetChangelog(pkgnam, Fedora, 24);

	BOOST_TEST_CHECK(vers.size() > 0, "Failed to fetch changelog for `" + pkgnam + "` from the vendor.");

	auto found = false;

	for (auto& ver : vers)
	{
		if (ver.first == pkgver)
		{
			found = true;
			auto refdat = dateToUnix(pkgdat);

			BOOST_TEST_CHECK((ver.second == refdat), "Found package `" + pkgnam + " " + pkgver + "`, but publish date is off by " + to_string(refdat - ver.second) + " seconds.");

			break;
		}
	}

	BOOST_TEST_CHECK(found, "Failed to find `" + pkgnam + " " + pkgver + "` in fetched changelog.");
}

/*!
 * Tests the version comparison function.
 * 
 * This function should compare version numbers regardless of style, with the proper
 * handling of the vendor-level patches. Should work best with Apache and semantic versioning,
 * however every sane versioning scheme should adhere to the rules used by the checker.
 */
BOOST_AUTO_TEST_CASE(VersionComparison)
{
	vector<tuple<string, string, int>> vers = {
		{ "a:apache:http_server:2.2.22", "a:apache:http_server:2.2.22",  0 },
		{ "a:apache:http_server:2.2.22", "a:apache:http_server:2.2.21",  1 },
		{ "a:apache:http_server:2.2.22", "a:apache:http_server:2.2.23", -1 },
		{ "a:apache:http_server:2.2.22", "a:apache:http_server:2.3",    -1 },
		{ "a:php:php:5.5.5;deb8u1",      "a:php:php:5.5.5;deb8u1",       0 },
		{ "a:php:php:5.4.5;deb8u1",      "a:php:php:5.5.5;deb8u1",      -1 },
		{ "a:php:php:5.5.5;deb8u2",      "a:php:php:5.5.5;deb8u1",       1 },
		{ "a:php:php:5.5.5;deb8u1",      "a:php:php:5.5.5;deb10",       -1 },
		{ "a:php:php:5.5.5",             "a:php:php:5.5.5;u1",          -1 },
		{ "a:exim:exim:4.84.2-1",        "a:exim:exim:4.87;3~bpo8+1",   -1 },
		{ "a:exim:exim:4.87-4",          "a:exim:exim:4.87;3~bpo8+1",    1 }
	};

	for (auto& ver : vers)
	{
		auto res = compareVersions(get<0>(ver), get<1>(ver));
		auto exp = get<2>(ver);

		BOOST_TEST_CHECK(res == exp, "CPE `" + get<0>(ver) + "` should be " + (exp == 0 ? "`equal` to" : (exp == 1 ? "`newer` than" : "`older` than")) +  " `" + get<1>(ver) + "`, it instead is `" + (res == 0 ? "equal" : (res == 1 ? "newer" : "older")) + "`.");
	}
}

/*!
 * Tests the date and time parsing function.
 * 
 * This case tests the parsing and relative comparison of RFC1123-formatted dates.
 */
BOOST_AUTO_TEST_CASE(DateTimeComparison)
{
	vector<tuple<string, string, int>> dates = {
		{ "Sun, 08 May 2016 14:03:10", "Sat, 30 Apr 2016 13:38:29",  1 },
		{ "Thu, 07 Apr 2016 19:26:59", "Sat, 30 Apr 2016 13:38:29", -1 },
		{ "Fri, 01 Apr 2016 19:04:07", "Fri, 01 Apr 2016 19:04:07",  0 }
	};

	for (auto& date : dates)
	{
		auto res = compareDates(get<0>(date), get<1>(date));
		auto exp = get<2>(date);

		BOOST_TEST_CHECK(res == exp, "Date `" + get<0>(date) + "` should be " + (exp == 0 ? "`equal` to" : (exp == 1 ? "`newer` than" : "`older` than")) +  " `" + get<1>(date) + "`, it instead is `" + (res == 0 ? "equal" : (res == 1 ? "newer" : "older")) + "`.");
	}
}

//---------------------------------------------------------------------------------------------------------------------
// Operating System Identifier Tests
//---------------------------------------------------------------------------------------------------------------------

/*!
 * Tests automatic operating system and distribution identification.
 *
 * The automatic identifier calls each supported operating system's identifier in order of popularity.
 * These implementations have a `Scan()` function and are expected to gracefully reject unsupported distributions.
 */
BOOST_AUTO_TEST_CASE(IdentifyAuto)
{
	// test release name-based detection

	Host hostrn("whatever", { 22 });
	hostrn.services->at(0)->banner = "SSH-2.0-OpenSSH_5.5p1 Debian-6+squeeze\r\n";

	// test tag-based detection

	Host hosttg("whatever", { 22 });
	hosttg.services->at(0)->banner = "SSH-2.0-OpenSSH_6.6.1p1 Debian-2ubuntu2.4\r\n";

	// test version-based detection

	Host hostvr("whatever", { 22, 80 });
	hostvr.services->at(0)->banner = "SSH-2.0-OpenSSH_5.3\r\n";
	hostvr.services->at(1)->banner = "HTTP/1.1 200 OK\r\nServer: Apache (CentOS)\r\n\r\n";

	BOOST_TEST_CHECK(OperatingSystemIdentifier::AutoProcess(&hostrn), "Failed to identify release name-based Debian Squeeze.");
	BOOST_TEST_CHECK(OperatingSystemIdentifier::AutoProcess(&hosttg), "Failed to identify tag-based Ubuntu Trusty Tahr.");
	BOOST_TEST_CHECK(OperatingSystemIdentifier::AutoProcess(&hostvr), "Failed to identify version-based CentOS 6.");

	BOOST_TEST_CHECK(hostrn.opSys == OpSys::Debian, "Failed to identify Debian, got instead '" + OperatingSystemIdentifier::OpSysString(hostrn.opSys) + "'.");
	BOOST_TEST_CHECK(hostrn.osVer == 6, "Failed to identify version of Debian 6, got instead '" + to_string(hostrn.osVer) + "'.");

	BOOST_TEST_CHECK(hosttg.opSys == OpSys::Ubuntu, "Failed to identify Ubuntu, got instead '" + OperatingSystemIdentifier::OpSysString(hosttg.opSys) + "'.");
	BOOST_TEST_CHECK(hosttg.osVer == 14.04, "Failed to identify version of Ubuntu 14.04, got instead '" + to_string(hosttg.osVer) + "'.");

	BOOST_TEST_CHECK(hostvr.opSys == OpSys::EnterpriseLinux, "Failed to identify CentOS, got instead '" + OperatingSystemIdentifier::OpSysString(hostvr.opSys) + "'.");
	BOOST_TEST_CHECK(hostvr.osVer == 6, "Failed to identify version of CentOS 6, got instead '" + to_string(hostvr.osVer) + "'.");
}

/*!
 * Tests the Debian operating system and distribution identifier.
 *
 * The test first targets the SSH banners, falling back otherwise to data collected across all services.
 */
BOOST_AUTO_TEST_CASE(IdentifyDebian)
{
	// test release name-based detection

	Host hostrn("whatever", { 22 });
	hostrn.services->at(0)->banner = "SSH-2.0-OpenSSH_5.5p1 Debian-6+squeeze\r\n";

	// test tag-based detection

	Host hosttg("whatever", { 22 });
	hosttg.services->at(0)->banner = "SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u1\r\n";

	// test version-based detection

	Host hostvr("whatever", { 22, 80 });
	hostvr.services->at(0)->banner = "SSH-2.0-OpenSSH_6.0p1\r\n";
	hostvr.services->at(1)->banner = "HTTP/1.1 200 OK\r\nServer: Apache (Debian)\r\n\r\n";

	DebianIdentifier os;

	BOOST_TEST_CHECK(os.Scan(&hostrn), "Failed to identify release name-based Debian Squeeze.");
	BOOST_TEST_CHECK(os.Scan(&hosttg), "Failed to identify tag-based Debian Jessie.");
	BOOST_TEST_CHECK(os.Scan(&hostvr), "Failed to identify version-based Debian Wheezy.");

	BOOST_TEST_CHECK(hostrn.opSys == OpSys::Debian, "Failed to identify Debian, got instead '" + OperatingSystemIdentifier::OpSysString(hostrn.opSys) + "'.");
	BOOST_TEST_CHECK(hostrn.osVer == 6, "Failed to identify version of Debian 6, got instead '" + to_string(hostrn.osVer) + "'.");

	BOOST_TEST_CHECK(hosttg.opSys == OpSys::Debian, "Failed to identify Debian, got instead '" + OperatingSystemIdentifier::OpSysString(hosttg.opSys) + "'.");
	BOOST_TEST_CHECK(hosttg.osVer == 8, "Failed to identify version of Debian 8, got instead '" + to_string(hosttg.osVer) + "'.");

	BOOST_TEST_CHECK(hostvr.opSys == OpSys::Debian, "Failed to identify Debian, got instead '" + OperatingSystemIdentifier::OpSysString(hostvr.opSys) + "'.");
	BOOST_TEST_CHECK(hostvr.osVer == 7, "Failed to identify version of Debian 7, got instead '" + to_string(hostvr.osVer) + "'.");
}

/*!
 * Tests the Ubuntu operating system and distribution identifier.
 *
 * The test first targets the SSH banners, falling back otherwise to data collected across all services.
 */
BOOST_AUTO_TEST_CASE(IdentifyUbuntu)
{
	// test tag-based detection

	Host hosttg("whatever", { 22 });
	hosttg.services->at(0)->banner = "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.4\r\n";

	// test version-based detection

	Host hostvr("whatever", { 22, 80 });
	hostvr.services->at(0)->banner = "SSH-2.0-OpenSSH_7.2p2\r\n";
	hostvr.services->at(1)->banner = "HTTP/1.1 200 OK\r\nServer: Apache (Ubuntu)\r\n\r\n";

	UbuntuIdentifier os;

	BOOST_TEST_CHECK(os.Scan(&hosttg), "Failed to identify tag-based Ubuntu Trusty Tahr.");
	BOOST_TEST_CHECK(os.Scan(&hostvr), "Failed to identify version-based Ubuntu Xenial Xerus.");

	BOOST_TEST_CHECK(hosttg.opSys == OpSys::Ubuntu, "Failed to identify Ubuntu, got instead '" + OperatingSystemIdentifier::OpSysString(hosttg.opSys) + "'.");
	BOOST_TEST_CHECK(hosttg.osVer == 14.04, "Failed to identify version of Ubuntu 14.04, got instead '" + to_string(hosttg.osVer) + "'.");

	BOOST_TEST_CHECK(hostvr.opSys == OpSys::Ubuntu, "Failed to identify Ubuntu, got instead '" + OperatingSystemIdentifier::OpSysString(hostvr.opSys) + "'.");
	BOOST_TEST_CHECK(hostvr.osVer == 16.04, "Failed to identify version of Ubuntu 16.04, got instead '" + to_string(hostvr.osVer) + "'.");
}

/*!
 * Tests the Red Hat/CentOS operating system and distribution identifier.
 *
 * The test first targets the SSH banners, falling back otherwise to data collected across all services.
 */
BOOST_AUTO_TEST_CASE(IdentifyEnterpriseLinux)
{
	// test tag-based detection

	Host hosttg("whatever", { 22 });
	hosttg.services->at(0)->banner = "SSH-2.0-OpenSSH_6.6.1p1-RHEL7-6.6.1p1-22\r\n";

	// test version-based detection

	Host hostvr("whatever", { 22, 80 });
	hostvr.services->at(0)->banner = "SSH-2.0-OpenSSH_5.3\r\n";
	hostvr.services->at(1)->banner = "HTTP/1.1 200 OK\r\nServer: Apache (CentOS)\r\n\r\n";

	EnterpriseLinuxIdentifier os;

	BOOST_TEST_CHECK(os.Scan(&hosttg), "Failed to identify tag-based RHEL 7.");
	BOOST_TEST_CHECK(os.Scan(&hostvr), "Failed to identify version-based CentOS 6.");

	BOOST_TEST_CHECK(hosttg.opSys == OpSys::EnterpriseLinux, "Failed to identify Red Hat, got instead '" + OperatingSystemIdentifier::OpSysString(hosttg.opSys) + "'.");
	BOOST_TEST_CHECK(hosttg.osVer == 7, "Failed to identify version of Red Hat 7, got instead '" + to_string(hosttg.osVer) + "'.");

	BOOST_TEST_CHECK(hostvr.opSys == OpSys::EnterpriseLinux, "Failed to identify CentOS, got instead '" + OperatingSystemIdentifier::OpSysString(hostvr.opSys) + "'.");
	BOOST_TEST_CHECK(hostvr.osVer == 6, "Failed to identify version of CentOS 6, got instead '" + to_string(hostvr.osVer) + "'.");
}

/*!
 * Tests the Fedora operating system and distribution identifier.
 *
 * The test first targets the SSH banners, falling back otherwise to data collected across all services.
 */
BOOST_AUTO_TEST_CASE(IdentifyFedora)
{
	// test version-based detection

	Host hostvr("whatever", { 22, 80 });
	hostvr.services->at(0)->banner = "SSH-2.0-OpenSSH_7.1p1\r\n";
	hostvr.services->at(1)->banner = "HTTP/1.1 200 OK\r\nServer: Apache (Fedora)\r\n\r\n";

	FedoraIdentifier os;

	BOOST_TEST_CHECK(os.Scan(&hostvr), "Failed to identify version-based Fedora 24.");

	BOOST_TEST_CHECK(hostvr.opSys == OpSys::Fedora, "Failed to identify Fedora, got instead '" + OperatingSystemIdentifier::OpSysString(hostvr.opSys) + "'.");
	BOOST_TEST_CHECK(hostvr.osVer == 24, "Failed to identify version of Fedora 24, got instead '" + to_string(hostvr.osVer) + "'.");
}

/*!
 * Tests the Windows operating system identifier.
 *
 * The test checks if any Windows-exclusive services are running on the host.
 */
BOOST_AUTO_TEST_CASE(IdentifyWindows)
{
	// test Cygwin detection

	Host hostcy("whatever", { 22 });
	hostcy.services->at(0)->banner = "SSH-2.0-OpenSSH_5.1 Cygwin-1.7.32\r\n";

	// test Microsoft-branded server detection

	Host hostms("whatever", { 80 });
	hostms.services->at(0)->banner = "HTTP/1.1 200 OK\r\nDate: Wed, 30 Mar 2016 00:49:15 GMT\r\nServer: Microsoft-IIS/8.5\r\nX-Powered-By: ASP.NET\r\n\r\n";

	WindowsIdentifier os;

	BOOST_TEST_CHECK(os.Scan(&hostcy), "Failed to identify Windows via Cygwin.");
	BOOST_TEST_CHECK(os.Scan(&hostms), "Failed to identify Windows via Microsoft servers.");

	BOOST_TEST_CHECK(hostcy.opSys == OpSys::WindowsNT, "Failed to identify Windows, got instead '" + OperatingSystemIdentifier::OpSysString(hostcy.opSys) + "'.");
	BOOST_TEST_CHECK(hostms.opSys == OpSys::WindowsNT, "Failed to identify Windows, got instead '" + OperatingSystemIdentifier::OpSysString(hostms.opSys) + "'.");
}

//---------------------------------------------------------------------------------------------------------------------
// Factory Tests
//---------------------------------------------------------------------------------------------------------------------

/*!
 * Tests the port scanner implementation spawner.
 */
BOOST_AUTO_TEST_CASE(PortScanFactory)
{
	auto tcp = ServiceScannerFactory::Get(IPPROTO_TCP);
	BOOST_TEST_CHECK((typeid(*tcp) == typeid(TcpScanner)), "Factory should have spawned TcpScanner for IPPROTO_TCP, but instead spawned `" + string(typeid(*tcp).name()) + "`.");
	delete tcp;

	auto udp = ServiceScannerFactory::Get(IPPROTO_UDP);
	BOOST_TEST_CHECK((typeid(*udp) == typeid(UdpScanner)), "Factory should have spawned UdpScanner for IPPROTO_UDP, but instead spawned `" + string(typeid(*udp).name()) + "`.");
	delete udp;

	auto icmp = ServiceScannerFactory::Get(IPPROTO_ICMP);
	BOOST_TEST_CHECK((typeid(*icmp) == typeid(IcmpPinger)), "Factory should have spawned IcmpPinger for IPPROTO_ICMP, but instead spawned `" + string(typeid(*icmp).name()) + "`.");
	delete icmp;

	auto icmp6 = ServiceScannerFactory::Get(IPPROTO_ICMPV6);
	BOOST_TEST_CHECK((typeid(*icmp6) == typeid(IcmpPinger)), "Factory should have spawned IcmpPinger for IPPROTO_ICMPV6, but instead spawned `" + string(typeid(*icmp6).name()) + "`.");
	delete icmp6;
}

/*!
 * Tests the host scanner implementation spawner.
 */
BOOST_AUTO_TEST_CASE(HostScanFactory)
{
	auto ins = HostScannerFactory::Get(false, false);
	BOOST_TEST_CHECK((typeid(*ins) == typeid(InternalScanner)), "Factory should have spawned InternalScanner for <!passive,!external>, but instead spawned `" + string(typeid(*ins).name()) + "`.");
	delete ins;

	auto shd = HostScannerFactory::Get(true);
	BOOST_TEST_CHECK((typeid(*shd) == typeid(ShodanScanner)), "Factory should have spawned ShodanScanner for <passive,>, but instead spawned `" + string(typeid(*shd).name()) + "`.");
	delete shd;

	auto nmp = HostScannerFactory::Get(false, true);
	BOOST_TEST_CHECK((typeid(*nmp) == typeid(NmapScanner)), "Factory should have spawned NmapScanner for <!passive,external>, but instead spawned `" + string(typeid(*nmp).name()) + "`.");
	delete nmp;
}

//---------------------------------------------------------------------------------------------------------------------
// Passive Port Scanner Tests
//---------------------------------------------------------------------------------------------------------------------

/*!
 * Tests the Shodan passive scanner.
 */
BOOST_AUTO_TEST_CASE(ShodanPassiveScan)
{
	ShodanScanner scan(readKey("shodan-key"));

	if (!scan.HasKey())
	{
		BOOST_FAIL("Failed to get `shodan-key` configuration entry from the persistent store.");
		return;
	}
	
	Host host("188.166.36.214"); // excelsior.rolisoft.net

	unordered_set<unsigned short> exp = { 25, 80 };

	scan.Scan(&host);

	BOOST_TEST_CHECK(host.services->size() != 0, "Failed to find any open ports.");

	for (auto& serv : *host.services)
	{
		switch (serv->port)
		{
		case 20:
			exp.erase(20);

			BOOST_TEST_CHECK(!serv->alive, "Port 20 should not be alive.");
			BOOST_TEST_CHECK((serv->reason == AR_TimedOut || serv->reason == AR_IcmpUnreachable), "Port 20 reason should either be TimedOut or IcmpUnreachable, it is instead " + Service::ReasonString(serv->reason) + ".");
			break;

		case 25:
			exp.erase(25);

			BOOST_TEST_CHECK(serv->alive, "Port 25 should be alive.");
			BOOST_TEST_CHECK(serv->banner.length() > 0, "Failed to grab service banner on port 25.");
			BOOST_TEST_CHECK(serv->reason == AR_ReplyReceived, "Port 25 reason should be ReplyReceived, it is instead " + Service::ReasonString(serv->reason) + ".");
			break;

		case 80:
			exp.erase(80);

			BOOST_TEST_CHECK(serv->alive, "Port 80 should be alive.");
			BOOST_TEST_CHECK(serv->banner.length() > 0, "Failed to grab service banner on port 80.");
			BOOST_TEST_CHECK(serv->reason == AR_ReplyReceived, "Port 80 reason should be ReplyReceived, it is instead " + Service::ReasonString(serv->reason) + ".");
			break;
		}
	}

	if (!exp.empty())
	{
		for (auto port : exp)
		{
			BOOST_TEST_CHECK(false, "Port " + to_string(port) + " was not in the dataset.");
		}
	}
}

/*!
 * Tests the Censys passive scanner.
 */
BOOST_AUTO_TEST_CASE(CensysPassiveScan)
{
	CensysScanner scan(readKey("censys-key"));

	if (!scan.HasKey())
	{
		BOOST_FAIL("Failed to get `censys-key` configuration entry from the persistent store.");
		return;
	}
	
	Host host("188.166.36.214"); // excelsior.rolisoft.net

	unordered_set<unsigned short> exp = { 25, 80 };

	scan.Scan(&host);

	BOOST_TEST_CHECK(host.services->size() != 0, "Failed to find any open ports.");

	for (auto& serv : *host.services)
	{
		switch (serv->port)
		{
		case 20:
			exp.erase(20);

			BOOST_TEST_CHECK(!serv->alive, "Port 20 should not be alive.");
			BOOST_TEST_CHECK((serv->reason == AR_TimedOut || serv->reason == AR_IcmpUnreachable), "Port 20 reason should either be TimedOut or IcmpUnreachable, it is instead " + Service::ReasonString(serv->reason) + ".");
			break;

		case 25:
			exp.erase(25);

			BOOST_TEST_CHECK(serv->alive, "Port 25 should be alive.");
			BOOST_TEST_CHECK(serv->banner.length() > 0, "Failed to grab service banner on port 25.");
			BOOST_TEST_CHECK(serv->reason == AR_ReplyReceived, "Port 25 reason should be ReplyReceived, it is instead " + Service::ReasonString(serv->reason) + ".");
			break;

		case 80:
			exp.erase(80);

			BOOST_TEST_CHECK(serv->alive, "Port 80 should be alive.");
			BOOST_TEST_CHECK(serv->banner.length() > 0, "Failed to grab service banner on port 80.");
			BOOST_TEST_CHECK(serv->reason == AR_ReplyReceived, "Port 80 reason should be ReplyReceived, it is instead " + Service::ReasonString(serv->reason) + ".");
			break;
		}
	}

	if (!exp.empty())
	{
		for (auto port : exp)
		{
			BOOST_TEST_CHECK(false, "Port " + to_string(port) + " was not in the dataset.");
		}
	}
}

/*!
 * Tests the Mr. Looquer passive scanner for IPv6 addresses.
 */
BOOST_AUTO_TEST_CASE(LooquerIPv6PassiveScan)
{
	LooquerScanner scan(readKey("looquer-key"));

	if (!scan.HasKey())
	{
		BOOST_FAIL("Failed to get `looquer-key` configuration entry from the persistent store.");
		return;
	}
	
	Host host("2620:0:cc1:115::218"); // OpenDNS

	unordered_set<unsigned short> exp = { 80, 443 };

	scan.Scan(&host);

	BOOST_TEST_CHECK(host.services->size() != 0, "Failed to find any open ports.");

	for (auto& serv : *host.services)
	{
		switch (serv->port)
		{
		case 20:
			exp.erase(20);

			BOOST_TEST_CHECK(!serv->alive, "Port 20 should not be alive.");
			BOOST_TEST_CHECK((serv->reason == AR_TimedOut || serv->reason == AR_IcmpUnreachable), "Port 20 reason should either be TimedOut or IcmpUnreachable, it is instead " + Service::ReasonString(serv->reason) + ".");
			break;

		case 80:
			exp.erase(80);

			BOOST_TEST_CHECK(serv->alive, "Port 80 should be alive.");
			BOOST_TEST_CHECK(serv->banner.length() > 0, "Failed to grab service banner on port 80.");
			BOOST_TEST_CHECK(serv->reason == AR_ReplyReceived, "Port 80 reason should be ReplyReceived, it is instead " + Service::ReasonString(serv->reason) + ".");
			break;

		case 443:
			exp.erase(443);

			BOOST_TEST_CHECK(serv->alive, "Port 443 should be alive.");
			BOOST_TEST_CHECK(serv->banner.length() > 0, "Failed to grab service banner on port 443.");
			BOOST_TEST_CHECK(serv->reason == AR_ReplyReceived, "Port 443 reason should be ReplyReceived, it is instead " + Service::ReasonString(serv->reason) + ".");
			break;
		}
	}

	if (!exp.empty())
	{
		for (auto port : exp)
		{
			BOOST_TEST_CHECK(false, "Port " + to_string(port) + " was not in the dataset.");
		}
	}
}

/*!
 * Tests the Mr. Looquer passive scanner for IPv4 addresses.
 * 
 * This service focuses on IPv6 addresses, however IPv4 addresses can also be queried,
 * when the service successfully made a connection between the addresses.
 * 
 * This test queries the IPv4 address of the same host queried for in the IPv6 test,
 * and performs the same checks on it.
 */
BOOST_AUTO_TEST_CASE(LooquerIPv4PassiveScan)
{
	LooquerScanner scan(readKey("looquer-key"));

	if (!scan.HasKey())
	{
		BOOST_FAIL("Failed to get `looquer-key` configuration entry from the persistent store.");
		return;
	}
	
	Host host("67.215.92.219"); // OpenDNS

	unordered_set<unsigned short> exp = { 80, 443 };

	scan.Scan(&host);

	BOOST_TEST_CHECK(host.services->size() != 0, "Failed to find any open ports.");

	for (auto& serv : *host.services)
	{
		switch (serv->port)
		{
		case 20:
			exp.erase(20);

			BOOST_TEST_CHECK(!serv->alive, "Port 20 should not be alive.");
			BOOST_TEST_CHECK((serv->reason == AR_TimedOut || serv->reason == AR_IcmpUnreachable), "Port 20 reason should either be TimedOut or IcmpUnreachable, it is instead " + Service::ReasonString(serv->reason) + ".");
			break;

		case 80:
			exp.erase(80);

			BOOST_TEST_CHECK(serv->alive, "Port 80 should be alive.");
			BOOST_TEST_CHECK(serv->banner.length() > 0, "Failed to grab service banner on port 80.");
			BOOST_TEST_CHECK(serv->reason == AR_ReplyReceived, "Port 80 reason should be ReplyReceived, it is instead " + Service::ReasonString(serv->reason) + ".");
			break;

		case 443:
			exp.erase(443);

			BOOST_TEST_CHECK(serv->alive, "Port 443 should be alive.");
			BOOST_TEST_CHECK(serv->banner.length() > 0, "Failed to grab service banner on port 443.");
			BOOST_TEST_CHECK(serv->reason == AR_ReplyReceived, "Port 443 reason should be ReplyReceived, it is instead " + Service::ReasonString(serv->reason) + ".");
			break;
		}
	}

	if (!exp.empty())
	{
		for (auto port : exp)
		{
			BOOST_TEST_CHECK(false, "Port " + to_string(port) + " was not in the dataset.");
		}
	}
}

/*!
 * Tests the amalgamation passive scanner.
 * 
 * This scanner uses data from Shodan, Censys and Mr Looquer. As such, it has the
 * requirements (API keys) of all three components, in order to successfully run.
 */
BOOST_AUTO_TEST_CASE(AmalgamatedPassiveScan)
{
	PassiveScanner scan(readKey("shodan-key"), readKey("censys-key"), readKey("looquer-key"));

	if (!scan.HasShodanKey())
	{
		BOOST_FAIL("Failed to get `shodan-key` configuration entry from the persistent store.");
		return;
	}

	if (!scan.HasCensysKey())
	{
		BOOST_FAIL("Failed to get `censys-key` configuration entry from the persistent store.");
		return;
	}

	if (!scan.HasLooquerKey())
	{
		BOOST_FAIL("Failed to get `looquer-key` configuration entry from the persistent store.");
		return;
	}
	
	Host host("188.166.36.214"); // excelsior.rolisoft.net

	unordered_set<unsigned short> exp = { 25, 80 };

	scan.Scan(&host);

	BOOST_TEST_CHECK(host.services->size() != 0, "Failed to find any open ports.");

	for (auto& serv : *host.services)
	{
		switch (serv->port)
		{
		case 20:
			exp.erase(20);

			BOOST_TEST_CHECK(!serv->alive, "Port 20 should not be alive.");
			BOOST_TEST_CHECK((serv->reason == AR_TimedOut || serv->reason == AR_IcmpUnreachable), "Port 20 reason should either be TimedOut or IcmpUnreachable, it is instead " + Service::ReasonString(serv->reason) + ".");
			break;

		case 25:
			exp.erase(25);

			BOOST_TEST_CHECK(serv->alive, "Port 25 should be alive.");
			BOOST_TEST_CHECK(serv->banner.length() > 0, "Failed to grab service banner on port 25.");
			BOOST_TEST_CHECK(serv->reason == AR_ReplyReceived, "Port 25 reason should be ReplyReceived, it is instead " + Service::ReasonString(serv->reason) + ".");
			break;

		case 80:
			exp.erase(80);

			BOOST_TEST_CHECK(serv->alive, "Port 80 should be alive.");
			BOOST_TEST_CHECK(serv->banner.length() > 0, "Failed to grab service banner on port 80.");
			BOOST_TEST_CHECK(serv->reason == AR_ReplyReceived, "Port 80 reason should be ReplyReceived, it is instead " + Service::ReasonString(serv->reason) + ".");
			break;
		}
	}

	if (!exp.empty())
	{
		for (auto port : exp)
		{
			BOOST_TEST_CHECK(false, "Port " + to_string(port) + " was not in the dataset.");
		}
	}
}

//---------------------------------------------------------------------------------------------------------------------
// Internal Port Scanner Tests
//---------------------------------------------------------------------------------------------------------------------

/*!
 * Tests the IPv4 TCP port scanner.
 */
BOOST_AUTO_TEST_CASE(TcpIpv4PortScan)
{
	TcpScanner scan;

	Host host("188.166.36.214", { 20, 25, 80 }); // excelsior.rolisoft.net

	auto& servs = *host.services;

	TaskQueueRunner::QuickScan(scan, servs);

	BOOST_TEST_CHECK(!servs[0]->alive, "Port 20 should not be alive.");
	BOOST_TEST_CHECK( servs[1]->alive, "Port 25 should be alive.");
	BOOST_TEST_CHECK( servs[2]->alive, "Port 80 should be alive.");

	BOOST_TEST_CHECK(servs[1]->banner.length() > 0, "Failed to grab service banner on port 25.");
	BOOST_TEST_CHECK(servs[2]->banner.length() > 0, "Failed to grab service banner on port 80.");

	BOOST_TEST_CHECK((servs[0]->reason == AR_TimedOut || servs[0]->reason == AR_IcmpUnreachable), "Port 20 reason should either be TimedOut or IcmpUnreachable, it is instead " + Service::ReasonString(servs[0]->reason) + ".");
	BOOST_TEST_CHECK( servs[1]->reason == AR_ReplyReceived, "Port 25 reason should be ReplyReceived, it is instead " + Service::ReasonString(servs[1]->reason) + ".");
	BOOST_TEST_CHECK( servs[2]->reason == AR_ReplyReceived, "Port 80 reason should be ReplyReceived, it is instead " + Service::ReasonString(servs[1]->reason) + ".");
}

/*!
 * Tests the IPv6 TCP port scanner.
 * 
 * This test requires IPv6 connectivity to be present on the test runner machine.
 */
BOOST_AUTO_TEST_CASE(TcpIpv6PortScan)
{
	TcpScanner scan;

	Host host("2a03:b0c0:2:d0::383:c001", { 20, 25, 80 }); // excelsior.rolisoft.net

	auto& servs = *host.services;

	TaskQueueRunner::QuickScan(scan, servs);

	BOOST_TEST_CHECK(!servs[0]->alive, "Port 20 should not be alive.");
	BOOST_TEST_CHECK( servs[1]->alive, "Port 25 should be alive.");
	BOOST_TEST_CHECK( servs[2]->alive, "Port 80 should be alive.");

	BOOST_TEST_CHECK(servs[1]->banner.length() > 0, "Failed to grab service banner on port 25.");
	BOOST_TEST_CHECK(servs[2]->banner.length() > 0, "Failed to grab service banner on port 80.");

	BOOST_TEST_CHECK((servs[0]->reason == AR_TimedOut || servs[0]->reason == AR_IcmpUnreachable), "Port 20 reason should either be TimedOut or IcmpUnreachable, it is instead " + Service::ReasonString(servs[0]->reason) + ".");
	BOOST_TEST_CHECK( servs[1]->reason == AR_ReplyReceived, "Port 25 reason should be ReplyReceived, it is instead " + Service::ReasonString(servs[1]->reason) + ".");
	BOOST_TEST_CHECK( servs[2]->reason == AR_ReplyReceived, "Port 80 reason should be ReplyReceived, it is instead " + Service::ReasonString(servs[1]->reason) + ".");
}

/*!
 * Tests the `DataReader` class's ability to load the UDP payloads from a gzipped binary database.
 * 
 * This test requires the "payloads" data file to be present in order to run.
 */
BOOST_AUTO_TEST_CASE(UdpPayloadLoader)
{
	UdpScanner udp;

	auto payloads = udp.GetPayloads();

	BOOST_TEST_CHECK((payloads.size() >= 2), "Payloads list should contain at least two entries instead of " + to_string(payloads.size()) + ".");

	BOOST_TEST_CHECK((payloads.find(0)  != payloads.end()), "Payloads list should contain generic payload.");
	BOOST_TEST_CHECK((payloads.find(53) != payloads.end()), "Payloads list should contain DNS payload.");
}

/*!
 * Tests the IPv4 UDP port scanner.
 */
BOOST_AUTO_TEST_CASE(UdpIpv4PortScan)
{
	UdpScanner scan;

	Host host1("188.166.36.214", { }, { 53 }); // excelsior.rolisoft.net
	Host host2("208.67.222.222", { }, { 53 }); // OpenDNS

	Services servs = { host1.services->front(), host2.services->front() };

	TaskQueueRunner::QuickScan(scan, servs);

	BOOST_TEST_CHECK(!servs[0]->alive, "Port 53 on 178.* should not answer.");
	BOOST_TEST_CHECK( servs[1]->alive, "Port 53 on 208.* should answer.");

	BOOST_TEST_CHECK(servs[1]->banner.length() > 0, "Failed to grab service banner.");

	BOOST_TEST_CHECK((servs[0]->reason == AR_TimedOut || servs[0]->reason == AR_IcmpUnreachable), "Port 53 on 178.* reason should either be TimedOut or IcmpUnreachable, it is instead " + Service::ReasonString(servs[0]->reason) + ".");
	BOOST_TEST_CHECK( servs[1]->reason == AR_ReplyReceived, "Port 53 on 208.* reason should be ReplyReceived, it is instead " + Service::ReasonString(servs[1]->reason) + ".");
}

/*!
 * Tests the IPv6 UDP port scanner.
 * 
 * This test requires IPv6 connectivity to be present on the test runner machine.
 */
BOOST_AUTO_TEST_CASE(UdpIpv6PortScan)
{
	UdpScanner scan;

	Host host1("2a03:b0c0:2:d0::383:c001", { }, { 53 }); // excelsior.rolisoft.net
	Host host2("2620:0:ccc::2", { }, { 53 }); // OpenDNS

	Services servs = { host1.services->front(), host2.services->front() };

	TaskQueueRunner::QuickScan(scan, servs);

	BOOST_TEST_CHECK(!servs[0]->alive, "Port 53 on 2a03.* should not answer.");
	BOOST_TEST_CHECK( servs[1]->alive, "Port 53 on 2620.* should answer.");

	BOOST_TEST_CHECK(servs[1]->banner.length() > 0, "Failed to grab service banner.");

	BOOST_TEST_CHECK((servs[0]->reason == AR_TimedOut || servs[0]->reason == AR_IcmpUnreachable), "Port 53 on 2a03.* reason should either be TimedOut or IcmpUnreachable, it is instead " + Service::ReasonString(servs[0]->reason) + ".");
	BOOST_TEST_CHECK( servs[1]->reason == AR_ReplyReceived, "Port 53 on 2620.* reason should be ReplyReceived, it is instead " + Service::ReasonString(servs[1]->reason) + ".");
}

/*!
 * Tests the IPv4 ICMP ping scanner.
 */
BOOST_AUTO_TEST_CASE(IcmpIpv4Ping)
{
	IcmpPinger scan;

	Host host1("188.166.36.214", { 0 }); // excelsior.rolisoft.net
	Host host2("0.0.1.0", { 0 }); // bogon

	Services servs = { host1.services->front(), host2.services->front() };

	TaskQueueRunner::QuickScan(scan, servs);

	BOOST_TEST_CHECK( servs[0]->alive, "178.* should answer.");
	BOOST_TEST_CHECK(!servs[1]->alive, "0.* should not answer.");
	
	BOOST_TEST_CHECK( servs[0]->reason == AR_ReplyReceived, "178.* reason should be ReplyReceived, it is instead " + Service::ReasonString(servs[0]->reason) + ".");
	BOOST_TEST_CHECK((servs[1]->reason == AR_TimedOut || servs[1]->reason == AR_IcmpUnreachable || servs[1]->reason == AR_ScanFailed), "0.* reason should either be TimedOut or IcmpUnreachable, it is instead " + Service::ReasonString(servs[1]->reason) + ".");
}

/*!
 * Tests the IPv6 ICMP ping scanner.
 * 
 * This test requires IPv6 connectivity to be present on the test runner machine.
 */
BOOST_AUTO_TEST_CASE(IcmpIpv6Ping)
{
	IcmpPinger scan;

	Host host1("2a03:b0c0:2:d0::383:c001", { 0 }); // excelsior.rolisoft.net
	Host host2("0100::", { 0 }); // bogon

	Services servs = { host1.services->front(), host2.services->front() };

	TaskQueueRunner::QuickScan(scan, servs);

	BOOST_TEST_CHECK( servs[0]->alive, "2a03.* should answer.");
	BOOST_TEST_CHECK(!servs[1]->alive, "0100.* should not answer.");
	
	BOOST_TEST_CHECK( servs[0]->reason == AR_ReplyReceived, "2a03.* reason should be ReplyReceived, it is instead " + Service::ReasonString(servs[0]->reason) + ".");
	BOOST_TEST_CHECK((servs[1]->reason == AR_TimedOut || servs[1]->reason == AR_IcmpUnreachable), "0100.* reason should either be TimedOut or IcmpUnreachable, it is instead " + Service::ReasonString(servs[1]->reason) + ".");
}

/*!
 * Tests the ARP scanner.
 */
BOOST_AUTO_TEST_CASE(ArpPing)
{
	ArpPinger scan;

	Hosts hosts = {
		new Host("192.168.1.1"), // bogon
		new Host("192.168.1.254"), // bogon
		new Host("188.166.36.214"), // excelsior.rolisoft.net
	};

	scan.Scan(&hosts);

	BOOST_TEST_CHECK( hosts[0]->alive, "*.1 should answer.");
	BOOST_TEST_CHECK(!hosts[1]->alive, "*.254 should not answer.");
	BOOST_TEST_CHECK(!hosts[2]->alive, "178.* should not answer.");

	BOOST_TEST_CHECK(hosts[0]->reason == AR_ReplyReceived, "*.1 reason should be ReplyReceived, it is instead " + Service::ReasonString(hosts[0]->reason) + ".");
	BOOST_TEST_CHECK(hosts[1]->reason == AR_TimedOut,      "*.254 reason should be TimedOut, it is instead " + Service::ReasonString(hosts[1]->reason) + ".");
	BOOST_TEST_CHECK(hosts[2]->reason == AR_ScanFailed,    "178.* reason should be ScanFailed, it is instead " + Service::ReasonString(hosts[2]->reason) + ".");

	freeHosts(hosts);
}

//---------------------------------------------------------------------------------------------------------------------
// External Port Scanner Tests
//---------------------------------------------------------------------------------------------------------------------

/*!
 * Tests whether the interaction with nmap is working properly.
 * 
 * This test requires the `nmap` executable to be reachable from %PATH%.
 */
BOOST_AUTO_TEST_CASE(NmapGetVersion)
{
	NmapScanner scan;
	
	string version = scan.GetVersion();

	BOOST_TEST_CHECK(version.length() > 0, "Failed to get nmap version.");
}

/*!
 * Tests the IPv4 TCP port scanning ability through nmap.
 * 
 * This case just tests the XML parsing ability, an installation of nmap
 * is not required. Interaction with nmap is tested with `NmapGetVersion`.
 */
BOOST_AUTO_TEST_CASE(NmapIpv4Processing)
{
	NmapScanner scan;

	auto hosts = scan.Process("<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE nmaprun><nmaprun scanner=\"nmap\" args=\"...\" start=\"1459035690\" startstr=\"Sun Mar 27 00:41:30 2016\" version=\"7.00\" xmloutputversion=\"1.04\"><scaninfo type=\"syn\" protocol=\"tcp\" numservices=\"1\" services=\"25\"/><scaninfo type=\"udp\" protocol=\"udp\" numservices=\"0\" services=\"\"/><verbose level=\"0\"/><debugging level=\"0\"/><host starttime=\"1459035698\" endtime=\"1459035698\"><status state=\"up\" reason=\"user-set\" reason_ttl=\"0\"/><address addr=\"188.166.36.214\" addrtype=\"ipv4\"/><hostnames><hostname name=\"excelsior.rolisoft.net\" type=\"PTR\"/></hostnames><ports><port protocol=\"tcp\" portid=\"25\"><state state=\"open\" reason=\"syn-ack\" reason_ttl=\"53\"/><service name=\"smtp\" method=\"table\" conf=\"3\"/><script id=\"banner\" output=\"220 excelsior.rolisoft.net ESMTP Sat, 26 Mar 2016 23:41:41 +0000\"/></port></ports><times srtt=\"38000\" rttvar=\"38000\" to=\"190000\"/></host><runstats><finished time=\"1459035698\" timestr=\"Sun Mar 27 00:41:38 2016\" elapsed=\"8.10\" summary=\"Nmap done at Sun Mar 27 00:41:38 2016; 1 IP address (1 host up) scanned in 8.10 seconds\" exit=\"success\"/><hosts up=\"1\" down=\"0\" total=\"1\"/></runstats></nmaprun>");

	BOOST_TEST_REQUIRE(hosts->size() == 1, "Number of scanned hosts should be 1, it is instead " + to_string(hosts->size()) + ".");
	BOOST_TEST_REQUIRE((*hosts)[0]->services->size() == 1, "Number of discovered services should be 1, it is instead " + to_string((*hosts)[0]->services->size()) + ".");

	BOOST_TEST_CHECK((*hosts)[0]->address == "188.166.36.214", "Host should be 188.166.36.214.");
	BOOST_TEST_CHECK((*hosts)[0]->alive, "Port 25 should be alive.");

	BOOST_TEST_CHECK((*(*hosts)[0]->services)[0]->port == 25,          "Port of first service should be 25.");
	BOOST_TEST_CHECK((*(*hosts)[0]->services)[0]->banner.length() > 0, "Failed to grab service banner.");

	BOOST_TEST_CHECK((*hosts)[0]->reason == AR_ReplyReceived, "Port 25 reason should be ReplyReceived, it is instead " + Service::ReasonString((*hosts)[0]->reason) + ".");

	freeHosts(*hosts);
	delete hosts;
}

/*!
 * Tests the IPv4 TCP port scanning ability through nmap.
 * 
 * This test requires the `nmap` executable to be reachable from %PATH%,
 * but is regardless disabled, since nmap execution takes too long.
 */
BOOST_AUTO_TEST_CASE_DISABLED(NmapIpv4PortScan)
{
	NmapScanner scan;

	Hosts hosts = {
		new Host("188.166.36.214", { 25 }), // excelsior.rolisoft.net
	};

	scan.Scan(&hosts);

	BOOST_TEST_REQUIRE(hosts.size() == 1, "Number of scanned hosts should be 1, it is instead " + to_string(hosts.size()) + ".");
	BOOST_TEST_REQUIRE(hosts[0]->services->size() == 1, "Number of discovered services should be 1, it is instead " + to_string(hosts[0]->services->size()) + ".");

	BOOST_TEST_CHECK(hosts[0]->alive, "Port 25 should be alive.");

	BOOST_TEST_CHECK((*hosts[0]->services)[0]->banner.length() > 0, "Failed to grab service banner.");

	BOOST_TEST_CHECK(hosts[0]->reason == AR_ReplyReceived, "Port 25 reason should be ReplyReceived, it is instead " + Service::ReasonString(hosts[0]->reason) + ".");

	freeHosts(hosts);
}

/*!
 * Tests the IPv6 TCP port scanning ability through nmap.
 * 
 * This case just tests the XML parsing ability, an installation of nmap
 * is not required. Interaction with nmap is tested with `NmapGetVersion`.
 */
BOOST_AUTO_TEST_CASE(NmapIpv6Processing)
{
	NmapScanner scan;

	auto hosts = scan.Process("<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE nmaprun><nmaprun scanner=\"nmap\" args=\"...\" start=\"1459035966\" startstr=\"Sun Mar 27 00:46:06 2016\" version=\"7.00\" xmloutputversion=\"1.04\"><scaninfo type=\"syn\" protocol=\"tcp\" numservices=\"1\" services=\"25\"/><scaninfo type=\"udp\" protocol=\"udp\" numservices=\"0\" services=\"\"/><verbose level=\"0\"/><debugging level=\"0\"/><host starttime=\"1459035974\" endtime=\"1459035974\"><status state=\"up\" reason=\"user-set\" reason_ttl=\"0\"/><address addr=\"2a03:b0c0:2:d0::383:c001\" addrtype=\"ipv6\"/><hostnames><hostname name=\"excelsior.rolisoft.net\" type=\"PTR\"/></hostnames><ports><port protocol=\"tcp\" portid=\"25\"><state state=\"open\" reason=\"syn-ack\" reason_ttl=\"56\"/><service name=\"smtp\" method=\"table\" conf=\"3\"/><script id=\"banner\" output=\"220 excelsior.rolisoft.net ESMTP Sat, 26 Mar 2016 23:46:17 +0000\"/></port></ports><times srtt=\"49000\" rttvar=\"49000\" to=\"245000\"/></host><runstats><finished time=\"1459035974\" timestr=\"Sun Mar 27 00:46:14 2016\" elapsed=\"8.06\" summary=\"Nmap done at Sun Mar 27 00:46:14 2016; 1 IP address (1 host up) scanned in 8.06 seconds\" exit=\"success\"/><hosts up=\"1\" down=\"0\" total=\"1\"/></runstats></nmaprun>");

	BOOST_TEST_REQUIRE(hosts->size() == 1, "Number of scanned hosts should be 1, it is instead " + to_string(hosts->size()) + ".");
	BOOST_TEST_REQUIRE((*hosts)[0]->services->size() == 1, "Number of discovered services should be 1, it is instead " + to_string((*hosts)[0]->services->size()) + ".");

	BOOST_TEST_CHECK((*hosts)[0]->address == "2a03:b0c0:2:d0::383:c001", "Host should be 2a03:b0c0:2:d0::383:c001.");
	BOOST_TEST_CHECK((*hosts)[0]->alive, "Port 25 should be alive.");

	BOOST_TEST_CHECK((*(*hosts)[0]->services)[0]->port == 25,          "Port of first service should be 25.");
	BOOST_TEST_CHECK((*(*hosts)[0]->services)[0]->banner.length() > 0, "Failed to grab service banner.");

	BOOST_TEST_CHECK((*hosts)[0]->reason == AR_ReplyReceived, "Port 25 reason should be ReplyReceived, it is instead " + Service::ReasonString((*hosts)[0]->reason) + ".");

	freeHosts(*hosts);
	delete hosts;
}

/*!
 * Tests the IPv6 TCP port scanning ability through nmap.
 * 
 * This test requires the `nmap` executable to be reachable from %PATH% and for
 * IPv6 connectivity to be present on the test runner machine,
 * but is regardless disabled, since nmap execution takes too long.
 */
BOOST_AUTO_TEST_CASE_DISABLED(NmapIpv6PortScan)
{
	NmapScanner scan;
	
	Hosts hosts = {
		new Host("2a03:b0c0:2:d0::383:c001", { 25 }), // excelsior.rolisoft.net
	};

	scan.Scan(&hosts);

	BOOST_TEST_REQUIRE(hosts.size() == 1, "Number of scanned hosts should be 1, it is instead " + to_string(hosts.size()) + ".");
	BOOST_TEST_REQUIRE(hosts[0]->services->size() == 1, "Number of discovered services should be 1, it is instead " + to_string(hosts[0]->services->size()) + ".");

	BOOST_TEST_CHECK(hosts[0]->alive, "Port 25 should be alive.");

	BOOST_TEST_CHECK((*hosts[0]->services)[0]->banner.length() > 0, "Failed to grab service banner.");

	BOOST_TEST_CHECK(hosts[0]->reason == AR_ReplyReceived, "Port 25 reason should be ReplyReceived, it is instead " + Service::ReasonString(hosts[0]->reason) + ".");

	freeHosts(hosts);
}
