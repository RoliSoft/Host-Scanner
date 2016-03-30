#include "ThreeDigitTokenizer.h"
#include <boost/regex.hpp>

using namespace std;
using namespace boost;

bool ThreeDigitTokenizer::CanTokenize(const string& banner)
{
	// the three-digit protocol parser is not specific to a single protocol, and
	// can handle SMTP, NNTP and FTP amongst others. since there is no exact
	// specification on how to provide the server information (e.g. Server header
	// in HTTP) for these protocols, this tokenizer will just try to filter
	// "non-success" (outside of 200-299) messages and clean them up some.
	// current implementation "can tokenize" if the service banner starts with
	// a response code between 200-599 followed by space or dash plus more text.

	static regex rgx("^[2-5]\\d{2}[- ](?!$)", regex::perl);

	try
	{
		return regex_search(banner, rgx);
	}
	catch (boost::exception&)
	{
		return false;
	}
}

vector<string> ThreeDigitTokenizer::Tokenize(const string& banner)
{
	vector<string> lines;

	// try extracting tokens around the "ESMTP" word in messages with the status 220

	static regex s1rgx("^2[02]0[- ][A-Za-z0-9\\.\\-_:]+([^\\r\\n]*?E?SMTP[^\\r\\n]*?)(?: *\\(|\\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun|ready)\\b|$)", regex::perl | regex::icase);

	sregex_token_iterator s1it(banner.begin(), banner.end(), s1rgx, 1);
	sregex_token_iterator end;

	for (; s1it != end; ++s1it)
	{
		lines.push_back((*s1it).str());
	}

	if (lines.size() != 0)
	{
		return lines;
	}

	// loosen previous regex by removing the hostname removal part

	static regex s2rgx("^2[02]0[- ][^\\r\\n]*?((?:Microsoft *)?E?SMTP[^\\r\\n]*?)(?: *\\(|\\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun|ready)\\b|$)", regex::perl | regex::icase);

	sregex_token_iterator s2it(banner.begin(), banner.end(), s2rgx, 1);

	for (; s2it != end; ++s2it)
	{
		lines.push_back((*s2it).str());
	}

	if (lines.size() != 0)
	{
		return lines;
	}

	// loosen it further and add additional services

	static regex s3rgx("^2[02]0[- ]([^\\r\\n]*(?:E?SMTP|SNPP|NNTP|FTP)[^\\r\\n]*)$", regex::perl | regex::icase);

	sregex_token_iterator s3it(banner.begin(), banner.end(), s3rgx, 1);

	for (; s3it != end; ++s3it)
	{
		lines.push_back((*s3it).str());
	}

	if (lines.size() != 0)
	{
		return lines;
	}

	// if all else fails, return all informational/success lines

	static regex s4rgx("^2[02]0[- ]([^\\r\\n]*)$", regex::perl);

	sregex_token_iterator s4it(banner.begin(), banner.end(), s4rgx, 1);

	for (; s4it != end; ++s4it)
	{
		lines.push_back((*s4it).str());
	}

	if (lines.size() != 0)
	{
		return lines;
	}

	// if that fails as well, it means the service banner only had error messages
	// or the protocol was erroneously identified as being compatible with this
	// tokenizer; in this case, just return the original service banner.

	return vector<string> { banner };
}

ThreeDigitTokenizer::~ThreeDigitTokenizer()
{
}
