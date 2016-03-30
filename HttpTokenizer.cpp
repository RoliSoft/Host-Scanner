#include "HttpTokenizer.h"
#include <boost/regex.hpp>

using namespace std;
using namespace boost;

bool HttpTokenizer::CanTokenize(const string& banner)
{
	static regex rgx("^HTTP\\/1\\.[01]\\s(?:\\d{3})(?:\\.\\d+)?\\s", regex::perl);

	try
	{
		return regex_search(banner, rgx);
	}
	catch (boost::exception&)
	{
		return false;
	}
}

vector<string> HttpTokenizer::Tokenize(const string& banner)
{
	vector<string> lines;

	static regex flrgx("^(Server|X-(?:Powered-By|AspNet(?:Mvc)?-Version|Page-Speed)):\\s+([^\\r\\n]+)$", regex::perl);

	sregex_token_iterator flit(banner.begin(), banner.end(), flrgx, { 1, 2 });
	sregex_token_iterator end;

	for (; flit != end; ++flit)
	{
		auto name  = (*flit).str();
		auto value = (*++flit).str();

		if (name != "Server" && name != "X-Powered-By")
		{
			value = name.substr(2) + " " + value;
		}

		lines.push_back(value);
	}

	if (lines.size() == 0)
	{
		return vector<string> { banner };
	}

	vector<string> tokens;

	for (auto& line : lines)
	{
		static regex scrgx("([A-Za-z0-9\\-_\\.]+)(?:[\\/ ](\\d[^\\s]*))?", regex::perl);

		sregex_token_iterator scit(line.begin(), line.end(), scrgx, { 1, 2 });

		for (; scit != end; ++scit)
		{
			auto product = (*scit).str();
			auto version = (*++scit).str();

			if (version.length() != 0)
			{
				product += "/" + version;
			}

			tokens.push_back(product);
		}
	}

	if (tokens.size() == 0)
	{
		return vector<string> { banner };
	}

	return tokens;
}

HttpTokenizer::~HttpTokenizer()
{
}
