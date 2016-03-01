#include "ProtocolTokenizer.h"
#include "HttpTokenizer.h"
#include "ThreeDigitTokenizer.h"

using namespace std;

vector<string> ProtocolTokenizer::AutoTokenize(const string& banner)
{
	// primitive implementation for now, later perhaps register implementations
	// into an ordered_map by protocol popularity and call CanTokenize() on each

	static HttpTokenizer http;

	if (http.CanTokenize(banner))
	{
		return http.Tokenize(banner);
	}

	static ThreeDigitTokenizer tdt;

	if (tdt.CanTokenize(banner))
	{
		return tdt.Tokenize(banner);
	}

	// if no protocol-specific tokenizer is available,
	// return the whole string as a token

	return vector<string> { banner };
}

ProtocolTokenizer::~ProtocolTokenizer()
{
}
