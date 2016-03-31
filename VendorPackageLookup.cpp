#include "VendorPackageLookup.h"
#include <boost/regex.hpp>

using namespace std;
using namespace boost;

bool VendorPackageLookup::ValidateCVE(const string& cve)
{
	static regex cvergx("^CVE-\\d{4}-\\d{4,}$", regex::icase);

	return regex_match(cve, cvergx);
}

VendorPackageLookup::~VendorPackageLookup()
{
}
