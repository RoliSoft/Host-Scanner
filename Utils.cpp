#include "Utils.h"
#include <stdlib.h>
#include <string>
#include <boost/regex.hpp>
#include <boost/core/ignore_unused.hpp>
#include <boost/date_time/local_time/local_time.hpp>

#if Unix
	#include <limits.h>
	#include <unistd.h>
	#include <string.h>
#endif

using namespace std;
using namespace boost;

string execute(const char* cmd)
{
	// run the process

	auto pipe = popen(cmd, "r");

	if (!pipe)
	{
		log(ERR, "Failed to execute command: `" + string(cmd) + "`");
		return "";
	}

	// read what it writes to the standard output during its lifetime

	string result;

	char buffer[512];
	while (!feof(pipe))
	{
		if (fgets(buffer, 512, pipe) != NULL)
		{
			result += buffer;
		}
	}

	// clean up and return

	pclose(pipe);

	return result;
}

string getAppPath()
{
#if Windows
	char result[MAX_PATH];
	auto size = GetModuleFileName(NULL, result, MAX_PATH);
#elif Unix
	char result[PATH_MAX];
	auto size = readlink("/proc/self/exe", result, PATH_MAX);
#endif
	return string(result, (size > 0) ? size : 0);
}

string getWorkDir()
{
#if Windows
	char result[MAX_PATH];
	GetCurrentDirectory(MAX_PATH, result);
#elif Unix
	char result[PATH_MAX];
	getcwd(result, PATH_MAX);
#endif
	return string(result);
}

string getEnvVar(const string& env)
{
#if Windows
	char *result;
	size_t size;
	auto retval = _dupenv_s(&result, &size, env.c_str()) == 0 ? string(result) : "";
	delete result;
	return retval;
#elif Unix
	return getenv(env.c_str());
#endif
}

tuple<string, string> splitPath(const string& path)
{
	auto idx = path.find_last_of(PATH_SEPARATOR);

	if (idx == string::npos)
	{
		return make_tuple(path, "");
	}

	return make_tuple(path.substr(0, idx), path.substr(idx + 1));
}

string pluralize(int quantity, const string& unit, bool addIs, bool past)
{
	return to_string(quantity) + " " + unit + (quantity != 1 ? "s" : "") + (addIs ? (quantity != 1 ? (past ? " were" : " are") : (past ? " was" : " is")) : "");
}

tuple<string, string, int> getURL(const string& url, const function<void(CURL*)>& opts)
{
#if HAVE_CURL

	CURL *curl;
	CURLcode res;

	curl = curl_easy_init();

	if (!curl)
	{
		return make_tuple("", "failed to initialize curl", -1);
	}

	curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);

	string buffer, error;

	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, static_cast<size_t(*)(char*, size_t, size_t, void*)>([](char *ptr, size_t size, size_t nmemb, void *userdata)
		{
			auto blocks = size * nmemb;
			auto buffer = reinterpret_cast<string*>(userdata);
			buffer->append(ptr, blocks);
			return blocks;
		}));

	if (opts != nullptr)
	{
		opts(curl);
	}

	res = curl_easy_perform(curl);

	long code;
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);

	if (res != CURLE_OK)
	{
		error = curl_easy_strerror(res);
	}

	curl_easy_cleanup(curl);

	return make_tuple(buffer, error, code);

#else

#if __GNUC__ || __clang__
	ignore_unused(url);
	ignore_unused(opts);
#endif

	return make_tuple("", "not compiled with curl support", -1);

#endif
}

string getNetErrStr(optional<int> code)
{
#if Windows
	LPSTR errlp = nullptr;
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, 0, code.is_initialized() ? code.get() : WSAGetLastError(), MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), LPSTR(&errlp), 0, 0);
	string err(errlp);
	LocalFree(errlp);
	return err;
#else
	char* err = strerror(code.is_initialized() ? code.get() : errno);
	return err ? err : "";
#endif
}

long dateToUnix(const string& datetime, const string& format)
{
	using namespace gregorian;
	using namespace local_time;
	using namespace posix_time;

	ptime epoch(date(1970, 1, 1));

	auto dt(local_sec_clock::local_time(time_zone_ptr()));
	auto lf(new local_time_input_facet(format));

	stringstream ss(datetime);
	ss.imbue(locale(locale::classic(), lf));

	ss >> dt;

	return (dt.utc_time() - epoch).total_seconds();
}

string unixToDate(long datetime, const string& format)
{
	using namespace gregorian;
	using namespace local_time;
	using namespace posix_time;

	ptime epoch(date(1970, 1, 1));
	auto lf(new date_facet(format.c_str()));

	stringstream ss;
	ss.imbue(locale(locale::classic(), lf));

	ss << (epoch + seconds(datetime)).date();

	return ss.str();
}

string escapeRegex(const string& input)
{
	static const regex  escape("[.^$|()\\[\\]{}*+?\\\\]");
	static const string replace = "\\\\&";

	return regex_replace(input, escape, replace, match_default | format_sed);
}

int compareDates(const string& a, const string& b)
{
	auto al = dateToUnix(a);
	auto bl = dateToUnix(b);

	if (al < bl)
	{
		return -1;
	}

	if (al > bl)
	{
		return 1;
	}

	return 0;
}

int compareVersions(const string& a, const string& b)
{
	static const regex intrgx("(\\d+)");

	sregex_iterator ait(a.begin(), a.end(), intrgx);
	sregex_iterator bit(b.begin(), b.end(), intrgx);
	sregex_iterator end;

	while (true)
	{
		auto am = *ait;
		auto bm = *bit;

		auto ai = stoi(am[1].str());
		auto bi = stoi(bm[1].str());

		if (ai < bi)
		{
			// A is older

			return -1;
		}
		
		if (ai > bi)
		{
			// A is newer

			return 1;
		}

		// if they're equal, fall-through to next

		++ait;
		++bit;

		if (ait == end && bit == end)
		{
			// if both end here, they're equal

			return 0;
		}
		
		if (ait == end)
		{
			// if A ends here and B doesn't, A is older

			return -1;
		}
		
		if (bit == end)
		{
			// if B ends here and A doesn't, A is newer

			return 1;
		}
	}
}
