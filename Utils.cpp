#include "Utils.h"
#include <stdlib.h>
#include <string>

#if Unix
	#include <limits.h>
	#include <unistd.h>
#endif

using namespace std;

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
	auto retval = _dupenv_s(&result, &size, env.c_str()) == 0 ? string(result, size) : "";
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

string pluralize(int quantity, const string& unit)
{
	return to_string(quantity) + " " + unit + (quantity != 1 ? "s" : "");
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
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

	return make_tuple("", "not compiled with curl support", -1);

#endif
}
#pragma GCC diagnostic pop
